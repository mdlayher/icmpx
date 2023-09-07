package echo

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/icmpx"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sync/errgroup"
)

func TestClientPing(t *testing.T) {
	// Basic dual-stack ping to two emulated hosts.
	c := testClient(t)

	for _, ip := range []netip.Addr{c.Host4.IP, c.Host6.IP} {
		for i := 0; i < 3; i++ {
			res, err := c.Client.Ping(context.Background(), ip)
			if err != nil {
				t.Fatalf("failed to ping %s: %v", ip, err)
			}

			t.Logf("%s: ping: %+v, pong: %+v", res.IP, res.Ping, res.Pong)
		}
	}
}

func TestClientPingRetry(t *testing.T) {
	// Emulate a host that drops the first packet, forcing the Client to retry
	// exactly once after a brief delay.
	c := testClient(t)

	var recv atomic.Bool
	c.Host6.OnEcho = func(req *icmp.Echo) *icmp.Echo {
		if recv.Load() {
			return req
		}

		recv.Store(true)
		return nil
	}

	var (
		mu      sync.Mutex
		retries []*icmp.Echo
	)

	c.Client.v6.hooks = testHooks{
		OnRetry: func(req *icmp.Echo) {
			mu.Lock()
			defer mu.Unlock()
			retries = append(retries, req)
		},
	}

	res, err := c.Client.Ping(context.Background(), c.Host6.IP)
	if err != nil {
		t.Fatalf("failed to ping: %v", err)
	}

	if err := c.Client.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// Client retried exactly once with the same ID and data as the successful
	// ping, but sequence number 1.
	t.Run("retries", func(t *testing.T) {
		if diff := cmp.Diff(1, len(retries)); diff != "" {
			t.Fatalf("unexpected number of retries (-want +got):\n%s", diff)
		}

		want := &icmp.Echo{
			ID:   res.Pong.ID,
			Seq:  1,
			Data: res.Pong.Data,
		}

		if diff := cmp.Diff(want, retries[0]); diff != "" {
			t.Fatalf("unexpected retry message (-want +got):\n%s", diff)
		}
	})

	// Successful pong matches the second ping attempt.
	t.Run("success", func(t *testing.T) {
		if diff := cmp.Diff(res.Ping, res.Pong); diff != "" {
			t.Fatalf("unexpected ping/pong pair (-want +got):\n%s", diff)
		}

		if diff := cmp.Diff(2, res.Ping.Seq); diff != "" {
			t.Fatalf("unexpected ping sequence (-want +got):\n%s", diff)
		}

		if diff := cmp.Diff(c.Host6.IP, res.IP, cmp.Comparer(ipEqual)); diff != "" {
			t.Fatalf("unexpected pong IP (-want +got):\n%s", diff)
		}
	})
}

var _ icmpx.Conn = &testHost{}

// A testHost implements icmpx.Conn by emulating a host that replies to ICMPv4/6
// echo requests with replies.
type testHost struct {
	IP     netip.Addr
	OnEcho func(req *icmp.Echo) *icmp.Echo

	reqC, resC chan echo
}

type client struct {
	Client       *Client
	Host4, Host6 *testHost
}

// testClient sets up a Client that talks to emulated hosts.
func testClient(t *testing.T) *client {
	var (
		host4 = newTestHost(t, netip.MustParseAddr("192.0.2.0"))
		host6 = newTestHost(t, netip.MustParseAddr("2001:db8::1"))
	)

	c := newClient(host4, host6)

	// Speed up retries for tests.
	c.v4.retryDelay = 100 * time.Millisecond
	c.v6.retryDelay = 100 * time.Millisecond

	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Fatalf("failed to clean up client: %v", err)
		}
	})

	return &client{
		Client: c,

		Host4: host4,
		Host6: host6,
	}
}

func newTestHost(t *testing.T, ip netip.Addr) *testHost {
	t.Helper()

	h := &testHost{
		IP:   ip,
		reqC: make(chan echo, 1),
		resC: make(chan echo, 1),
	}

	ctx, cancel := context.WithCancel(context.Background())

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return h.run(ctx) })

	t.Cleanup(func() {
		cancel()

		if err := eg.Wait(); err != nil {
			t.Fatalf("failed to stop testHost: %v", err)
		}
	})

	return h
}

type echo struct {
	Message *icmp.Message
	Host    netip.Addr
	Err     error
}

func (c *testHost) run(ctx context.Context) error {
	for n := 0; ; n++ {
		select {
		case <-ctx.Done():
			return nil
		case req := <-c.reqC:
			var typ icmp.Type
			switch req.Message.Type {
			case ipv4.ICMPTypeEcho:
				typ = ipv4.ICMPTypeEchoReply
			case ipv6.ICMPTypeEchoRequest:
				typ = ipv6.ICMPTypeEchoReply
			}

			res := req.Message.Body.(*icmp.Echo)
			if c.OnEcho != nil {
				res = c.OnEcho(res)
			}
			if res == nil {
				continue
			}

			c.resC <- echo{
				Message: &icmp.Message{
					Type: typ,
					Body: res,
				},
				Host: req.Host,
			}

		}
	}
}

func (*testHost) Close() error { return nil }

func (h *testHost) ReadFrom(ctx context.Context) (*icmp.Message, netip.Addr, error) {
	select {
	case <-ctx.Done():
		return nil, netip.Addr{}, ctx.Err()
	case e := <-h.resC:
		return e.Message, e.Host, e.Err
	}
}

func (c *testHost) WriteTo(ctx context.Context, msg *icmp.Message, dst netip.Addr) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.reqC <- echo{
		Message: msg,
		Host:    dst,
	}:
		return nil
	}
}

func ipEqual(x, y netip.Addr) bool { return x == y }
