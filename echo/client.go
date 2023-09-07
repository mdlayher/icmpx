package echo

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mdlayher/icmpx"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sync/errgroup"
)

// A Client sends ICMPv4/6 echo requests to perform ping operations.
type Client struct {
	v4, v6 *connContext
}

// NewClient binds a Client on the specified network interface.
func NewClient(ifi *net.Interface) (*Client, error) {
	c4, err := icmpx.ListenIPv4(ifi, icmpx.IPv4Config{
		Filter: icmpx.IPv4AllowOnly(ipv4.ICMPTypeEchoReply),
	})
	if err != nil {
		return nil, err
	}

	c6, err := icmpx.ListenIPv6(ifi, icmpx.IPv6Config{
		Filter: icmpx.IPv6AllowOnly(ipv6.ICMPTypeEchoReply),
	})
	if err != nil {
		_ = c4.Close()
		return nil, err
	}

	return newClient(c4, c6), nil
}

// newClient constructs a Client from raw icmpx.Conns.
func newClient(c4, c6 icmpx.Conn) *Client {
	return &Client{
		v4: newConnContext(ipv4.ICMPTypeEcho, c4),
		v6: newConnContext(ipv6.ICMPTypeEchoRequest, c6),
	}
}

// Close closes the Client's underlying network connections.
func (ec *Client) Close() error {
	if err := ec.v4.Close(); err != nil {
		_ = ec.v6.Close()
		return err
	}

	return ec.v6.Close()
}

// A Response is the result of a Client.Ping operation.
type Response struct {
	// Duration reports how much time elapsed during the echo request and
	// response cycle.
	Duration time.Duration

	// Ping and Pong are the raw ICMP ping messages sent by the Client and
	// received from the target host.
	Ping, Pong *icmp.Echo

	// IP is the IPv4/6 address of the target host.
	IP netip.Addr
}

// Ping performs an ICMPv4/6 echo or "ping" on a target host.
func (ec *Client) Ping(ctx context.Context, dst netip.Addr) (*Response, error) {
	if dst.Is4() {
		return ec.v4.Ping(ctx, dst)
	}

	return ec.v6.Ping(ctx, dst)
}

// A connContext manages the state of an ICMPv4/6 socket for ping operations.
type connContext struct {
	// Manages the underlying socket and ICMPv4/6 echo request type.
	conn icmpx.Conn
	typ  icmp.Type

	// Manages the concurrency of the connContext.
	eg     *errgroup.Group
	cancel context.CancelFunc

	// Manages the echo message state per unique destination host.
	pingsMu sync.Mutex
	pings   map[netip.Addr]icmp.Echo

	// Manages dispatching ping responses to listeners by the ICMPv4/6 echo ID.
	resMu     sync.RWMutex
	responses map[echoID]chan pingResponse

	// Swappable parameters for testing.
	retryDelay time.Duration
	hooks      testHooks
}

// testHooks enable instrumenting connContext code with hooks used in tests. Any
// fields which are nil become no-ops.
type testHooks struct {
	// OnRetry fires when a request fails to receive a timely response and must
	// be retried.
	OnRetry func(req *icmp.Echo)
}

// An echoID is a hint for the keys used in the connContext.responses map.
type echoID = int

// A pingResponse contains an ICMPv4/6 echo response to dispatch to a listener.
type pingResponse struct {
	Echo *icmp.Echo
	IP   netip.Addr
}

// newConnContext creates a connContext for a given ICMPv4/6 type and socket,
// starting its background goroutines.
func newConnContext(typ icmp.Type, conn icmpx.Conn) *connContext {
	ctx, cancel := context.WithCancel(context.Background())
	eg, ctx := errgroup.WithContext(ctx)

	cc := &connContext{
		conn: conn,
		typ:  typ,

		eg:     eg,
		cancel: cancel,

		pings: make(map[netip.Addr]icmp.Echo),

		responses: make(map[echoID]chan pingResponse),

		// By default, we try sending another echo after 1 second has elapsed
		// without a reply to a prior attempt.
		retryDelay: 1 * time.Second,
	}

	eg.Go(func() error { return cc.readLoop(ctx) })

	return cc
}

// Close stops the connContext's background goroutines and closes the ICMPv4/6
// socket.
func (cc *connContext) Close() error {
	cc.cancel()
	if err := cc.eg.Wait(); err != nil {
		_ = cc.conn.Close()
		return err
	}

	return cc.conn.Close()
}

// errRetry is a sentinel error indicating the caller should retry an operation.
var errRetry = errors.New("retry")

// Ping performs a single ping operation.
func (cc *connContext) Ping(ctx context.Context, dst netip.Addr) (*Response, error) {
	start := time.Now()

	// It may take more than one attempt for an echo request to succeed, so send
	// them at regular intervals until a response is received.
	for {
		// Generates an appropriate echo message for the target while also
		// maintaining the appropriate sequence number state.
		echo, err := cc.echo(dst)
		if err != nil {
			return nil, err
		}

		switch res, err := cc.doPing(ctx, start, echo, dst); {
		case err == nil:
			// Ping succeeded.
			return res, nil
		case errors.Is(err, errRetry):
			if cc.hooks.OnRetry != nil {
				cc.hooks.OnRetry(echo)
			}

			// Timed out waiting for a response. Try again.
			continue
		default:
			// Unhandled error.
			return nil, err
		}
	}
}

// doPing performs a single echo request/response cycle with a short timeout. If
// the ping does not receive a timely response, it returns errRetry.
func (cc *connContext) doPing(
	ctx context.Context,
	start time.Time,
	echo *icmp.Echo,
	dst netip.Addr,
) (*Response, error) {
	msg := &icmp.Message{
		Type: cc.typ,
		Body: echo,
	}

	if err := cc.conn.WriteTo(ctx, msg, dst); err != nil {
		return nil, err
	}

	// Once a ping has been sent, wait for the background reader to notify
	// us of a matching response by ID. If we receive none in a short period
	// of time, tell the caller to try again.
	cc.resMu.RLock()
	defer cc.resMu.RUnlock()

	tickC := time.After(cc.retryDelay)
	for {
		select {
		case res := <-cc.responses[echo.ID]:
			// TODO(mdlayher): check for sequence/data mismatch.
			return &Response{
				Duration: time.Since(start),
				Ping:     echo,
				Pong:     res.Echo,
				IP:       res.IP,
			}, nil
		case <-tickC:
			return nil, errRetry
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// readLoop manages the ICMPv4/6 echo reading goroutine until ctx is canceled.
func (cc *connContext) readLoop(ctx context.Context) error {
	for {
		msg, ip, err := cc.conn.ReadFrom(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return err
		}

		// Our ICMP filter guarantees that all messages are echoes.
		echo := msg.Body.(*icmp.Echo)

		cc.resMu.RLock()
		if pingC, ok := cc.responses[echo.ID]; ok {
			// A caller is waiting for this echo response.
			pingC <- pingResponse{
				Echo: echo,
				IP:   ip,
			}
		}
		cc.resMu.RUnlock()
	}
}

// echo generates an ICMP echo message while also doing bookkeeping around the
// ID, sequence number, and opaque data.
func (cc *connContext) echo(ip netip.Addr) (*icmp.Echo, error) {
	cc.pingsMu.Lock()
	defer cc.pingsMu.Unlock()

	if echo, ok := cc.pings[ip]; ok {
		// Already have a message for this host, increment the sequence number
		// and return.
		echo.Seq++
		cc.pings[ip] = echo
		return &echo, nil
	}

	// New host, generate opaque random data and set up an initial message with
	// a unique ID.
	data := make([]byte, 8)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}

	echo := icmp.Echo{
		ID:   int(binary.BigEndian.Uint16(data[:2])),
		Seq:  1,
		Data: data,
	}
	cc.pings[ip] = echo

	cc.resMu.Lock()
	defer cc.resMu.Unlock()

	// Perform the initial setup for this ID's responses.
	if _, ok := cc.responses[echo.ID]; !ok {
		cc.responses[echo.ID] = make(chan pingResponse, 1)
	}

	return &echo, nil
}
