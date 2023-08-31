package icmpx_test

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/icmpx"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/net/nettest"
)

var lo = func() *net.Interface {
	lo, err := nettest.LoopbackInterface()
	if err != nil {
		panic(err)
	}

	return lo
}()

func TestIntegrationIPv4Conn(t *testing.T) {
	t.Parallel()

	c, err := icmpx.ListenIPv4(lo, icmpx.IPv4Config{
		Filter: icmpx.IPv4AllowOnly(ipv4.ICMPTypeEchoReply),
	})
	if err != nil {
		// ICMPv4 sockets require elevated privileges.
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("skipping, permission denied")
		}

		t.Fatalf("failed to listen IPv4: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Ping localhost on lo as it should pretty much always work with no
	// potential firewall issues.
	var (
		dst = netip.MustParseAddr("127.0.0.1")
		req = &icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Body: &icmp.Echo{
				ID:   echoID(t),
				Seq:  1,
				Data: []byte{0xde, 0xad, 0xbe, 0xef},
			},
		}
	)

	if err := c.WriteTo(ctx, req, dst); err != nil {
		t.Fatalf("failed to write echo: %v", err)
	}

	t.Logf("ping: %s: %#v", dst, req)

	res, src, err := c.ReadFrom(ctx)
	if err != nil {
		t.Fatalf("failed to read echo: %v", err)
	}

	t.Logf("pong: %s: %#v", src, res)

	if diff := cmp.Diff(dst, src, cmp.Comparer(ipEqual)); diff != "" {
		t.Fatalf("unexpected source IP (-want +got):\n%s", diff)
	}

	// The kernel set a checksum on our outgoing message but we don't care about
	// it for comparing the expected echo reply. Verify it's set and move on to
	// compare the echo reply.
	if res.Checksum == 0 {
		t.Fatal("no ICMPv4 checksum was set on echo reply")
	}
	res.Checksum = 0

	want := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Body: req.Body,
	}

	if diff := cmp.Diff(want, res); diff != "" {
		t.Fatalf("unexpected echo reply (-want +got):\n%s", diff)
	}
}

func TestIntegrationIPv6Conn(t *testing.T) {
	t.Parallel()

	c, err := icmpx.ListenIPv6(lo, icmpx.IPv6Config{
		Filter: icmpx.IPv6AllowOnly(ipv6.ICMPTypeEchoReply),
	})
	if err != nil {
		// ICMPv6 sockets require elevated privileges.
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("skipping, permission denied")
		}

		t.Fatalf("failed to listen IPv6: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Ping localhost on lo as it should pretty much always work with no
	// potential firewall issues.
	var (
		dst = netip.IPv6Loopback()
		req = &icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest,
			Body: &icmp.Echo{
				ID:   echoID(t),
				Seq:  1,
				Data: []byte{0xde, 0xad, 0xbe, 0xef},
			},
		}
	)

	if err := c.WriteTo(ctx, req, dst); err != nil {
		t.Fatalf("failed to write echo: %v", err)
	}

	t.Logf("ping: %s: %#v", dst, req)

	res, src, err := c.ReadFrom(ctx)
	if err != nil {
		t.Fatalf("failed to read echo: %v", err)
	}

	t.Logf("pong: %s: %#v", src, res)

	if diff := cmp.Diff(dst, src, cmp.Comparer(ipEqual)); diff != "" {
		t.Fatalf("unexpected source IP (-want +got):\n%s", diff)
	}

	// The kernel set a checksum on our outgoing message but we don't care about
	// it for comparing the expected echo reply. Verify it's set and move on to
	// compare the echo reply.
	if res.Checksum == 0 {
		t.Fatal("no ICMPv6 checksum was set on echo reply")
	}
	res.Checksum = 0

	want := &icmp.Message{
		Type: ipv6.ICMPTypeEchoReply,
		Body: req.Body,
	}

	if diff := cmp.Diff(want, res); diff != "" {
		t.Fatalf("unexpected echo reply (-want +got):\n%s", diff)
	}
}

func echoID(t *testing.T) int {
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("failed to read random bytes: %v", err)
	}

	return int(binary.BigEndian.Uint16(b))
}

func ipEqual(x, y netip.Addr) bool { return x == y }
