package echo_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/icmpx/echo"
	"golang.org/x/net/nettest"
	"golang.org/x/sync/errgroup"
)

func TestIntegrationClient(t *testing.T) {
	t.Parallel()

	lo, err := nettest.LoopbackInterface()
	if err != nil {
		t.Fatalf("failed to find loopback: %v", err)
	}

	c, err := echo.NewClient(lo)
	if err != nil {
		// ICMP sockets require elevated privileges.
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("skipping, permission denied")
		}

		t.Fatalf("failed to create client: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eg, ctx := errgroup.WithContext(ctx)

	for _, ip := range []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.IPv6Loopback(),
	} {
		ip := ip
		eg.Go(func() error {
			got, err := c.Ping(ctx, ip)
			if err != nil {
				return fmt.Errorf("ping %s: %v", ip, err)
			}

			if got.Duration == 0 {
				return errors.New("ping duration was zero")
			}

			if diff := cmp.Diff(got.Ping, got.Pong); diff != "" {
				return fmt.Errorf("unexpected ping/pong (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(ip, got.IP, cmp.Comparer(ipEqual)); diff != "" {
				return fmt.Errorf("unexpected IP (-want +got):\n%s", diff)
			}

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		t.Fatalf("failed to run: %v", err)
	}
}

func ipEqual(x, y netip.Addr) bool { return x == y }
