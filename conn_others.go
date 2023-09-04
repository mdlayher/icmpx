//go:build !linux

package icmpx

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"

	"golang.org/x/net/icmp"
)

var errUnimplemented = fmt.Errorf("icmpx: unimplemented on %s", runtime.GOOS)

type conn struct{}

func (*conn) Close() error { return errUnimplemented }

func listenIPv4(_ *net.Interface, _ IPv4Config) (*IPv4Conn, error) { return nil, errUnimplemented }
func listenIPv6(_ *net.Interface, _ IPv6Config) (*IPv6Conn, error) { return nil, errUnimplemented }

func (*IPv4Conn) sendto(_ context.Context, _ []byte, _ netip.Addr) error { return errUnimplemented }
func (*IPv6Conn) sendto(_ context.Context, _ []byte, _ netip.Addr) error { return errUnimplemented }

func (*IPv4Conn) recvfromLocked(_ context.Context) (*icmp.Message, netip.Addr, error) {
	return nil, netip.Addr{}, errUnimplemented
}

func (*IPv6Conn) recvfromLocked(_ context.Context) (*icmp.Message, netip.Addr, error) {
	return nil, netip.Addr{}, errUnimplemented
}

func (*IPv4Conn) setTOS(_ int) error          { return errUnimplemented }
func (*IPv6Conn) setTrafficClass(_ int) error { return errUnimplemented }
