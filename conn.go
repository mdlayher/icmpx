package icmpx

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/net/icmp"
)

// A Conn allows reading and writing ICMPv4/6 messages, depending on the
// concrete type of Conn.
type Conn interface {
	// Close closes the underlying socket.
	io.Closer

	// ReadFrom reads an ICMP message and returns the sender's IP address.
	ReadFrom(ctx context.Context) (*icmp.Message, netip.Addr, error)

	// WriteTo writes an ICMP message to a destination IP address.
	WriteTo(ctx context.Context, msg *icmp.Message, dst netip.Addr) error
}

// An IPv4Conn allows reading and writing ICMPv4 data on a network interface.
type IPv4Conn struct {
	// IP is the chosen IPv4 bind address for ICMPv4 communication.
	IP netip.Addr

	c   *conn
	ifi *net.Interface
	mu  sync.RWMutex
	b   []byte
}

// An IPv4Config configures an IPv4Conn.
type IPv4Config struct {
	// Filter applies an optional ICMPv4 filter to an IPv4Conn's underlying
	// socket before bind(2) is called, ensuring that no packets will be
	// received which do not match the filter.
	//
	// If nil, no ICMPv4 filter is applied.
	Filter *IPv4Filter
}

// ListenIPv4 binds an ICMPv4 socket on the specified network interface.
func ListenIPv4(ifi *net.Interface, cfg IPv4Config) (*IPv4Conn, error) { return listenIPv4(ifi, cfg) }

// Close closes the underlying socket.
func (c *IPv4Conn) Close() error { return c.c.Close() }

// WriteTo writes an ICMPv4 message to a destination IPv4 address.
func (c *IPv4Conn) WriteTo(ctx context.Context, msg *icmp.Message, dst netip.Addr) error {
	if !dst.Is4() {
		return errors.New("IPv4 addresses must be used with *icmpx.IPv4Conn")
	}

	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	return c.sendto(ctx, b, dst)
}

// ReadFrom reads an ICMPv4 message and returns the sender's IPv4 address.
func (c *IPv4Conn) ReadFrom(ctx context.Context) (*icmp.Message, netip.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.recvfromLocked(ctx)
}

// An IPv6Conn allows reading and writing ICMPv6 data on a network interface.
type IPv6Conn struct {
	// IP is the chosen IPv6 bind address for ICMPv6 communication.
	IP netip.Addr

	c   *conn
	ifi *net.Interface
	mu  sync.RWMutex
	b   []byte
}

// An IPv6Config configures an IPv6Conn.
type IPv6Config struct {
	// Filter applies an optional ICMPv6 filter to an IPv6Conn's underlying
	// socket before bind(2) is called, ensuring that no packets will be
	// received which do not match the filter.
	//
	// If nil, no ICMPv6 filter is applied.
	Filter *IPv6Filter
}

// ListenIPv6 binds an ICMPv6 socket on the specified network interface.
func ListenIPv6(ifi *net.Interface, cfg IPv6Config) (*IPv6Conn, error) { return listenIPv6(ifi, cfg) }

// Close closes the underlying socket.
func (c *IPv6Conn) Close() error { return c.c.Close() }

// WriteTo writes an ICMPv6 message to a destination IPv6 address.
func (c *IPv6Conn) WriteTo(ctx context.Context, msg *icmp.Message, dst netip.Addr) error {
	if !dst.Is6() {
		return errors.New("IPv6 addresses must be used with *icmpx.IPv6Conn")
	}

	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	return c.sendto(ctx, b, dst)
}

// ReadFrom reads an ICMPv6 message and returns the sender's IPv6 address.
func (c *IPv6Conn) ReadFrom(ctx context.Context) (*icmp.Message, netip.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.recvfromLocked(ctx)
}
