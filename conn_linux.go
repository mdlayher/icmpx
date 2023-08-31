package icmpx

import (
	"context"
	"net"
	"net/netip"

	"github.com/mdlayher/socket"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// A conn abstracts socket.Conn in an OS-independent way.
type conn = socket.Conn

// listenIPv4 is the IPv4Conn entry point on Linux.
func listenIPv4(ifi *net.Interface, cfg IPv4Config) (*IPv4Conn, error) {
	sa, ip, err := bindSockaddr(fIPv4, ifi)
	if err != nil {
		return nil, err
	}

	conn, err := socket.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP, "icmpx-ipv4", nil)
	if err != nil {
		return nil, err
	}

	if err := conn.SetsockoptInt(unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, ifi.Index); err != nil {
		_ = conn.Close()
		return nil, err
	}

	if cfg.Filter != nil {
		if err := cfg.Filter.set(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	if err := conn.Bind(sa); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &IPv4Conn{
		IP:  ip,
		c:   conn,
		ifi: ifi,
		b:   make([]byte, ifi.MTU),
	}, nil
}

// sendto sends an ICMPv4 message.
func (c *IPv4Conn) sendto(ctx context.Context, b []byte, dst netip.Addr) error {
	// IPv4 addresses do not use the IPv6 zone in the destination sockaddr.
	return c.c.Sendto(ctx, b, 0, toSockaddr(dst, 0))
}

// recvfromLocked receives an ICMPv4 message. It assumes c.mu is locked so that
// c.b may be reused safely.
func (c *IPv4Conn) recvfromLocked(ctx context.Context) (*icmp.Message, netip.Addr, error) {
	n, addr, err := c.c.Recvfrom(ctx, c.b, 0)
	if err != nil {
		return nil, netip.Addr{}, err
	}

	// ICMPv4 sockets return the entire IPv4 header, but we only care about the
	// ICMP message that lies beyond the header.
	//
	// TODO(mdlayher): consider an API that exposes the header, though no
	// equivalent exists for IPv6 and it would create an awkward API.
	h, err := ipv4.ParseHeader(c.b)
	if err != nil {
		return nil, netip.Addr{}, err
	}

	m, err := icmp.ParseMessage(unix.IPPROTO_ICMP, c.b[h.Len:n])
	if err != nil {
		return nil, netip.Addr{}, err
	}

	return m, fromSockaddr(addr), nil
}

// set applies the IPv4 filter to a *socket.Conn.
func (f *IPv4Filter) set(c *socket.Conn) error {
	// The filter is technically a 4 byte struct but passing a uint32 with an
	// equivalent memory layout works fine.
	return c.SetsockoptInt(unix.SOL_RAW, unix.ICMP_FILTER, int(f.data))
}

// listenIPv6 is the IPv6Conn entry point on Linux.
func listenIPv6(ifi *net.Interface, cfg IPv6Config) (*IPv6Conn, error) {
	sa, ip, err := bindSockaddr(fIPv6, ifi)
	if err != nil {
		return nil, err
	}

	conn, err := socket.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6, "icmpx-ipv6", nil)
	if err != nil {
		return nil, err
	}

	if err := conn.SetsockoptInt(unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, ifi.Index); err != nil {
		_ = conn.Close()
		return nil, err
	}

	if cfg.Filter != nil {
		if err := cfg.Filter.set(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	if err := conn.Bind(sa); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &IPv6Conn{
		IP:  ip,
		c:   conn,
		ifi: ifi,
		b:   make([]byte, ifi.MTU),
	}, nil
}

// sendto sends an ICMPv6 message.
func (c *IPv6Conn) sendto(ctx context.Context, b []byte, dst netip.Addr) error {
	return c.c.Sendto(ctx, b, 0, toSockaddr(dst, uint32(c.ifi.Index)))
}

// recvfromLocked receives an ICMPv6 message. It assumes c.mu is locked so that
// c.b may be reused safely.
func (c *IPv6Conn) recvfromLocked(ctx context.Context) (*icmp.Message, netip.Addr, error) {
	n, addr, err := c.c.Recvfrom(ctx, c.b, 0)
	if err != nil {
		return nil, netip.Addr{}, err
	}

	m, err := icmp.ParseMessage(unix.IPPROTO_ICMPV6, c.b[:n])
	if err != nil {
		return nil, netip.Addr{}, err
	}

	return m, fromSockaddr(addr), nil
}

// set applies the IPv6 filter to a *socket.Conn.
func (f *IPv6Filter) set(c *socket.Conn) error {
	return c.SetsockoptICMPv6Filter(unix.SOL_ICMPV6, unix.ICMPV6_FILTER, &unix.ICMPv6Filter{Data: f.data})
}
