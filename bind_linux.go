package icmpx

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// A family is an IP address family.
type family int

// Valid family values.
const (
	_ family = iota
	fIPv4
	fIPv6
)

// String returns the name of a family.
func (f family) String() string {
	switch f {
	case fIPv4:
		return "IPv4"
	case fIPv6:
		return "IPv6"
	default:
		panic("unreachable")
	}
}

// bindSockaddr choses an IPv4 or IPv6 bind address for the given interface.
func bindSockaddr(family family, ifi *net.Interface) (unix.Sockaddr, netip.Addr, error) {
	// Strict mode allows in-kernel filtering of addresses for a given interface
	// index.
	rc, err := rtnetlink.Dial(&netlink.Config{Strict: true})
	if err != nil {
		return nil, netip.Addr{}, err
	}
	defer rc.Close()

	msgs, err := rc.Execute(
		&rtnetlink.AddressMessage{Index: uint32(ifi.Index)},
		unix.RTM_GETADDR,
		netlink.Request|netlink.Dump,
	)
	if err != nil {
		return nil, netip.Addr{}, err
	}

	// The returned messages always contain address data.
	ams := make([]*rtnetlink.AddressMessage, len(msgs))
	for i := range msgs {
		ams[i] = msgs[i].(*rtnetlink.AddressMessage)
	}

	return (&bindContext{
		family: family,
		ifi:    ifi,
	}).Select(ams)
}

// A bindContext manages shared state while selecting a socket bind address.
type bindContext struct {
	family family
	ifi    *net.Interface
}

// Select chooses an appropriate bind address based on rtnetlink address
// messages returned from the kernel.
func (bc *bindContext) Select(msgs []*rtnetlink.AddressMessage) (unix.Sockaddr, netip.Addr, error) {
	var (
		sa unix.Sockaddr
		ip netip.Addr
		ok bool
	)

	switch bc.family {
	case fIPv4:
		sa, ip, ok = bc.selectIPv4(msgs)
	case fIPv6:
		sa, ip, ok = bc.selectIPv6(msgs)
	default:
		panic("unreachable")
	}
	if !ok {
		return nil, netip.Addr{}, fmt.Errorf("no valid %s bind address for %q", bc.family, bc.ifi.Name)
	}

	return sa, ip, nil
}

// selectIPv4 selects an IPv4 bind address.
func (bc *bindContext) selectIPv4(msgs []*rtnetlink.AddressMessage) (unix.Sockaddr, netip.Addr, bool) {
	for _, m := range msgs {
		if m.Family != unix.AF_INET || m.Index != uint32(bc.ifi.Index) {
			continue
		}

		ip, ok := netip.AddrFromSlice(m.Attributes.Address)
		if !ok {
			continue
		}
		ip = ip.Unmap()

		// For IPv4, we assume there is a single valid address which can reach
		// any of the necessary scopes. There is no attached IPv6 zone.
		return toSockaddr(ip, 0), ip, true
	}

	return nil, netip.Addr{}, false
}

// selectIPv6 selects an IPv6 bind address.
func (bc *bindContext) selectIPv6(msgs []*rtnetlink.AddressMessage) (unix.Sockaddr, netip.Addr, bool) {
	// Select a bind IPv6 address by iterating over available addresses and
	// choosing the one that is most suitable.
	var bind netip.Addr
	for _, m := range msgs {
		if m.Family != unix.AF_INET6 || m.Index != uint32(bc.ifi.Index) {
			continue
		}

		ip, ok := netip.AddrFromSlice(m.Attributes.Address)
		if !ok {
			continue
		}

		if !bind.IsValid() {
			// No candidate yet, pick the first valid address.
			bind = ip
		}

		if !ip.IsPrivate() && ip.IsGlobalUnicast() && m.Attributes.Flags&unix.IFA_F_MANAGETEMPADDR != 0 {
			// Address is global unicast, not in the ULA space, and used to
			// generate temporary addresses.
			//
			// It's likely stable and has a broad enough scope to ping any
			// possible targets on this link.
			bind = ip
		}
	}
	if !bind.IsValid() {
		return nil, netip.Addr{}, false
	}

	return toSockaddr(bind, uint32(bc.ifi.Index)), bind, true
}

// toSockaddr converts an IP address and optional IPv6 zone into the equivalent
// unix.Sockaddr implementation.
func toSockaddr(ip netip.Addr, zone uint32) unix.Sockaddr {
	switch {
	case ip.Is4():
		return &unix.SockaddrInet4{Addr: ip.As4()}
	case ip.Is6():
		sa := &unix.SockaddrInet6{Addr: ip.As16()}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			sa.ZoneId = uint32(zone)
		}

		return sa
	default:
		panic("unreachable")
	}
}

// fromSockaddr converts a unix.Sockaddr implementation into a netip.Addr.
func fromSockaddr(sa unix.Sockaddr) netip.Addr {
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrFrom4(sa.Addr)
	case *unix.SockaddrInet6:
		addr := netip.AddrFrom16(sa.Addr)
		if sa.ZoneId > 0 {
			addr = addr.WithZone(strconv.Itoa(int(sa.ZoneId)))
		}

		return addr
	default:
		panic("unreachable")
	}
}
