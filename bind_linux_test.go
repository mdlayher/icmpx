package icmpx

import (
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/net/nettest"
	"golang.org/x/sys/unix"
)

var lo = func() *net.Interface {
	lo, err := nettest.LoopbackInterface()
	if err != nil {
		panic(err)
	}

	return lo
}()

func TestIntegration_bindSockaddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		f    family
		ip   netip.Addr
	}{
		{
			name: "IPv4",
			f:    fIPv4,
			ip:   netip.MustParseAddr("127.0.0.1"),
		},
		{
			name: "IPv6",
			f:    fIPv6,
			ip:   netip.IPv6Loopback(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ip, err := bindSockaddr(tt.f, lo)
			if err != nil {
				t.Fatalf("failed to bind: %v", err)
			}

			if diff := cmp.Diff(tt.ip, ip, cmp.Comparer(ipEqual)); diff != "" {
				t.Fatalf("unexpected bind IP (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_bindContextSelect(t *testing.T) {
	tests := []struct {
		name string
		f    family
		msgs []*rtnetlink.AddressMessage

		sa unix.Sockaddr
		ip netip.Addr
	}{
		{
			name: "IPv4",
			f:    fIPv4,
			msgs: []*rtnetlink.AddressMessage{{
				Family: unix.AF_INET,
				Index:  uint32(lo.Index),
				Attributes: &rtnetlink.AddressAttributes{
					Address: net.IPv4(127, 0, 0, 1),
				},
			}},

			sa: &unix.SockaddrInet4{
				Addr: [4]byte{127, 0, 0, 1},
			},
			ip: netip.MustParseAddr("127.0.0.1"),
		},
		{
			name: "IPv6 localhost",
			f:    fIPv6,
			msgs: []*rtnetlink.AddressMessage{{
				Family: unix.AF_INET6,
				Index:  uint32(lo.Index),
				Attributes: &rtnetlink.AddressAttributes{
					Address: net.ParseIP("::1"),
				},
			}},

			sa: &unix.SockaddrInet6{
				Addr: [16]byte{15: 1},
			},
			ip: netip.IPv6Loopback(),
		},
		{
			name: "IPv6 GUA",
			f:    fIPv6,
			msgs: []*rtnetlink.AddressMessage{
				{
					Family: unix.AF_INET6,
					Index:  uint32(lo.Index),
					Attributes: &rtnetlink.AddressAttributes{
						Address: net.ParseIP("::1"),
					},
				},
				{
					Family: unix.AF_INET6,
					Index:  uint32(lo.Index),
					Attributes: &rtnetlink.AddressAttributes{
						Address: net.ParseIP("2001:db8::1234"),
					},
				},
				// This address will be prioritized because it is an IPv6 GUA
				// used to generate temporary addresses.
				{
					Family: unix.AF_INET6,
					Index:  uint32(lo.Index),
					Attributes: &rtnetlink.AddressAttributes{
						Address: net.ParseIP("2001:db8::1"),
						Flags:   unix.IFA_F_MANAGETEMPADDR,
					},
				},
			},

			sa: &unix.SockaddrInet6{
				Addr: [16]byte{
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
			},
			ip: netip.MustParseAddr("2001:db8::1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa, ip, err := (&bindContext{
				family: tt.f,
				ifi:    lo,
			}).Select(tt.msgs)
			if err != nil {
				t.Fatalf("failed to select bind sockaddr: %v", err)
			}

			if diff := cmp.Diff(tt.sa, sa, cmp.Comparer(saEqual)); diff != "" {
				t.Fatalf("unexpected bind sockaddr (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.ip, ip, cmp.Comparer(ipEqual)); diff != "" {
				t.Fatalf("unexpected bind IP (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_toSockaddr(t *testing.T) {
	tests := []struct {
		name string
		ip   netip.Addr
		zone uint32
		sa   unix.Sockaddr
	}{
		{
			name: "IPv4",
			ip:   netip.MustParseAddr("192.0.2.0"),
			sa: &unix.SockaddrInet4{
				Addr: [4]byte{192, 0, 2, 0},
			},
		},
		{
			name: "IPv6 LLA",
			ip:   netip.MustParseAddr("fe80::1"),
			zone: 1,
			sa: &unix.SockaddrInet6{
				Addr: [16]byte{
					0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
				ZoneId: 1,
			},
		},
		{
			name: "IPv6 GUA",
			ip:   netip.MustParseAddr("2001:db8::1"),
			sa: &unix.SockaddrInet6{
				Addr: [16]byte{
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.sa, toSockaddr(tt.ip, tt.zone), cmp.Comparer(saEqual)); diff != "" {
				t.Fatalf("unexpected sockaddr (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_fromSockaddr(t *testing.T) {
	tests := []struct {
		name string
		sa   unix.Sockaddr
		ip   netip.Addr
	}{
		{
			name: "IPv4",
			sa: &unix.SockaddrInet4{
				Addr: [4]byte{192, 0, 2, 0},
			},
			ip: netip.MustParseAddr("192.0.2.0"),
		},
		{
			name: "IPv6 LLA",
			sa: &unix.SockaddrInet6{
				Addr: [16]byte{
					0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
				ZoneId: 1,
			},
			ip: netip.MustParseAddr("fe80::1%1"),
		},
		{
			name: "IPv6 GUA",
			sa: &unix.SockaddrInet6{
				Addr: [16]byte{
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
			},
			ip: netip.MustParseAddr("2001:db8::1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.ip, fromSockaddr(tt.sa), cmp.Comparer(ipEqual)); diff != "" {
				t.Fatalf("unexpected IP address (-want +got):\n%s", diff)
			}
		})
	}
}

func saEqual(x, y unix.Sockaddr) bool {
	if reflect.TypeOf(x) != reflect.TypeOf(y) {
		return false
	}

	x4, xOK := x.(*unix.SockaddrInet4)
	y4, yOK := y.(*unix.SockaddrInet4)
	if xOK && yOK {
		return x4.Addr == y4.Addr && x4.Port == y4.Port
	}

	x6, xOK := x.(*unix.SockaddrInet6)
	y6, yOK := y.(*unix.SockaddrInet6)
	if xOK && yOK {
		return x6.Addr == y6.Addr && x6.Port == y6.Port && x6.ZoneId == y6.ZoneId
	}

	return false
}

func ipEqual(x, y netip.Addr) bool { return x == y }
