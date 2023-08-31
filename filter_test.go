package icmpx_test

import (
	"testing"

	"github.com/mdlayher/icmpx"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestIPv4Filter(t *testing.T) {
	f := icmpx.IPv4AllowOnly(ipv4.ICMPTypeEchoReply)

	if !f.WillBlock(ipv4.ICMPTypeEcho) {
		t.Fatalf("echo request should be blocked, but is not")
	}
	if f.WillBlock(ipv4.ICMPTypeEchoReply) {
		t.Fatalf("initial echo reply should not be blocked, but is")
	}

	f.Block(ipv4.ICMPTypeEchoReply)
	if !f.WillBlock(ipv4.ICMPTypeEchoReply) {
		t.Fatalf("final echo reply should be blocked, but is not")
	}
}

func TestIPv6Filter(t *testing.T) {
	f := icmpx.IPv6AllowOnly(ipv6.ICMPTypeEchoReply)

	if !f.WillBlock(ipv6.ICMPTypeEchoRequest) {
		t.Fatalf("echo request should be blocked, but is not")
	}
	if f.WillBlock(ipv6.ICMPTypeEchoReply) {
		t.Fatalf("initial echo reply should not be blocked, but is")
	}

	f.Block(ipv6.ICMPTypeEchoReply)
	if !f.WillBlock(ipv6.ICMPTypeEchoReply) {
		t.Fatalf("final echo reply should be blocked, but is not")
	}
}
