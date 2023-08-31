// ICMPv4/6 filter types are copied from golang.org/x/net.
//
// Copyright 2013-2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package icmpx

import (
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// An IPv4Filter creates an ICMPv4 filter which may be attached to an IPv4Conn.
type IPv4Filter struct {
	// A raw bitmask that mirrors the kernel's ICMPv4 data structure.
	data uint32
}

// IPv4AllowOnly constructs an IPv4Filter which only permits the specified
// ICMPv4 types. All other ICMPv4 traffic is filtered out.
func IPv4AllowOnly(types ...ipv4.ICMPType) *IPv4Filter {
	var f IPv4Filter
	f.SetAll(true)

	for _, t := range types {
		f.Accept(t)
	}

	return &f
}

// Accept accepts an ICMPv4 type using the filter.
func (f *IPv4Filter) Accept(typ ipv4.ICMPType) {
	f.data &^= 1 << (uint32(typ) & 31)
}

// Block blocks an ICMPv4 type using the filter.
func (f *IPv4Filter) Block(typ ipv4.ICMPType) {
	f.data |= 1 << (uint32(typ) & 31)
}

// SetAll either blocks or allows all ICMPv4 types on the filter depending on
// the input value.
func (f *IPv4Filter) SetAll(block bool) {
	if block {
		f.data = 1<<32 - 1
	} else {
		f.data = 0
	}
}

// WillBlock reports whether a given ICMPv4 type will be blocked by the filter.
func (f *IPv4Filter) WillBlock(typ ipv4.ICMPType) bool {
	return f.data&(1<<(uint32(typ)&31)) != 0
}

// An IPv6Filter creates an ICMPv6 filter which may be attached to an IPv6Conn.
type IPv6Filter struct {
	// A raw bitmask that mirrors the kernel's ICMPv6 data structure.
	data [8]uint32
}

// IPv6AllowOnly constructs an IPv6Filter which only permits the specified
// ICMPv6 types. All other ICMPv6 traffic is filtered out.
func IPv6AllowOnly(types ...ipv6.ICMPType) *IPv6Filter {
	var f IPv6Filter
	f.SetAll(true)

	for _, t := range types {
		f.Accept(t)
	}

	return &f
}

// Accept accepts an ICMPv6 type using the filter.
func (f *IPv6Filter) Accept(typ ipv6.ICMPType) {
	f.data[typ>>5] &^= 1 << (uint32(typ) & 31)
}

// Block blocks an ICMPv6 type using the filter.
func (f *IPv6Filter) Block(typ ipv6.ICMPType) {
	f.data[typ>>5] |= 1 << (uint32(typ) & 31)
}

// SetAll either blocks or allows all ICMPv6 types on the filter depending on
// the input value.
func (f *IPv6Filter) SetAll(block bool) {
	for i := range f.data {
		if block {
			f.data[i] = 1<<32 - 1
		} else {
			f.data[i] = 0
		}
	}
}

// WillBlock reports whether a given ICMPv6 type will be blocked by the filter.
func (f *IPv6Filter) WillBlock(typ ipv6.ICMPType) bool {
	return f.data[typ>>5]&(1<<(uint32(typ)&31)) != 0
}
