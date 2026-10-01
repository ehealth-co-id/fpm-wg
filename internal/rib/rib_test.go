package rib

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"
)

func attr(typ uint16, val []byte) []byte {
	b := make([]byte, 4, 4+len(val)+4)
	binary.LittleEndian.PutUint16(b[0:2], uint16(4+len(val)))
	binary.LittleEndian.PutUint16(b[2:4], typ)
	b = append(b, val...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func ip4(a, b, c, d byte) []byte { return []byte{a, b, c, d} }

func routeMsg(dstLen int, attrs ...[]byte) syscall.NetlinkMessage {
	data := make([]byte, rtmsgLen)
	data[0] = syscall.AF_INET
	data[1] = byte(dstLen)
	for _, a := range attrs {
		data = append(data, a...)
	}
	return syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: syscall.RTM_NEWROUTE},
		Data:   data,
	}
}

const wgIndex = 7

func TestParseRoutes(t *testing.T) {
	msgs := []syscall.NetlinkMessage{
		// 10.255.0.5/32 via 192.168.200.5 on the wg iface
		routeMsg(32, attr(rtaDst, ip4(10, 255, 0, 5)), attr(rtaGateway, ip4(192, 168, 200, 5)), attr(rtaOIF, u32(wgIndex))),
		// same prefix but egressing a different interface -> ignored
		routeMsg(32, attr(rtaDst, ip4(10, 255, 0, 6)), attr(rtaGateway, ip4(192, 168, 200, 6)), attr(rtaOIF, u32(2))),
		// connected route (no gateway) -> ignored
		routeMsg(24, attr(rtaDst, ip4(192, 168, 200, 0)), attr(rtaOIF, u32(wgIndex))),
		// default route via wg
		routeMsg(0, attr(rtaGateway, ip4(192, 168, 200, 8)), attr(rtaOIF, u32(wgIndex))),
	}
	got := parse(msgs, wgIndex)

	want := map[netip.Prefix]netip.Addr{
		netip.MustParsePrefix("10.255.0.5/32"): netip.MustParseAddr("192.168.200.5"),
		netip.MustParsePrefix("0.0.0.0/0"):     netip.MustParseAddr("192.168.200.8"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %d routes, want %d: %v", len(got), len(want), got)
	}
	for p, gw := range want {
		if got[p] != gw {
			t.Errorf("%s: got %v, want %v", p, got[p], gw)
		}
	}
}

func TestParseMultipathUsesFirstGW(t *testing.T) {
	// rtnexthop { len, flags, hops, ifindex } + nested RTA_GATEWAY
	leg := func(gw []byte) []byte {
		nh := make([]byte, 8)
		binary.LittleEndian.PutUint16(nh[0:2], 8+8) // header + one attr
		nh = append(nh, attr(rtaGateway, gw)...)
		return nh
	}
	mp := append(leg(ip4(192, 168, 200, 5)), leg(ip4(192, 168, 200, 6))...)
	msgs := []syscall.NetlinkMessage{
		routeMsg(24, attr(rtaDst, ip4(192, 168, 3, 0)), attr(rtaMultipath, mp), attr(rtaOIF, u32(wgIndex))),
	}
	got := parse(msgs, wgIndex)
	if got[netip.MustParsePrefix("192.168.3.0/24")] != netip.MustParseAddr("192.168.200.5") {
		t.Fatalf("multipath gateway = %v", got)
	}
}
