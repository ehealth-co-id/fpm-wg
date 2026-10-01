// Package rib reads routes from the kernel routing table.
//
// fpm-wg uses this as its source of truth instead of the nexthop ids carried
// in FRR's dplane messages. Those ids (RTA_NH_ID) are reused, and resolving
// them from a cache yields a stale gateway when a group is renumbered — which
// silently attributes a prefix to the wrong WireGuard peer.
package rib

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// rtnetlink route attribute types (linux/rtnetlink.h).
const (
	rtaDst       = 1
	rtaOIF       = 4
	rtaGateway   = 5
	rtaMultipath = 9
)

const rtmsgLen = 12

// Routes returns prefix -> gateway for every IPv4 route egressing iface that
// carries a gateway (i.e. is reachable over that interface). Multipath routes
// are represented by their first gateway.
func Routes(iface string) (map[netip.Prefix]netip.Addr, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", iface, err)
	}
	raw, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("netlink route dump: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(raw)
	if err != nil {
		return nil, fmt.Errorf("parse netlink dump: %w", err)
	}
	return parse(msgs, ifi.Index), nil
}

// parse extracts the routes egressing ifIndex. It is separated from Routes so
// it can be unit-tested with synthetic netlink messages.
func parse(msgs []syscall.NetlinkMessage, ifIndex int) map[netip.Prefix]netip.Addr {
	out := make(map[netip.Prefix]netip.Addr)
	for i := range msgs {
		m := msgs[i]
		if m.Header.Type != syscall.RTM_NEWROUTE || len(m.Data) < rtmsgLen {
			continue
		}
		family, dstLen := m.Data[0], int(m.Data[1])
		if family != syscall.AF_INET || dstLen > 32 {
			continue
		}
		// ParseNetlinkRouteAttr skips the rtmsg header itself.
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			continue
		}

		var (
			dst     netip.Addr
			haveDst bool
			oif     int
			gw      netip.Addr
			haveGw  bool
		)
		for _, a := range attrs {
			switch a.Attr.Type {
			case rtaDst:
				if len(a.Value) >= 4 {
					dst, haveDst = netip.AddrFrom4([4]byte(a.Value[:4])), true
				}
			case rtaOIF:
				if len(a.Value) >= 4 {
					oif = int(binary.LittleEndian.Uint32(a.Value[:4]))
				}
			case rtaGateway:
				if len(a.Value) >= 4 {
					gw, haveGw = netip.AddrFrom4([4]byte(a.Value[:4])), true
				}
			case rtaMultipath:
				if !haveGw {
					if g, ok := firstMultipathGW(a.Value); ok {
						gw, haveGw = g, true
					}
				}
			}
		}
		if oif != ifIndex || !haveGw {
			continue
		}
		if !haveDst {
			dst = netip.IPv4Unspecified()
		}
		out[netip.PrefixFrom(dst, dstLen)] = gw
	}
	return out
}

// firstMultipathGW walks an RTA_MULTIPATH blob (rtnexthop entries, each with
// nested rtattrs) and returns the first gateway.
func firstMultipathGW(b []byte) (netip.Addr, bool) {
	for i := 0; i+8 <= len(b); {
		nlen := int(binary.LittleEndian.Uint16(b[i : i+2]))
		if nlen < 8 || i+nlen > len(b) {
			break
		}
		sub := b[i+8 : i+nlen]
		for j := 0; j+4 <= len(sub); {
			ln := int(binary.LittleEndian.Uint16(sub[j : j+2]))
			if ln < 4 || j+ln > len(sub) {
				break
			}
			if binary.LittleEndian.Uint16(sub[j+2:j+4]) == rtaGateway && ln-4 >= 4 {
				return netip.AddrFrom4([4]byte(sub[j+4 : j+8])), true
			}
			j += (ln + 3) &^ 3
		}
		i += (nlen + 3) &^ 3
	}
	return netip.Addr{}, false
}
