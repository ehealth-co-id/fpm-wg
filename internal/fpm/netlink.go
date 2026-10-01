package fpm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// netlink message types emitted by dplane_fpm_nl (linux/rtnetlink.h).
const (
	rtmNewRoute   = 24
	rtmDelRoute   = 25
	rtmNewNexthop = 104
	rtmDelNexthop = 105
)

// rtnetlink route attributes used by zebra's encoder.
const (
	rtaDst       = 1
	rtaOIF       = 4
	rtaGateway   = 5
	rtaMultipath = 9
	rtaTable     = 15
	rtaNhID      = 30
)

// nexthop-object attributes (linux/rtnetlink.h, NHA_*).
const (
	nhaID      = 1
	nhaOIF     = 5
	nhaGateway = 6
)

const (
	nlmsgHdrLen = 16
	rtmsgLen    = 12
	nhmsgLen    = 8
)

// ErrShortMessage means the netlink payload was truncated.
var ErrShortMessage = errors.New("fpm: short netlink message")

// Kind classifies a decoded message.
type Kind uint8

const (
	KindOther Kind = iota
	KindRoute
	KindNexthop
)

// Route is a decoded RTM_NEWROUTE / RTM_DELROUTE.
//
// With the default `fpm use-next-hop-groups` enabled, zebra usually emits the
// gateway via a nexthop object: the route carries NexthopID and the gateway
// must be resolved from a previously seen Nexthop (see Syncer).
type Route struct {
	Prefix    netip.Prefix
	Table     uint8
	OIF       uint32
	Gateway   netip.Addr // inline RTA_GATEWAY or first RTA_MULTIPATH leg
	HasGW     bool
	NexthopID uint32
	HasNhID   bool
}

// Nexthop is a decoded RTM_NEWNEXTHOP nexthop object.
type Nexthop struct {
	ID      uint32
	Gateway netip.Addr
	HasGW   bool
	OIF     uint32
}

// Msg is a decoded netlink message.
type Msg struct {
	Type    uint16
	NlFlags uint16
	Kind    Kind
	Route   *Route
	Nexthop *Nexthop
}

// Decode decodes exactly one netlink message (its nlmsghdr + body).
func Decode(b []byte) (Msg, error) {
	if len(b) < nlmsgHdrLen {
		return Msg{}, ErrShortMessage
	}
	nlLen := int(binary.LittleEndian.Uint32(b[0:4]))
	mtype := binary.LittleEndian.Uint16(b[4:6])
	flags := binary.LittleEndian.Uint16(b[6:8])
	if nlLen < nlmsgHdrLen || nlLen > len(b) {
		nlLen = len(b) // be lenient: decode what we have
	}
	body := b[nlmsgHdrLen:nlLen]

	m := Msg{Type: mtype, NlFlags: flags, Kind: KindOther}
	switch mtype {
	case rtmNewRoute, rtmDelRoute:
		r, err := decodeRoute(body)
		if err != nil {
			return Msg{}, err
		}
		m.Kind, m.Route = KindRoute, r
	case rtmNewNexthop, rtmDelNexthop:
		n, err := decodeNexthop(body)
		if err != nil {
			return Msg{}, err
		}
		m.Kind, m.Nexthop = KindNexthop, n
	}
	return m, nil
}

// DecodeAll decodes every netlink message in a frame payload.
func DecodeAll(payload []byte) ([]Msg, error) {
	var out []Msg
	for off := 0; off+nlmsgHdrLen <= len(payload); {
		nlLen := int(binary.LittleEndian.Uint32(payload[off : off+4]))
		if nlLen < nlmsgHdrLen || off+nlLen > len(payload) {
			break
		}
		m, err := Decode(payload[off : off+nlLen])
		if err != nil {
			return out, err
		}
		out = append(out, m)
		off += (nlLen + 3) &^ 3
	}
	return out, nil
}

func decodeRoute(body []byte) (*Route, error) {
	if len(body) < rtmsgLen {
		return nil, fmt.Errorf("%w: route body=%d", ErrShortMessage, len(body))
	}
	family := body[0]
	dstLen := int(body[1])
	rt := &Route{Table: body[4]}

	var dst netip.Addr
	haveDst := false
	for _, a := range attrs(body[rtmsgLen:]) {
		switch a.typ {
		case rtaDst:
			if ip, ok := addr4(a.val); ok {
				dst, haveDst = ip, true
			}
		case rtaGateway:
			if ip, ok := addr4(a.val); ok {
				rt.Gateway, rt.HasGW = ip, true
			}
		case rtaOIF:
			if len(a.val) >= 4 {
				rt.OIF = binary.LittleEndian.Uint32(a.val[:4])
			}
		case rtaMultipath:
			if ip, ok := firstMultipathGW(a.val); ok {
				rt.Gateway, rt.HasGW = ip, true
			}
		case rtaNhID:
			if len(a.val) >= 4 {
				rt.NexthopID, rt.HasNhID = binary.LittleEndian.Uint32(a.val[:4]), true
			}
		}
	}

	if family == 2 /* AF_INET */ {
		if !haveDst {
			dst = netip.IPv4Unspecified()
		}
		if dstLen > 32 {
			dstLen = 32
		}
		rt.Prefix = netip.PrefixFrom(dst, dstLen)
	}
	return rt, nil
}

func decodeNexthop(body []byte) (*Nexthop, error) {
	if len(body) < nhmsgLen {
		return nil, fmt.Errorf("%w: nexthop body=%d", ErrShortMessage, len(body))
	}
	nh := &Nexthop{}
	for _, a := range attrs(body[nhmsgLen:]) {
		switch a.typ {
		case nhaID:
			if len(a.val) >= 4 {
				nh.ID = binary.LittleEndian.Uint32(a.val[:4])
			}
		case nhaGateway:
			if ip, ok := addr4(a.val); ok {
				nh.Gateway, nh.HasGW = ip, true
			}
		case nhaOIF:
			if len(a.val) >= 4 {
				nh.OIF = binary.LittleEndian.Uint32(a.val[:4])
			}
		}
	}
	return nh, nil
}

type attr struct {
	typ uint16
	val []byte
}

// attrs walks rtattr structs: {u16 len, u16 type, payload}, 4-byte aligned.
func attrs(b []byte) []attr {
	var out []attr
	for i := 0; i+4 <= len(b); {
		ln := int(binary.LittleEndian.Uint16(b[i : i+2]))
		if ln < 4 || i+ln > len(b) {
			break
		}
		out = append(out, attr{
			typ: binary.LittleEndian.Uint16(b[i+2 : i+4]),
			val: b[i+4 : i+ln],
		})
		i += (ln + 3) &^ 3
	}
	return out
}

func addr4(v []byte) (netip.Addr, bool) {
	if len(v) != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(v)), true
}

// firstMultipathGW walks an RTA_MULTIPATH blob (rtnexthop + nested attrs).
func firstMultipathGW(b []byte) (netip.Addr, bool) {
	for i := 0; i+8 <= len(b); {
		nhLen := int(binary.LittleEndian.Uint16(b[i : i+2]))
		if nhLen < 8 || i+nhLen > len(b) {
			break
		}
		for _, a := range attrs(b[i+8 : i+nhLen]) {
			if a.typ == rtaGateway {
				if ip, ok := addr4(a.val); ok {
					return ip, true
				}
			}
		}
		i += (nhLen + 3) &^ 3
	}
	return netip.Addr{}, false
}
