package fpm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"testing"
)

// Frames captured live from stock FRR 10.6.2 dplane_fpm_nl in the podman lab.
const (
	// RTM_NEWROUTE 192.168.0.0/24, references nexthop object id 15.
	frameNewRoute = "34000000180001050000000094a2ebdc02180000fec400010000000008000100c0a80000080006001400000008001e000f000000"
	// RTM_NEWNEXTHOP id 15 -> gateway 192.168.200.3 (oif 3).
	frameNexthop15 = "30000000680001050000000094a2ebdc02000b0000000000080001000f00000008000600c0a8c8030800050003000000"
	// RTM_NEWNEXTHOP id 11 -> gateway 172.24.128.1 (oif 2).
	frameNexthop11 = "30000000680001050000000094a2ebdc02000b0004000000080001000b00000008000600ac1880010800050002000000"
	// RTM_DELROUTE 192.168.3.0/24 (no gateway, no nexthop id).
	frameDelRoute = "2c000000190001040000000094a2ebdc02180000fec400000000000008000100c0a803000800060014000000"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func TestDecodeRouteWithNexthopID(t *testing.T) {
	m, err := Decode(mustHex(t, frameNewRoute))
	if err != nil {
		t.Fatal(err)
	}
	if m.Kind != KindRoute || m.Type != rtmNewRoute {
		t.Fatalf("kind/type = %v/%d", m.Kind, m.Type)
	}
	r := m.Route
	if r.Prefix != netip.MustParsePrefix("192.168.0.0/24") {
		t.Errorf("prefix = %v", r.Prefix)
	}
	if !r.HasNhID || r.NexthopID != 15 {
		t.Errorf("nhid = %d (has=%v), want 15", r.NexthopID, r.HasNhID)
	}
	if r.HasGW {
		t.Errorf("expected no inline gateway, got %v", r.Gateway)
	}
}

func TestDecodeNexthopObjects(t *testing.T) {
	cases := []struct {
		frame string
		id    uint32
		gw    string
	}{
		{frameNexthop15, 15, "192.168.200.3"},
		{frameNexthop11, 11, "172.24.128.1"},
	}
	for _, c := range cases {
		m, err := Decode(mustHex(t, c.frame))
		if err != nil {
			t.Fatal(err)
		}
		if m.Kind != KindNexthop {
			t.Fatalf("kind = %v", m.Kind)
		}
		if m.Nexthop.ID != c.id {
			t.Errorf("id = %d, want %d", m.Nexthop.ID, c.id)
		}
		if !m.Nexthop.HasGW || m.Nexthop.Gateway != netip.MustParseAddr(c.gw) {
			t.Errorf("gw = %v (has=%v), want %s", m.Nexthop.Gateway, m.Nexthop.HasGW, c.gw)
		}
	}
}

func TestDecodeDelRoute(t *testing.T) {
	m, err := Decode(mustHex(t, frameDelRoute))
	if err != nil {
		t.Fatal(err)
	}
	if m.Kind != KindRoute || m.Type != rtmDelRoute {
		t.Fatalf("kind/type = %v/%d", m.Kind, m.Type)
	}
	if m.Route.Prefix != netip.MustParsePrefix("192.168.3.0/24") {
		t.Errorf("prefix = %v", m.Route.Prefix)
	}
}

func TestReadFrameRoundTrip(t *testing.T) {
	payload := mustHex(t, frameNewRoute)
	var buf bytes.Buffer
	hdr := []byte{ProtoVersion, MsgTypeNetlink, 0, 0}
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(payload)+headerSize))
	buf.Write(hdr)
	buf.Write(payload)

	f, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if f.Version != ProtoVersion || f.Type != MsgTypeNetlink {
		t.Fatalf("hdr = %d/%d", f.Version, f.Type)
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Fatalf("payload mismatch")
	}
	if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestReadFrameRejectsBadLen(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader([]byte{1, 1, 0, 2}))
	if !errors.Is(err, ErrBadLen) {
		t.Fatalf("want ErrBadLen, got %v", err)
	}
}

func TestDecodeAllAndBadAttr(t *testing.T) {
	// Truncated route body must error, not panic.
	if _, err := Decode([]byte{16, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); !errors.Is(err, ErrShortMessage) {
		t.Fatalf("want ErrShortMessage, got %v", err)
	}
	// DecodeAll should yield the single message present.
	msgs, err := DecodeAll(mustHex(t, frameDelRoute))
	if err != nil || len(msgs) != 1 {
		t.Fatalf("DecodeAll = %d msgs, err=%v", len(msgs), err)
	}
}
