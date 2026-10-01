package syncer

import (
	"encoding/hex"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/ehealthid/fpm-wg/internal/fpm"
	wg "github.com/ehealthid/fpm-wg/internal/wg"
)

type fakeApplier struct {
	peers map[string][]netip.Prefix
	sets  int
}

func newFake() *fakeApplier {
	return &fakeApplier{peers: map[string][]netip.Prefix{
		"PEER3": {netip.MustParsePrefix("192.168.200.3/32")},
		"PEER5": {netip.MustParsePrefix("192.168.200.5/32")},
	}}
}

func (f *fakeApplier) Peers(string) ([]wg.Peer, error) {
	out := make([]wg.Peer, 0, len(f.peers))
	for k, ips := range f.peers {
		out = append(out, wg.Peer{Key: k, AllowedIPs: ips})
	}
	return out, nil
}

func (f *fakeApplier) SetAllowedIPs(_, key string, ips []netip.Prefix) error {
	f.peers[key] = append([]netip.Prefix(nil), ips...)
	f.sets++
	return nil
}

func (f *fakeApplier) has(key, p string) bool {
	want := netip.MustParsePrefix(p)
	for _, ip := range f.peers[key] {
		if ip == want {
			return true
		}
	}
	return false
}

func newTest(t *testing.T) (*Syncer, *fakeApplier) {
	t.Helper()
	f := newFake()
	s := New("wg0", netip.MustParsePrefix("192.168.200.0/24"), f,
		10*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	return s, f
}

func nh(id uint32, gw string) fpm.Msg {
	return fpm.Msg{Kind: fpm.KindNexthop, Nexthop: &fpm.Nexthop{
		ID: id, Gateway: netip.MustParseAddr(gw), HasGW: true}}
}

func route(typ uint16, prefix string, nhid uint32) fpm.Msg {
	return fpm.Msg{Type: typ, Kind: fpm.KindRoute, Route: &fpm.Route{
		Prefix: netip.MustParsePrefix(prefix), NexthopID: nhid, HasNhID: nhid != 0}}
}

func TestAddDeleteLifecycle(t *testing.T) {
	s, f := newTest(t)
	s.Apply(nh(15, "192.168.200.3"))
	s.Apply(nh(16, "192.168.200.5"))
	s.Apply(route(rtmNewRoute, "192.168.0.0/24", 15))
	s.Apply(route(rtmNewRoute, "192.168.3.0/24", 16))
	// both peers dirty in one window -> coalesced into one SetAllowedIPs each
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if f.sets != 2 {
		t.Errorf("sets = %d, want 2 (coalesced)", f.sets)
	}
	if !f.has("PEER3", "192.168.0.0/24") || !f.has("PEER5", "192.168.3.0/24") {
		t.Fatalf("adds wrong: %v", f.peers)
	}

	s.Apply(route(rtmDelRoute, "192.168.3.0/24", 0))
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if f.has("PEER5", "192.168.3.0/24") {
		t.Errorf("delete did not remove prefix: %v", f.peers["PEER5"])
	}
	if !f.has("PEER5", "192.168.200.5/32") {
		t.Errorf("base tunnel ip lost on peer5: %v", f.peers["PEER5"])
	}
}

func TestIdempotentAndBaseProtected(t *testing.T) {
	s, f := newTest(t)
	s.Apply(nh(15, "192.168.200.3"))
	s.Apply(route(rtmNewRoute, "192.168.0.0/24", 15))
	s.Apply(route(rtmNewRoute, "192.168.0.0/24", 15)) // duplicate
	s.Apply(route(rtmNewRoute, "192.168.0.0/24", 15)) // duplicate
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	var got int
	for _, ip := range f.peers["PEER3"] {
		if ip == netip.MustParsePrefix("192.168.0.0/24") {
			got++
		}
	}
	if got != 1 {
		t.Errorf("duplicate learns: count=%d", got)
	}

	// A delete for a base tunnel prefix must be a no-op.
	s.Apply(route(rtmDelRoute, "192.168.200.3/32", 0))
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if !f.has("PEER3", "192.168.200.3/32") {
		t.Error("base tunnel /32 removed by delete")
	}
}

func TestUnknownGatewayIgnored(t *testing.T) {
	s, f := newTest(t)
	s.Apply(nh(7, "172.24.128.1")) // not a peer tunnel addr
	s.Apply(route(rtmNewRoute, "172.24.128.0/20", 7))
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if f.sets != 0 {
		t.Errorf("non-peer route caused %d applies", f.sets)
	}
}

// Integration: decode the real FRR 10.6.2 frames captured in the lab, then sync.
func TestRealFrames(t *testing.T) {
	hexes := []string{
		"30000000680001050000000094a2ebdc02000b0000000000080001000f00000008000600c0a8c8030800050003000000",         // NH 15 -> 192.168.200.3
		"34000000180001050000000094a2ebdc02180000fec400010000000008000100c0a80000080006001400000008001e000f000000", // route 192.168.0.0/24 nhid15
	}
	s, f := newTest(t)
	for _, h := range hexes {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		msgs, err := fpm.DecodeAll(b)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range msgs {
			s.Apply(m)
		}
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if !f.has("PEER3", "192.168.0.0/24") {
		t.Fatalf("real-frame sync failed: %v", f.peers["PEER3"])
	}
}
