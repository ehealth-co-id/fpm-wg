package syncer

import (
	"io"
	"log/slog"
	"net/netip"
	"sort"
	"testing"

	wg "github.com/ehealthid/fpm-wg/internal/wg"
)

type fakeApplier struct {
	peers map[string][]netip.Prefix
	sets  int
}

func newFake(peers map[string][]netip.Prefix) *fakeApplier {
	return &fakeApplier{peers: peers}
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

func (f *fakeApplier) get(key string) []string {
	var ss []string
	for _, p := range f.peers[key] {
		ss = append(ss, p.String())
	}
	sort.Strings(ss)
	return ss
}

type fakeRIB struct{ routes map[netip.Prefix]netip.Addr }

func (f *fakeRIB) fn(string) (map[netip.Prefix]netip.Addr, error) { return f.routes, nil }

func newSyncer(t *testing.T, app *fakeApplier, ribfn RIBFunc) *Syncer {
	t.Helper()
	s := New(Options{
		Iface:     "wg0",
		TunnelNet: netip.MustParsePrefix("192.168.200.0/24"),
		Applier:   app,
		RIB:       ribfn,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	return s
}

func eq(t *testing.T, got []string, want ...string) {
	t.Helper()
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestReconcileFromKernel(t *testing.T) {
	app := newFake(map[string][]netip.Prefix{
		"PEER3": {netip.MustParsePrefix("192.168.200.3/32")},
		"PEER5": {netip.MustParsePrefix("192.168.200.5/32")},
	})
	rib := &fakeRIB{routes: map[netip.Prefix]netip.Addr{
		netip.MustParsePrefix("192.168.0.0/24"): netip.MustParseAddr("192.168.200.3"),
		netip.MustParsePrefix("10.255.0.5/32"):  netip.MustParseAddr("192.168.200.5"),
		netip.MustParsePrefix("172.24.0.0/16"):  netip.MustParseAddr("172.24.128.1"), // not a peer
	}}
	s := newSyncer(t, app, rib.fn)
	if err := s.Reconcile(); err != nil {
		t.Fatal(err)
	}
	eq(t, app.get("PEER3"), "192.168.0.0/24", "192.168.200.3/32")
	eq(t, app.get("PEER5"), "10.255.0.5/32", "192.168.200.5/32")
}

// Regression: a prefix must move to the correct peer when its kernel nexthop
// changes (the bug that broke e<->c when FRR renumbered nexthop groups).
func TestPrefixMovesBetweenPeers(t *testing.T) {
	app := newFake(map[string][]netip.Prefix{
		"PEER3": {netip.MustParsePrefix("192.168.200.3/32")},
		"PEER5": {netip.MustParsePrefix("192.168.200.5/32")},
	})
	// First state: 10.255.0.5/32 is (wrongly) attributed to PEER3.
	app.peers["PEER3"] = []netip.Prefix{
		netip.MustParsePrefix("192.168.200.3/32"),
		netip.MustParsePrefix("10.255.0.5/32"),
	}
	rib := &fakeRIB{routes: map[netip.Prefix]netip.Addr{
		netip.MustParsePrefix("10.255.0.5/32"): netip.MustParseAddr("192.168.200.5"),
	}}
	s := newSyncer(t, app, rib.fn)
	if err := s.Reconcile(); err != nil {
		t.Fatal(err)
	}
	eq(t, app.get("PEER3"), "192.168.200.3/32")                  // stale entry dropped
	eq(t, app.get("PEER5"), "10.255.0.5/32", "192.168.200.5/32") // and attributed correctly
}

func TestWithdrawRemovesPrefix(t *testing.T) {
	app := newFake(map[string][]netip.Prefix{
		"PEER5": {netip.MustParsePrefix("192.168.200.5/32")},
	})
	rib := &fakeRIB{routes: map[netip.Prefix]netip.Addr{
		netip.MustParsePrefix("192.168.3.0/24"): netip.MustParseAddr("192.168.200.5"),
	}}
	s := newSyncer(t, app, rib.fn)
	if err := s.Reconcile(); err != nil {
		t.Fatal(err)
	}
	eq(t, app.get("PEER5"), "192.168.3.0/24", "192.168.200.5/32")

	rib.routes = map[netip.Prefix]netip.Addr{} // route withdrawn from the kernel
	if err := s.Reconcile(); err != nil {
		t.Fatal(err)
	}
	eq(t, app.get("PEER5"), "192.168.200.5/32")
}

func TestNoOpWhenUnchanged(t *testing.T) {
	app := newFake(map[string][]netip.Prefix{
		"PEER5": {netip.MustParsePrefix("192.168.200.5/32")},
	})
	rib := &fakeRIB{routes: map[netip.Prefix]netip.Addr{
		netip.MustParsePrefix("192.168.3.0/24"): netip.MustParseAddr("192.168.200.5"),
	}}
	s := newSyncer(t, app, rib.fn)
	if err := s.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if app.sets != 1 {
		t.Fatalf("sets = %d, want 1", app.sets)
	}
	if err := s.Reconcile(); err != nil { // unchanged -> no write
		t.Fatal(err)
	}
	if app.sets != 1 {
		t.Fatalf("idempotent reconcile wrote again: sets = %d", app.sets)
	}
}
