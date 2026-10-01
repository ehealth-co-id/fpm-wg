// Package syncer maps FRR dplane events to WireGuard allowed-ips.
//
// It replaces the update_wireguard.lua hook: on a route install it resolves the
// wg0 nexthop to a peer and adds the prefix to that peer's allowed-ips; on a
// route delete it strips the prefix from whichever peer holds it. Changes are
// coalesced (the FPM module replays the whole RIB on connect) and applied as a
// full-list replace per peer, so the applier is called at most once per peer
// per flush window.
package syncer

import (
	"context"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/ehealthid/fpm-wg/internal/fpm"
	wg "github.com/ehealthid/fpm-wg/internal/wg"
)

// netlink route message types (linux/rtnetlink.h).
const (
	rtmNewRoute = 24
	rtmDelRoute = 25
)

type peerState struct {
	key     string
	allowed []netip.Prefix
	managed map[netip.Prefix]struct{} // prefixes we added (never the base tunnel /32)
	dirty   bool
}

// Syncer keeps the desired allowed-ips for every peer on one interface.
type Syncer struct {
	iface      string
	tunnelNet  netip.Prefix
	haveTunnel bool
	app        wg.Applier
	log        *slog.Logger
	flushEvery time.Duration
	kick       chan struct{}

	mu     sync.Mutex
	byKey  map[string]*peerState
	byAddr map[netip.Addr]string // peer tunnel addr -> key
	nh     map[uint32]netip.Addr // nexthop-object id -> gateway
}

// New builds a Syncer. tunnelNet (optional) restricts which /32 allowed-ips are
// treated as a peer's tunnel address.
func New(iface string, tunnelNet netip.Prefix, app wg.Applier, flushEvery time.Duration, log *slog.Logger) *Syncer {
	return &Syncer{
		iface:      iface,
		tunnelNet:  tunnelNet,
		haveTunnel: tunnelNet.IsValid(),
		app:        app,
		log:        log,
		flushEvery: flushEvery,
		kick:       make(chan struct{}, 1),
		byKey:      map[string]*peerState{},
		byAddr:     map[netip.Addr]string{},
		nh:         map[uint32]netip.Addr{},
	}
}

// Load refreshes peers and allowed-ips from the applier (source of truth).
// Call on every (re)connect, before processing the replayed RIB.
func (s *Syncer) Load() error {
	peers, err := s.app.Peers(s.iface)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byKey = make(map[string]*peerState, len(peers))
	s.byAddr = make(map[netip.Addr]string, len(peers))
	for _, p := range peers {
		ps := &peerState{
			key:     p.Key,
			allowed: append([]netip.Prefix(nil), p.AllowedIPs...),
			managed: make(map[netip.Prefix]struct{}),
		}
		s.byKey[p.Key] = ps
		for _, ip := range ps.allowed {
			if ip.Bits() != 32 {
				continue
			}
			if s.haveTunnel && !s.tunnelNet.Contains(ip.Addr()) {
				continue
			}
			if _, ok := s.byAddr[ip.Addr()]; !ok {
				s.byAddr[ip.Addr()] = p.Key
			}
		}
	}
	s.log.Info("loaded peers", "iface", s.iface, "peers", len(s.byKey), "tunnel_addrs", len(s.byAddr))
	return nil
}

// Apply processes one decoded FPM message.
func (s *Syncer) Apply(m fpm.Msg) {
	switch m.Kind {
	case fpm.KindNexthop:
		if m.Nexthop != nil && m.Nexthop.HasGW {
			s.mu.Lock()
			s.nh[m.Nexthop.ID] = m.Nexthop.Gateway
			s.mu.Unlock()
		}
	case fpm.KindRoute:
		r := m.Route
		if r == nil || !r.Prefix.IsValid() {
			return
		}
		s.mu.Lock()
		if m.Type == rtmDelRoute {
			// A withdraw carries only the destination; resolve nothing.
			s.delLocked(r.Prefix)
		} else {
			gw, ok := s.resolveGWLocked(r)
			if !ok {
				s.mu.Unlock()
				return // no resolvable gateway: vec/connected/onlink -> not wg-relevant
			}
			s.addLocked(r.Prefix, gw)
		}
		s.mu.Unlock()
		s.kickFlush()
	}
}

func (s *Syncer) resolveGWLocked(r *fpm.Route) (netip.Addr, bool) {
	if r.HasGW {
		return r.Gateway, true
	}
	if r.HasNhID {
		if gw, ok := s.nh[r.NexthopID]; ok {
			return gw, true
		}
	}
	return netip.Addr{}, false
}

func (s *Syncer) addLocked(p netip.Prefix, gw netip.Addr) {
	key, ok := s.byAddr[gw]
	if !ok {
		return // gateway is not a wg peer tunnel addr
	}
	ps := s.byKey[key]
	for _, a := range ps.allowed {
		if a == p {
			return // idempotent
		}
	}
	ps.allowed = append(ps.allowed, p)
	ps.managed[p] = struct{}{}
	ps.dirty = true
	s.log.Debug("route add", "prefix", p, "peer", short(key), "via", gw)
}

func (s *Syncer) delLocked(p netip.Prefix) {
	for _, ps := range s.byKey {
		if _, ok := ps.managed[p]; !ok {
			continue // only remove prefixes we learned; protects base tunnel /32
		}
		out := ps.allowed[:0]
		for _, a := range ps.allowed {
			if a != p {
				out = append(out, a)
			}
		}
		ps.allowed = out
		delete(ps.managed, p)
		ps.dirty = true
		s.log.Debug("route del", "prefix", p, "peer", short(ps.key))
	}
}

// Flush applies the current desired state for every dirty peer.
func (s *Syncer) Flush() error {
	s.mu.Lock()
	type job struct {
		key string
		ips []netip.Prefix
	}
	var jobs []job
	for _, ps := range s.byKey {
		if !ps.dirty {
			continue
		}
		ips := append([]netip.Prefix(nil), ps.allowed...)
		sort.Slice(ips, func(i, j int) bool { return ips[i].String() < ips[j].String() })
		jobs = append(jobs, job{ps.key, ips})
		ps.dirty = false
	}
	s.mu.Unlock()

	var firstErr error
	for _, j := range jobs {
		if err := s.app.SetAllowedIPs(s.iface, j.key, j.ips); err != nil {
			s.log.Error("set allowed-ips failed", "peer", short(j.key), "err", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		s.log.Info("applied allowed-ips", "peer", short(j.key), "count", len(j.ips))
	}
	return firstErr
}

// Run coalesces flushes until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.kick:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(s.flushEvery)
		case <-timer.C:
			if err := s.Flush(); err != nil {
				s.log.Error("flush", "err", err)
			}
		}
	}
}

func (s *Syncer) kickFlush() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func short(key string) string {
	if len(key) > 8 {
		return key[:8]
	}
	return key
}
