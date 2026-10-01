// Package syncer keeps WireGuard allowed-ips in sync with the kernel FIB.
//
// FRR's dplane_fpm_nl stream is used only as a trigger: on any route event the
// syncer re-reads the kernel routing table and recomputes, for each peer, the
// set of prefixes reachable through it. The kernel is the source of truth, so
// no FRR-internal nexthop ids are ever interpreted (those are reused and were
// the cause of prefixes being attributed to the wrong peer).
//
// Reconciliation is idempotent and self-healing: a full desired state is
// computed every time and applied only when it differs from what was last
// written.
package syncer

import (
	"context"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	wg "github.com/ehealthid/fpm-wg/internal/wg"
)

// RIBFunc returns prefix -> gateway for the routes egressing iface.
type RIBFunc func(iface string) (map[netip.Prefix]netip.Addr, error)

// Options configures a Syncer.
type Options struct {
	Iface             string
	TunnelNet         netip.Prefix // restricts which /32 allowed-ips are peer tunnel addrs
	Applier           wg.Applier
	RIB               RIBFunc
	FlushInterval     time.Duration // coalescing window for event-driven reconciles
	ReconcileInterval time.Duration // periodic safety-net reconcile (0 disables)
	Logger            *slog.Logger
}

// Syncer reconciles one WireGuard interface against the kernel FIB.
type Syncer struct {
	iface     string
	tunnelNet netip.Prefix
	haveTun   bool
	app       wg.Applier
	rib       RIBFunc
	log       *slog.Logger
	flush     time.Duration
	reconcile time.Duration
	kick      chan struct{}

	mu      sync.Mutex
	base    map[string][]netip.Prefix // key -> peer tunnel /32s (never touched)
	byAddr  map[netip.Addr]string     // peer tunnel addr -> key
	applied map[string]string         // key -> serialized allowed-ips last written
}

// New builds a Syncer with defaults filled in.
func New(o Options) *Syncer {
	if o.FlushInterval <= 0 {
		o.FlushInterval = 100 * time.Millisecond
	}
	if o.ReconcileInterval < 0 {
		o.ReconcileInterval = 0
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Syncer{
		iface:     o.Iface,
		tunnelNet: o.TunnelNet,
		haveTun:   o.TunnelNet.IsValid(),
		app:       o.Applier,
		rib:       o.RIB,
		log:       o.Logger,
		flush:     o.FlushInterval,
		reconcile: o.ReconcileInterval,
		kick:      make(chan struct{}, 1),
		base:      map[string][]netip.Prefix{},
		byAddr:    map[netip.Addr]string{},
		applied:   map[string]string{},
	}
}

// Load refreshes the peer set from the applier. Only each peer's tunnel /32(s)
// are treated as base state; every other allowed-ip is derived from the FIB on
// the next reconcile (so a previously wrong state is corrected, not adopted).
func (s *Syncer) Load() error {
	peers, err := s.app.Peers(s.iface)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.base = make(map[string][]netip.Prefix, len(peers))
	s.byAddr = make(map[netip.Addr]string, len(peers))
	s.applied = make(map[string]string, len(peers))
	for _, p := range peers {
		var tun []netip.Prefix
		for _, ip := range p.AllowedIPs {
			if ip.Bits() != 32 {
				continue
			}
			if s.haveTun && !s.tunnelNet.Contains(ip.Addr()) {
				continue
			}
			tun = append(tun, ip)
		}
		s.base[p.Key] = tun
		for _, ip := range tun {
			if _, ok := s.byAddr[ip.Addr()]; !ok {
				s.byAddr[ip.Addr()] = p.Key
			}
		}
	}
	s.log.Info("loaded peers", "iface", s.iface, "peers", len(s.base), "tunnel_addrs", len(s.byAddr))
	return nil
}

// Notify schedules a reconcile (debounced). Safe to call from any goroutine.
func (s *Syncer) Notify() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Reconcile reads the FIB and applies any changed peer allowed-ips.
func (s *Syncer) Reconcile() error {
	routes, err := s.rib(s.iface)
	if err != nil {
		return err
	}

	s.mu.Lock()
	desired := make(map[string][]netip.Prefix, len(s.base))
	for k, b := range s.base {
		desired[k] = append([]netip.Prefix(nil), b...)
	}
	for p, gw := range routes {
		key, ok := s.byAddr[gw]
		if !ok {
			continue
		}
		if hasPrefix(desired[key], p) {
			continue
		}
		desired[key] = append(desired[key], p)
	}

	type job struct {
		key string
		ips []netip.Prefix
	}
	var jobs []job
	for key, ips := range desired {
		sort.Slice(ips, func(i, j int) bool { return ips[i].String() < ips[j].String() })
		ser := serialize(ips)
		if s.applied[key] == ser {
			continue
		}
		jobs = append(jobs, job{key, ips})
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
		s.mu.Lock()
		s.applied[j.key] = serialize(j.ips)
		s.mu.Unlock()
		s.log.Info("applied allowed-ips", "peer", short(j.key), "count", len(j.ips))
	}
	return firstErr
}

// Run reconciles on FPM events (debounced) and periodically.
func (s *Syncer) Run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	var tick <-chan time.Time
	if s.reconcile > 0 {
		t := time.NewTicker(s.reconcile)
		defer t.Stop()
		tick = t.C
	}

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
			timer.Reset(s.flush)
		case <-timer.C:
			if err := s.Reconcile(); err != nil {
				s.log.Error("reconcile", "err", err)
			}
		case <-tick:
			if err := s.Reconcile(); err != nil {
				s.log.Error("reconcile", "err", err)
			}
		}
	}
}

func hasPrefix(list []netip.Prefix, p netip.Prefix) bool {
	for _, x := range list {
		if x == p {
			return true
		}
	}
	return false
}

func serialize(ips []netip.Prefix) string {
	ss := make([]string, len(ips))
	for i, p := range ips {
		ss[i] = p.String()
	}
	return strings.Join(ss, ",")
}

func short(key string) string {
	if len(key) > 8 {
		return key[:8]
	}
	return key
}
