// Package wg applies allowed-ips changes to a WireGuard interface.
package wg

import "net/netip"

// Peer is a WireGuard peer's public key and its current allowed-ips.
type Peer struct {
	Key        string // base64 public key
	AllowedIPs []netip.Prefix
}

// Applier is the interface the syncer drives. Implementations:
//   - Exec: shells out to the wg(8) CLI (portable; used in the lab).
//   - Ctrl: direct WireGuard netlink via wgctrl (production; no fork).
type Applier interface {
	// Peers returns every peer on iface with its current allowed-ips.
	Peers(iface string) ([]Peer, error)
	// SetAllowedIPs atomically replaces the allowed-ips for one peer.
	SetAllowedIPs(iface, key string, ips []netip.Prefix) error
}
