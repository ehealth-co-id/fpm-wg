package wg

import (
	"fmt"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Ctrl applies allowed-ips directly over WireGuard's generic-netlink family.
// No wg(8) fork; the production applier.
type Ctrl struct {
	c *wgctrl.Client
}

// NewCtrl opens a wgctrl client.
func NewCtrl() (*Ctrl, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	return &Ctrl{c: c}, nil
}

// Close releases the client.
func (c *Ctrl) Close() error { return c.c.Close() }

// Peers returns every peer and its allowed-ips.
func (c *Ctrl) Peers(iface string) ([]Peer, error) {
	dev, err := c.c.Device(iface)
	if err != nil {
		return nil, fmt.Errorf("wgctrl device %s: %w", iface, err)
	}
	out := make([]Peer, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		peer := Peer{Key: p.PublicKey.String()}
		for _, ipn := range p.AllowedIPs {
			if pfx, ok := fromIPNet(ipn); ok {
				peer.AllowedIPs = append(peer.AllowedIPs, pfx)
			}
		}
		out = append(out, peer)
	}
	return out, nil
}

// SetAllowedIPs replaces one peer's allowed-ips. UpdateOnly ensures we never
// create a peer that does not already exist on the interface.
func (c *Ctrl) SetAllowedIPs(iface, key string, ips []netip.Prefix) error {
	pub, err := wgtypes.ParseKey(key)
	if err != nil {
		return fmt.Errorf("parse peer key %q: %w", key, err)
	}
	nets := make([]net.IPNet, len(ips))
	for i, p := range ips {
		nets[i] = toIPNet(p)
	}
	cfg := wgtypes.Config{Peers: []wgtypes.PeerConfig{{
		PublicKey:         pub,
		UpdateOnly:        true,
		ReplaceAllowedIPs: true,
		AllowedIPs:        nets,
	}}}
	if err := c.c.ConfigureDevice(iface, cfg); err != nil {
		return fmt.Errorf("wgctrl configure %s: %w", iface, err)
	}
	return nil
}

func toIPNet(p netip.Prefix) net.IPNet {
	a := p.Addr()
	if a.Is4() {
		return net.IPNet{IP: net.IP(a.AsSlice()), Mask: net.CIDRMask(p.Bits(), 32)}
	}
	return net.IPNet{IP: net.IP(a.AsSlice()), Mask: net.CIDRMask(p.Bits(), 128)}
}

func fromIPNet(n net.IPNet) (netip.Prefix, bool) {
	ones, bits := n.Mask.Size()
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	if addr.Is4() && bits == 128 {
		ones -= 96 // v4-mapped: normalise prefix length to the v4 family
	}
	if ones < 0 || ones > addr.BitLen() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, ones), true
}
