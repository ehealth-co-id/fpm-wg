package wg

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

// Exec drives the wg(8) CLI. Polls `wg show <iface> allowed-ips` for state and
// issues `wg set <iface> peer <key> allowed-ips <csv>` to apply changes.
//
// Bin defaults to $WG_BIN or "wg". In the lab, WG_BIN points at a shim that
// emulates the CLI with a JSON state file (WireGuard is unavailable on WSL2).
type Exec struct {
	Bin string
}

// NewExec returns an Exec applier using $WG_BIN or "wg".
func NewExec() *Exec {
	bin := os.Getenv("WG_BIN")
	if bin == "" {
		bin = "wg"
	}
	return &Exec{Bin: bin}
}

// Peers returns all peers and their allowed-ips.
func (e *Exec) Peers(iface string) ([]Peer, error) {
	out, err := exec.Command(e.Bin, "show", iface, "allowed-ips").Output()
	if err != nil {
		return nil, fmt.Errorf("wg show %s: %w", iface, err)
	}
	var peers []Peer
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		p := Peer{Key: fields[0]}
		for _, f := range fields[1:] {
			// wg may delimit allowed-ips with spaces or commas.
			for _, tok := range strings.Split(f, ",") {
				if tok == "" {
					continue
				}
				pfx, err := netip.ParsePrefix(tok)
				if err != nil {
					return nil, fmt.Errorf("parse allowed-ip %q: %w", tok, err)
				}
				p.AllowedIPs = append(p.AllowedIPs, pfx)
			}
		}
		peers = append(peers, p)
	}
	return peers, nil
}

// SetAllowedIPs replaces one peer's allowed-ips.
func (e *Exec) SetAllowedIPs(iface, key string, ips []netip.Prefix) error {
	strs := make([]string, len(ips))
	for i, p := range ips {
		strs[i] = p.String()
	}
	cmd := exec.Command(e.Bin, "set", iface, "peer", key, "allowed-ips", strings.Join(strs, ","))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg set %s peer %s: %w: %s", iface, key, err, strings.TrimSpace(string(out)))
	}
	return nil
}
