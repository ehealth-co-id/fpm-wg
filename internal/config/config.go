// Package config loads fpm-wg runtime configuration.
//
// Zero-dependency: JSON file + flag overrides (see cmd/fpm-wg).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config is the on-disk configuration (JSON).
type Config struct {
	Listen            string `json:"listen"`             // TCP listen addr; FRR dials it
	Interface         string `json:"interface"`          // WireGuard interface, e.g. wg0
	TunnelNet         string `json:"tunnel_net"`         // CIDR of peer tunnel addrs, e.g. 192.168.200.0/24
	Applier           string `json:"applier"`            // "exec" (wg CLI) or "ctrl" (wgctrl netlink)
	FlushInterval     string `json:"flush_interval"`     // coalescing window, e.g. "100ms"
	ReconcileInterval string `json:"reconcile_interval"` // periodic FIB re-read, e.g. "30s" (0 disables)
	LogLevel          string `json:"log_level"`          // debug|info|warn|error
}

// Default returns production-sane defaults.
func Default() Config {
	return Config{
		Listen:            "127.0.0.1:2620",
		Interface:         "wg0",
		Applier:           "ctrl",
		FlushInterval:     "100ms",
		ReconcileInterval: "30s",
		LogLevel:          "info",
	}
}

// Load reads path (JSON) over the defaults. An empty path returns defaults.
func Load(path string) (Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse %s: %w", path, err)
	}
	return c, nil
}

// FlushDuration parses FlushInterval.
func (c Config) FlushDuration() (time.Duration, error) {
	if c.FlushInterval == "" {
		return 100 * time.Millisecond, nil
	}
	return time.ParseDuration(c.FlushInterval)
}

// ReconcileDuration parses ReconcileInterval. "0" disables periodic reconcile.
func (c Config) ReconcileDuration() (time.Duration, error) {
	if c.ReconcileInterval == "" {
		return 30 * time.Second, nil
	}
	return time.ParseDuration(c.ReconcileInterval)
}
