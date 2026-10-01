// Command fpm-wg syncs WireGuard allowed-ips from FRR's dplane_fpm_nl stream.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/ehealthid/fpm-wg/internal/config"
	"github.com/ehealthid/fpm-wg/internal/server"
	"github.com/ehealthid/fpm-wg/internal/syncer"
	wg "github.com/ehealthid/fpm-wg/internal/wg"
)

func main() {
	cfgPath := flag.String("config", "", "path to JSON config file")
	listen := flag.String("listen", "", "override listen address")
	iface := flag.String("interface", "", "override WireGuard interface")
	applier := flag.String("applier", "", "override applier: exec|ctrl")
	tunnelNet := flag.String("tunnel-net", "", "override tunnel_net CIDR")
	logLevel := flag.String("log-level", "", "override log level")
	flag.Parse()

	if err := run(*cfgPath, *listen, *iface, *applier, *tunnelNet, *logLevel); err != nil {
		fmt.Fprintln(os.Stderr, "fpm-wg:", err)
		os.Exit(1)
	}
}

func run(cfgPath, listen, iface, applier, tunnelNet, logLevel string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if listen != "" {
		cfg.Listen = listen
	}
	if iface != "" {
		cfg.Interface = iface
	}
	if applier != "" {
		cfg.Applier = applier
	}
	if tunnelNet != "" {
		cfg.TunnelNet = tunnelNet
	}
	if logLevel != "" {
		cfg.LogLevel = logLevel
	}

	log := newLogger(cfg.LogLevel)

	flushEvery, err := cfg.FlushDuration()
	if err != nil {
		return fmt.Errorf("flush_interval: %w", err)
	}

	app, err := newApplier(cfg.Applier)
	if err != nil {
		return err
	}

	var tnet netip.Prefix
	if cfg.TunnelNet != "" {
		tnet, err = netip.ParsePrefix(cfg.TunnelNet)
		if err != nil {
			return fmt.Errorf("tunnel_net: %w", err)
		}
	}

	syn := syncer.New(cfg.Interface, tnet, app, flushEvery, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go syn.Run(ctx)

	log.Info("fpm-wg starting",
		"interface", cfg.Interface, "tunnel_net", cfg.TunnelNet,
		"applier", cfg.Applier, "flush_interval", flushEvery)

	srv := server.New(cfg.Listen, syn, log)
	return srv.Serve(ctx)
}

func newApplier(name string) (wg.Applier, error) {
	switch name {
	case "exec":
		return wg.NewExec(), nil
	case "ctrl", "":
		return wg.NewCtrl()
	default:
		return nil, fmt.Errorf("unknown applier %q (want exec|ctrl)", name)
	}
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
}
