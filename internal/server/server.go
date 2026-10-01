// Package server accepts FRR's dplane_fpm_nl TCP connection and triggers
// reconciliation of WireGuard allowed-ips.
//
// The stream content is not interpreted: any dplane event is a signal that the
// FIB may have changed, and the syncer re-reads the kernel routing table. This
// keeps fpm-wg independent of FRR's internal nexthop representation.
package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"

	"github.com/ehealthid/fpm-wg/internal/fpm"
	"github.com/ehealthid/fpm-wg/internal/syncer"
)

// Server serves the FPM stream on a single TCP listener.
type Server struct {
	addr string
	syn  *syncer.Syncer
	log  *slog.Logger
}

// New builds a Server.
func New(addr string, syn *syncer.Syncer, log *slog.Logger) *Server {
	return &Server{addr: addr, syn: syn, log: log}
}

// Serve listens and handles connections until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	s.log.Info("listening for FPM", "addr", s.addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.handle(ctx, conn)
	}
}

// handle drains one zebra connection. FRR dials out and replays the whole RIB
// on connect, so peers are reloaded and a reconcile is scheduled per event.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	from := conn.RemoteAddr().String()
	s.log.Info("fpm connected", "from", from)
	if err := s.syn.Load(); err != nil {
		s.log.Error("load peers failed", "err", err)
	}
	s.syn.Notify()

	var frames int
	for ctx.Err() == nil {
		f, err := fpm.ReadFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				s.log.Warn("read frame", "err", err)
			}
			break
		}
		if f.Version != fpm.ProtoVersion || f.Type != fpm.MsgTypeNetlink {
			s.log.Warn("unexpected frame header", "version", f.Version, "type", f.Type)
			continue
		}
		s.syn.Notify()
		frames++
	}
	if err := s.syn.Reconcile(); err != nil {
		s.log.Error("final reconcile", "err", err)
	}
	s.log.Info("fpm disconnected", "from", from, "frames", frames)
}
