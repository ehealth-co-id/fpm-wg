// Package server accepts FRR's dplane_fpm_nl TCP connection and feeds decoded
// messages to the syncer.
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
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.handle(ctx, conn)
	}
}

// handle processes one zebra connection to completion. FRR dials out and, on
// connect, replays the entire RIB, so peers are reloaded before processing.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	from := conn.RemoteAddr().String()
	s.log.Info("fpm connected", "from", from)
	if err := s.syn.Load(); err != nil {
		s.log.Error("load peers failed", "err", err)
	}

	var frames, routes int
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
		msgs, err := fpm.DecodeAll(f.Payload)
		if err != nil {
			s.log.Warn("decode payload", "err", err)
		}
		for _, m := range msgs {
			if m.Kind == fpm.KindRoute {
				routes++
			}
			s.syn.Apply(m)
		}
		frames++
	}
	if err := s.syn.Flush(); err != nil {
		s.log.Error("final flush", "err", err)
	}
	s.log.Info("fpm disconnected", "from", from, "frames", frames, "routes", routes)
}
