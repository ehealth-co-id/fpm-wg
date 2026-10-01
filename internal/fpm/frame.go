// Package fpm decodes FRR's dplane_fpm_nl wire protocol.
//
// dplane_fpm_nl (zebra/dplane_fpm_nl.c) streams route dataplane events as:
//
//	[u8 version=1][u8 msg_type=1(netlink)][u16be len][netlink message]
//
// where len *includes* the 4-byte FPM header, i.e. len(payload) == len-4.
// The payload is a standard kernel-style netlink message (see netlink.go).
package fpm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Wire framing constants.
const (
	ProtoVersion   = 1
	MsgTypeNetlink = 1
	headerSize     = 4
)

// ErrBadLen means the declared frame length is smaller than the header.
var ErrBadLen = errors.New("fpm: declared length smaller than header")

// Frame is a single FPM message.
type Frame struct {
	Version byte
	Type    byte
	Payload []byte // one or more netlink messages
}

// ReadFrame reads exactly one frame from r. A clean close at a frame boundary
// yields io.EOF; a close mid-frame yields io.ErrUnexpectedEOF.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [headerSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	total := int(binary.BigEndian.Uint16(hdr[2:4]))
	if total < headerSize {
		return Frame{}, fmt.Errorf("%w: len=%d", ErrBadLen, total)
	}
	f := Frame{
		Version: hdr[0],
		Type:    hdr[1],
		Payload: make([]byte, total-headerSize),
	}
	if _, err := io.ReadFull(r, f.Payload); err != nil {
		return Frame{}, err
	}
	return f, nil
}
