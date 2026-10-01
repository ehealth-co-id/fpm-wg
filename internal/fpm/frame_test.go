package fpm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

// Frame captured live from stock FRR 10.6.2 dplane_fpm_nl.
const capturedFrame = "34000000180001050000000094a2ebdc02180000fec400010000000008000100c0a80000080006001400000008001e000f000000"

func TestReadFrameRoundTrip(t *testing.T) {
	payload, err := hex.DecodeString(capturedFrame)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	hdr := []byte{ProtoVersion, MsgTypeNetlink, 0, 0}
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(payload)+headerSize))
	buf.Write(hdr)
	buf.Write(payload)

	f, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if f.Version != ProtoVersion || f.Type != MsgTypeNetlink {
		t.Fatalf("hdr = %d/%d", f.Version, f.Type)
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Fatal("payload mismatch")
	}
	if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestReadFrameRejectsBadLen(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader([]byte{1, 1, 0, 2}))
	if !errors.Is(err, ErrBadLen) {
		t.Fatalf("want ErrBadLen, got %v", err)
	}
}
