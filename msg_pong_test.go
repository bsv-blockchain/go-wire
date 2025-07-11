// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPongLatest tests the MsgPong API against the latest protocol version.
func TestPongLatest(t *testing.T) {
	enc := BaseEncoding
	pver := ProtocolVersion

	nonce, err := RandomUint64()
	if err != nil {
		t.Errorf("RandomUint64: error generating nonce: %v", err)
	}

	msg := NewMsgPong(nonce)
	if msg.Nonce != nonce {
		t.Errorf("NewMsgPong: wrong nonce - got %v, want %v",
			msg.Nonce, nonce)
	}

	// Ensure the command is expected value.
	wantCmd := "pong"
	assertCommand(t, msg, wantCmd)

	// Ensure max payload is expected value for the latest protocol version.
	wantPayload := uint64(8)
	assertMaxPayload(t, msg, pver, wantPayload)

	assertWireRoundTrip(t, msg, NewMsgPong(0), pver, enc)
}

// TestPongBIP0031 tests the MsgPong API against the protocol version
// BIP0031Version.
func TestPongBIP0031(t *testing.T) {
	// Use the protocol version just prior to BIP0031Version changes.
	pver := BIP0031Version
	enc := BaseEncoding

	nonce, err := RandomUint64()
	if err != nil {
		t.Errorf("Error generating nonce: %v", err)
	}

	msg := NewMsgPong(nonce)
	if msg.Nonce != nonce {
		t.Errorf("Should get same nonce back out.")
	}

	// Ensure max payload is expected value for an old protocol version.
	size := msg.MaxPayloadLength(pver)
	if size != 0 {
		t.Errorf("Max length should be 0 for pong protocol version %d.",
			pver)
	}

	// Test encode with an old protocol version.
	var buf bytes.Buffer

	err = msg.BsvEncode(&buf, pver, enc)
	if err == nil {
		t.Errorf("encode of MsgPong succeeded when it shouldn't have %v",
			msg)
	}

	// Test decoding with an old protocol version.
	readmsg := NewMsgPong(0)

	err = readmsg.Bsvdecode(&buf, pver, enc)
	if err == nil {
		t.Errorf("decode of MsgPong succeeded when it shouldn't have %v",
			buf.Bytes())
	}

	// Since this protocol version doesn't support pong, make sure the
	// nonce didn't get encoded and decoded back out.
	if msg.Nonce == readmsg.Nonce {
		t.Errorf("Should not get same nonce for protocol version %d", pver)
	}
}

// TestPongCrossProtocol tests the MsgPong API when encoding with the latest
// protocol version and decoding with BIP0031Version.
func TestPongCrossProtocol(t *testing.T) {
	nonce, err := RandomUint64()
	if err != nil {
		t.Errorf("Error generating nonce: %v", err)
	}

	msg := NewMsgPong(nonce)
	if msg.Nonce != nonce {
		t.Errorf("Should get same nonce back out.")
	}

	// Encode with the latest protocol version.
	var buf bytes.Buffer

	err = msg.BsvEncode(&buf, ProtocolVersion, BaseEncoding)
	if err != nil {
		t.Errorf("encode of MsgPong failed %v err <%v>", msg, err)
	}

	// Decode with an old protocol version.
	readmsg := NewMsgPong(0)

	err = readmsg.Bsvdecode(&buf, BIP0031Version, BaseEncoding)
	if err == nil {
		t.Errorf("encode of MsgPong succeeded when it shouldn't have %v",
			msg)
	}

	// Since one of the protocol versions doesn't support the pong message,
	// make sure the nonce didn't get encoded and decoded back out.
	if msg.Nonce == readmsg.Nonce {
		t.Error("Should not get same nonce for cross protocol")
	}
}

// TestPongWire tests the MsgPong wire encode and decode for various protocol
// versions.
func TestPongWire(t *testing.T) {
	tests := []struct {
		in   MsgPong         // Message to encode
		out  MsgPong         // Expected decoded message
		buf  []byte          // Wire encoding
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encoding format
	}{
		// Latest protocol version.
		{
			MsgPong{Nonce: 123123}, // 0x1e0f3
			MsgPong{Nonce: 123123}, // 0x1e0f3
			[]byte{0xf3, 0xe0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			ProtocolVersion,
			BaseEncoding,
		},

		// Protocol version BIP0031Version+1
		{
			MsgPong{Nonce: 456456}, // 0x6f708
			MsgPong{Nonce: 456456}, // 0x6f708
			[]byte{0x08, 0xf7, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00},
			BIP0031Version + 1,
			BaseEncoding,
		},
	}

	t.Logf(runningTestsFmt, len(tests))

	for i, test := range tests {
		if test.in.Nonce == test.out.Nonce {
			assertWireRoundTrip(t, &test.in, &test.out, test.pver, test.enc)
		}

		var buf bytes.Buffer
		require.NoError(t, test.in.BsvEncode(&buf, test.pver, test.enc))
		assert.True(t, bytes.Equal(buf.Bytes(), test.buf), "test %d encode mismatch", i)
	}
}

// TestPongWireErrors performs negative tests against wire encode and decode
// of MsgPong to confirm error paths work correctly.
func TestPongWireErrors(t *testing.T) {
	pver := ProtocolVersion
	pverNoPong := BIP0031Version
	wireErr := &MessageError{}

	basePong := NewMsgPong(123123) // 0x1e0f3
	basePongEncoded := []byte{
		0xf3, 0xe0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	tests := []struct {
		in       *MsgPong        // Value to encode
		buf      []byte          // Wire encoding
		pver     uint32          // Protocol version for wire encoding
		enc      MessageEncoding // Message encoding format
		max      int             // Max size of fixed buffer to induce errors
		writeErr error           // Expected write error
		readErr  error           // Expected read error
	}{
		// Latest protocol version with intentional read/write errors.
		// Force error in nonce.
		{basePong, basePongEncoded, pver, BaseEncoding, 0, io.ErrShortWrite, io.EOF},
		// Force error due to unsupported protocol version.
		{basePong, basePongEncoded, pverNoPong, BaseEncoding, 4, wireErr, wireErr},
	}

	t.Logf(runningTestsFmt, len(tests))

	for _, test := range tests {
		assertWireError(t, test.in, &MsgPong{}, test.buf, test.pver,
			test.enc, test.max, test.writeErr, test.readErr)
	}
}
