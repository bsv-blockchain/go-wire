// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

// TestFilterCLearLatest tests the MsgFilterClear API against the latest
// protocol version.
func TestFilterClearLatest(t *testing.T) {
	pver := ProtocolVersion
	msg := NewMsgFilterClear()

	// Ensure the command is expected value.
	wantCmd := "filterclear"
	assertCommand(t, msg, wantCmd)

	// Ensure max payload is expected value for the latest protocol version.
	wantPayload := uint64(0)
	assertMaxPayload(t, msg, pver, wantPayload)
}

// TestFilterClearCrossProtocol tests the MsgFilterClear API when encoding with
// the latest protocol version and decoding with BIP0031Version.
func TestFilterClearCrossProtocol(t *testing.T) {
	msg := NewMsgFilterClear()

	// Encode with the latest protocol version.
	var buf bytes.Buffer

	err := msg.BsvEncode(&buf, ProtocolVersion, LatestEncoding)
	if err != nil {
		t.Errorf("encode of MsgFilterClear failed %v err <%v>", msg, err)
	}

	// Decode with an old protocol version.
	var readmsg MsgFilterClear

	err = readmsg.Bsvdecode(&buf, BIP0031Version, LatestEncoding)
	if err == nil {
		t.Errorf("decode of MsgFilterClear succeeded when it "+
			"shouldn't have %v", msg)
	}
}

// TestFilterClearWire tests the MsgFilterClear wire encode and decode for
// various protocol versions.
func TestFilterClearWire(t *testing.T) {
	msgFilterClear := NewMsgFilterClear()

	var msgFilterClearEncoded []byte

	tests := []struct {
		in   *MsgFilterClear // Message to encode
		out  *MsgFilterClear // Expected decoded message
		buf  []byte          // Wire encoding
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encoding format
	}{
		// Latest protocol version.
		{
			msgFilterClear,
			msgFilterClear,
			msgFilterClearEncoded,
			ProtocolVersion,
			BaseEncoding,
		},

		// Protocol version BIP0037Version + 1.
		{
			msgFilterClear,
			msgFilterClear,
			msgFilterClearEncoded,
			BIP0037Version + 1,
			BaseEncoding,
		},

		// Protocol version BIP0037Version.
		{
			msgFilterClear,
			msgFilterClear,
			msgFilterClearEncoded,
			BIP0037Version,
			BaseEncoding,
		},
	}

	t.Logf(runningTestsFmt, len(tests))

	for i, test := range tests {
		// Encode the message to wire format.
		var buf bytes.Buffer

		err := test.in.BsvEncode(&buf, test.pver, test.enc)
		if err != nil {
			t.Errorf("BsvEncode #%d error %v", i, err)
			continue
		}

		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("BsvEncode #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode the message from wire format.
		var msg MsgFilterClear

		rbuf := bytes.NewReader(test.buf)

		err = msg.Bsvdecode(rbuf, test.pver, test.enc)
		if err != nil {
			t.Errorf("Bsvdecode #%d error %v", i, err)
			continue
		}

		if !reflect.DeepEqual(&msg, test.out) {
			t.Errorf("Bsvdecode #%d\n got: %s want: %s", i,
				spew.Sdump(msg), spew.Sdump(test.out))
			continue
		}
	}
}

// TestFilterClearWireErrors performs negative tests against wire encode and
// decode of MsgFilterClear to confirm error paths work correctly.
func TestFilterClearWireErrors(t *testing.T) {
	pverNoFilterClear := BIP0037Version - 1
	wireErr := &MessageError{}

	baseFilterClear := NewMsgFilterClear()

	var baseFilterClearEncoded []byte

	tests := []struct {
		in       *MsgFilterClear // Value to encode
		buf      []byte          // Wire encoding
		pver     uint32          // Protocol version for wire encoding
		enc      MessageEncoding // Message encoding format
		max      int             // Max size of fixed buffer to induce errors
		writeErr error           // Expected write error
		readErr  error           // Expected read error
	}{
		// Force error due to unsupported protocol version.
		{
			baseFilterClear, baseFilterClearEncoded,
			pverNoFilterClear, BaseEncoding, 4, wireErr, wireErr,
		},
	}

	t.Logf(runningTestsFmt, len(tests))

	for i, test := range tests {
		// Encode to wire format.
		w := newFixedWriter(test.max)

		err := test.in.BsvEncode(w, test.pver, test.enc)
		if reflect.TypeOf(err) != reflect.TypeOf(test.writeErr) {
			t.Errorf("BsvEncode #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// For errors which are not of type MessageError, check them for
		// equality.
		var msgError *MessageError
		if !errors.As(err, &msgError) {
			if !errors.Is(err, test.writeErr) {
				t.Errorf("BsvEncode #%d wrong error got: %v, "+
					"want: %v", i, err, test.writeErr)
				continue
			}
		}

		// Decode from wire format.
		var msg MsgFilterClear

		r := newFixedReader(test.max, test.buf)

		err = msg.Bsvdecode(r, test.pver, test.enc)
		if reflect.TypeOf(err) != reflect.TypeOf(test.readErr) {
			t.Errorf("Bsvdecode #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}

		// For errors which are not of type MessageError, check them for
		// equality.
		if !errors.As(err, &msgError) {
			if !errors.Is(err, test.readErr) {
				t.Errorf("Bsvdecode #%d wrong error got: %v, "+
					"want: %v", i, err, test.readErr)
				continue
			}
		}
	}
}
