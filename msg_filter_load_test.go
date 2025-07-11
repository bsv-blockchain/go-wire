// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"
)

// TestFilterCLearLatest tests the MsgFilterLoad API against the latest protocol
// version.
func TestFilterLoadLatest(t *testing.T) {
	pver := ProtocolVersion
	enc := BaseEncoding

	data := []byte{0x01, 0x02}
	msg := NewMsgFilterLoad(data, 10, 0, 0)

	// Ensure the command is expected value.
	wantCmd := "filterload"
	assertCommand(t, msg, wantCmd)

	// Ensure max payload is expected value for the latest protocol version.
	wantPayload := uint64(36012)
	assertMaxPayload(t, msg, pver, wantPayload)

	// Test encode with latest protocol version.
	var buf bytes.Buffer

	err := msg.BsvEncode(&buf, pver, enc)
	if err != nil {
		t.Errorf("encode of MsgFilterLoad failed %v err <%v>", msg, err)
	}

	// Test decode with latest protocol version.
	readmsg := MsgFilterLoad{}

	err = readmsg.Bsvdecode(&buf, pver, enc)
	if err != nil {
		t.Errorf("decode of MsgFilterLoad failed [%v] err <%v>", buf, err)
	}
}

// TestFilterLoadCrossProtocol tests the MsgFilterLoad API when encoding with
// the latest protocol version and decoding with BIP0031Version.
func TestFilterLoadCrossProtocol(t *testing.T) {
	data := []byte{0x01, 0x02}
	msg := NewMsgFilterLoad(data, 10, 0, 0)

	// Encode with the latest protocol version.
	var buf bytes.Buffer

	err := msg.BsvEncode(&buf, ProtocolVersion, BaseEncoding)
	if err != nil {
		t.Errorf("encode of NewMsgFilterLoad failed %v err <%v>", msg,
			err)
	}

	// Decode with an old protocol version.
	var readmsg MsgFilterLoad

	err = readmsg.Bsvdecode(&buf, BIP0031Version, BaseEncoding)
	if err == nil {
		t.Errorf("decode of MsgFilterLoad succeeded when it shouldn't have %v",
			msg)
	}
}

// TestFilterLoadMaxFilterSize tests the MsgFilterLoad API maximum filter size.
func TestFilterLoadMaxFilterSize(t *testing.T) {
	data := bytes.Repeat([]byte{0xff}, 36001)
	msg := NewMsgFilterLoad(data, 10, 0, 0)

	// Encode with the latest protocol version.
	var buf bytes.Buffer

	err := msg.BsvEncode(&buf, ProtocolVersion, BaseEncoding)
	if err == nil {
		t.Errorf("encode of MsgFilterLoad succeeded when it shouldn't "+
			"have %v", msg)
	}

	// Decode with the latest protocol version.
	readbuf := bytes.NewReader(data)

	err = msg.Bsvdecode(readbuf, ProtocolVersion, BaseEncoding)
	if err == nil {
		t.Errorf("decode of MsgFilterLoad succeeded when it shouldn't "+
			"have %v", msg)
	}
}

// TestFilterLoadMaxHashFuncsSize tests the MsgFilterLoad API maximum hash functions.
func TestFilterLoadMaxHashFuncsSize(t *testing.T) {
	data := bytes.Repeat([]byte{0xff}, 10)
	msg := NewMsgFilterLoad(data, 61, 0, 0)

	// Encode with the latest protocol version.
	var buf bytes.Buffer

	err := msg.BsvEncode(&buf, ProtocolVersion, BaseEncoding)
	if err == nil {
		t.Errorf("encode of MsgFilterLoad succeeded when it shouldn't have %v",
			msg)
	}

	newBuf := []byte{
		0x0a,                                                       // filter size
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // filter
		0x3d, 0x00, 0x00, 0x00, // max hash funcs
		0x00, 0x00, 0x00, 0x00, // tweak
		0x00, // update Type
	}
	// Decode with the latest protocol version.
	readbuf := bytes.NewReader(newBuf)

	err = msg.Bsvdecode(readbuf, ProtocolVersion, BaseEncoding)
	if err == nil {
		t.Errorf("decode of MsgFilterLoad succeeded when it shouldn't have %v",
			msg)
	}
}

// TestFilterLoadWireErrors performs negative tests against wire encode and decode
// of MsgFilterLoad to confirm error paths work correctly.
func TestFilterLoadWireErrors(t *testing.T) {
	pver := ProtocolVersion
	pverNoFilterLoad := BIP0037Version - 1
	wireErr := &MessageError{}

	baseFilter := []byte{0x01, 0x02, 0x03, 0x04}
	baseFilterLoad := NewMsgFilterLoad(baseFilter, 10, 0, BloomUpdateNone)
	baseFilterLoadEncoded := append([]byte{0x04}, baseFilter...)
	baseFilterLoadEncoded = append(baseFilterLoadEncoded,
		0x00, 0x00, 0x00, 0x0a, // HashFuncs
		0x00, 0x00, 0x00, 0x00, // Tweak
		0x00) // Flags

	tests := []struct {
		in       *MsgFilterLoad  // Value to encode
		buf      []byte          // Wire encoding
		pver     uint32          // Protocol version for wire encoding
		enc      MessageEncoding // Message encoding format
		max      int             // Max size of fixed buffer to induce errors
		writeErr error           // Expected write error
		readErr  error           // Expected read error
	}{
		// Latest protocol version with intentional read/write errors.
		// Force error in filter size.
		{
			baseFilterLoad, baseFilterLoadEncoded, pver, BaseEncoding, 0,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in filter.
		{
			baseFilterLoad, baseFilterLoadEncoded, pver, BaseEncoding, 1,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in hash funcs.
		{
			baseFilterLoad, baseFilterLoadEncoded, pver, BaseEncoding, 5,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in tweak.
		{
			baseFilterLoad, baseFilterLoadEncoded, pver, BaseEncoding, 9,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in flags.
		{
			baseFilterLoad, baseFilterLoadEncoded, pver, BaseEncoding, 13,
			io.ErrShortWrite, io.EOF,
		},
		// Force error due to unsupported protocol version.
		{
			baseFilterLoad, baseFilterLoadEncoded, pverNoFilterLoad, BaseEncoding,
			10, wireErr, wireErr,
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
		var msg MsgFilterLoad

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
