// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"io"
	"testing"
)

// TestFilterAddLatest tests the MsgFilterAdd API against the latest protocol
// version.
func TestFilterAddLatest(t *testing.T) {
	enc := BaseEncoding
	pver := ProtocolVersion

	data := []byte{0x01, 0x02}
	msg := NewMsgFilterAdd(data)

	// Ensure the command is expected value.
	wantCmd := "filteradd"
	assertCommand(t, msg, wantCmd)

	// Ensure max payload is expected value for a latest protocol version.
	wantPayload := uint64(523)
	assertMaxPayload(t, msg, pver, wantPayload)

	// Test encode with latest protocol version.
	var buf bytes.Buffer

	err := msg.BsvEncode(&buf, pver, enc)
	if err != nil {
		t.Errorf("encode of MsgFilterAdd failed %v err <%v>", msg, err)
	}

	// Test decode with latest protocol version.
	var readmsg MsgFilterAdd

	err = readmsg.Bsvdecode(&buf, pver, enc)
	if err != nil {
		t.Errorf("decode of MsgFilterAdd failed [%v] err <%v>", buf, err)
	}
}

// TestFilterAddCrossProtocol tests the MsgFilterAdd API when encoding with the
// latest protocol version and decoding with BIP0031Version.
func TestFilterAddCrossProtocol(t *testing.T) {
	data := []byte{0x01, 0x02}
	msg := NewMsgFilterAdd(data)

	if !bytes.Equal(msg.Data, data) {
		t.Errorf("should get same data back out")
	}

	// Encode with a latest protocol version.
	var buf bytes.Buffer

	err := msg.BsvEncode(&buf, ProtocolVersion, LatestEncoding)
	if err != nil {
		t.Errorf("encode of MsgFilterAdd failed %v err <%v>", msg, err)
	}

	// Decode with an old protocol version.
	var readmsg MsgFilterAdd

	err = readmsg.Bsvdecode(&buf, BIP0031Version, LatestEncoding)
	if err == nil {
		t.Errorf("decode of MsgFilterAdd succeeded when it shouldn't "+
			"have %v", msg)
	}

	// Since one of the protocol versions doesn't support the filteradd
	// message, make sure the data didn't get encoded and decoded back out.
	if bytes.Equal(msg.Data, readmsg.Data) {
		t.Error("should not get same data for cross protocol")
	}
}

// TestFilterAddMaxDataSize tests the MsgFilterAdd API maximum data size.
func TestFilterAddMaxDataSize(t *testing.T) {
	data := bytes.Repeat([]byte{0xff}, 521)
	msg := NewMsgFilterAdd(data)

	// Encode with a latest protocol version.
	var buf bytes.Buffer

	err := msg.BsvEncode(&buf, ProtocolVersion, LatestEncoding)
	if err == nil {
		t.Errorf("encode of MsgFilterAdd succeeded when it shouldn't "+
			"have %v", msg)
	}

	// Decode with a latest protocol version.
	readbuf := bytes.NewReader(data)

	err = msg.Bsvdecode(readbuf, ProtocolVersion, LatestEncoding)
	if err == nil {
		t.Errorf("decode of MsgFilterAdd succeeded when it shouldn't "+
			"have %v", msg)
	}
}

// TestFilterAddWireErrors performs negative tests against wire encode and decode
// of MsgFilterAdd to confirm error paths work correctly.
func TestFilterAddWireErrors(t *testing.T) {
	pver := ProtocolVersion
	pverNoFilterAdd := BIP0037Version - 1
	wireErr := &MessageError{}

	baseData := []byte{0x01, 0x02, 0x03, 0x04}
	baseFilterAdd := NewMsgFilterAdd(baseData)
	baseFilterAddEncoded := append([]byte{0x04}, baseData...)

	tests := []struct {
		in       *MsgFilterAdd   // Value to encode
		buf      []byte          // Wire encoding
		pver     uint32          // Protocol version for wire encoding
		enc      MessageEncoding // Message encoding format
		max      int             // Max size of fixed buffer to induce errors
		writeErr error           // Expected write error
		readErr  error           // Expected read error
	}{
		// Latest protocol version with intentional read/write errors.
		// Force error in data size.
		{
			baseFilterAdd, baseFilterAddEncoded, pver, BaseEncoding, 0,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in data.
		{
			baseFilterAdd, baseFilterAddEncoded, pver, BaseEncoding, 1,
			io.ErrShortWrite, io.EOF,
		},
		// Force error due to unsupported protocol version.
		{
			baseFilterAdd, baseFilterAddEncoded, pverNoFilterAdd, BaseEncoding, 5,
			wireErr, wireErr,
		},
	}

	t.Logf(runningTestsFmt, len(tests))

	for _, test := range tests {
		assertWireError(t, test.in, &MsgFilterAdd{}, test.buf, test.pver,
			test.enc, test.max, test.writeErr, test.readErr)
	}
}
