// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

// TestGetAddr tests the MsgGetAddr API.
func TestGetAddr(t *testing.T) {
	pver := ProtocolVersion

	// Ensure the command is expected value.
	wantCmd := "getaddr"
	msg := NewMsgGetAddr()

	assertCommand(t, msg, wantCmd)

	// Ensure max payload is expected value for latest protocol version.
	// Num addresses (varInt) + max allowed addresses.
	wantPayload := uint64(0)
	assertMaxPayload(t, msg, pver, wantPayload)
}

// TestGetAddrWire tests the MsgGetAddr wire encode and decode for various
// protocol versions.
func TestGetAddrWire(t *testing.T) {
	msgGetAddr := NewMsgGetAddr()
	msgGetAddrEncoded := []byte{}

	tests := []struct {
		in   *MsgGetAddr     // Message to encode
		out  *MsgGetAddr     // Expected decoded message
		buf  []byte          // Wire encoding
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encoding variant.
	}{
		// Latest protocol version.
		{
			msgGetAddr,
			msgGetAddr,
			msgGetAddrEncoded,
			ProtocolVersion,
			BaseEncoding,
		},

		// Protocol version BIP0035Version.
		{
			msgGetAddr,
			msgGetAddr,
			msgGetAddrEncoded,
			BIP0035Version,
			BaseEncoding,
		},

		// Protocol version BIP0031Version.
		{
			msgGetAddr,
			msgGetAddr,
			msgGetAddrEncoded,
			BIP0031Version,
			BaseEncoding,
		},

		// Protocol version NetAddressTimeVersion.
		{
			msgGetAddr,
			msgGetAddr,
			msgGetAddrEncoded,
			NetAddressTimeVersion,
			BaseEncoding,
		},

		// Protocol version MultipleAddressVersion.
		{
			msgGetAddr,
			msgGetAddr,
			msgGetAddrEncoded,
			MultipleAddressVersion,
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
		var msg MsgGetAddr

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
