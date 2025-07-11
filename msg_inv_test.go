// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

// TestInv tests the MsgInv API.
func TestInv(t *testing.T) {
	pver := ProtocolVersion

	// Ensure the command is expected value.
	wantCmd := "inv"
	msg := NewMsgInv()

	if cmd := msg.Command(); cmd != wantCmd {
		t.Errorf("NewMsgInv: wrong command - got %v want %v",
			cmd, wantCmd)
	}

	// Ensure max payload is expected value for a latest protocol version.
	// Num inventory vectors (varInt) + max allowed inventory vectors.
	wantPayload := uint64(1800009)
	maxPayload := msg.MaxPayloadLength(pver)

	if maxPayload != wantPayload {
		t.Errorf("MaxPayloadLength: wrong max payload length for "+
			"protocol version %d - got %v, want %v", pver,
			maxPayload, wantPayload)
	}

	// Ensure inventory vectors are added properly.
	hash := chainhash.Hash{}
	iv := NewInvVect(InvTypeBlock, &hash)

	err := msg.AddInvVect(iv)
	if err != nil {
		t.Errorf("AddInvVect: %v", err)
	}

	if msg.InvList[0] != iv {
		t.Errorf("AddInvVect: wrong invvect added - got %v, want %v",
			spew.Sprint(msg.InvList[0]), spew.Sprint(iv))
	}

	// Ensure adding more than the max allowed inventory vectors per
	// message returns an error.
	for i := 0; i < MaxInvPerMsg; i++ {
		err = msg.AddInvVect(iv)
	}

	if err == nil {
		t.Errorf("AddInvVect: expected error on too many inventory " +
			"vectors not received")
	}

	// Ensure creating the message with a size hint larger than the max
	// works as expected.
	msg = NewMsgInvSizeHint(MaxInvPerMsg + 1)
	wantCap := MaxInvPerMsg

	if cap(msg.InvList) != wantCap {
		t.Errorf("NewMsgInvSizeHint: wrong cap for size hint - "+
			"got %v, want %v", cap(msg.InvList), wantCap)
	}
}

// TestInvWire tests the MsgInv wire encode and decode for various numbers
// of inventory vectors and protocol versions.
func TestInvWire(t *testing.T) {
	// Block 203707 hash.
	hashStr := "3264bc2ac36a60840790ba1d475d01367e7c723da941069e9dc"

	blockHash, err := chainhash.NewHashFromStr(hashStr)
	if err != nil {
		t.Errorf("NewHashFromStr: %v", err)
	}

	// Transaction 1 of Block 203707 hash.
	hashStr = "d28a3dc7392bf00a9855ee93dd9a81eff82a2c4fe57fbd42cfe71b487accfaf0"

	txHash, err := chainhash.NewHashFromStr(hashStr)
	if err != nil {
		t.Errorf("NewHashFromStr: %v", err)
	}

	iv := NewInvVect(InvTypeBlock, blockHash)
	iv2 := NewInvVect(InvTypeTx, txHash)

	// Empty inv message.
	NoInv := NewMsgInv()
	NoInvEncoded := []byte{
		0x00, // Varint for number of inventory vectors
	}

	// Inv message with multiple inventory vectors.
	MultiInv := NewMsgInv()
	err = MultiInv.AddInvVect(iv)
	require.NoError(t, err)

	err = MultiInv.AddInvVect(iv2)
	require.NoError(t, err)

	MultiInvEncoded := []byte{
		0x02,                   // Varint for number of inv vectors
		0x02, 0x00, 0x00, 0x00, // InvTypeBlock
		0xdc, 0xe9, 0x69, 0x10, 0x94, 0xda, 0x23, 0xc7,
		0xe7, 0x67, 0x13, 0xd0, 0x75, 0xd4, 0xa1, 0x0b,
		0x79, 0x40, 0x08, 0xa6, 0x36, 0xac, 0xc2, 0x4b,
		0x26, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Block 203707 hash
		0x01, 0x00, 0x00, 0x00, // InvTypeTx
		0xf0, 0xfa, 0xcc, 0x7a, 0x48, 0x1b, 0xe7, 0xcf,
		0x42, 0xbd, 0x7f, 0xe5, 0x4f, 0x2c, 0x2a, 0xf8,
		0xef, 0x81, 0x9a, 0xdd, 0x93, 0xee, 0x55, 0x98,
		0x0a, 0xf0, 0x2b, 0x39, 0xc7, 0x3d, 0x8a, 0xd2, // Tx 1 of block 203707 hash
	}

	tests := []struct {
		in   *MsgInv         // Message to encode
		out  *MsgInv         // Expected decoded message
		buf  []byte          // Wire encoding pver uint32
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encoding format
	}{
		// Latest protocol version with no inv vectors.
		{
			NoInv,
			NoInv,
			NoInvEncoded,
			ProtocolVersion,
			BaseEncoding,
		},

		// Latest protocol version with multiple inv vectors.
		{
			MultiInv,
			MultiInv,
			MultiInvEncoded,
			ProtocolVersion,
			BaseEncoding,
		},

		// Protocol version BIP0035Version no inv vectors.
		{
			NoInv,
			NoInv,
			NoInvEncoded,
			BIP0035Version,
			BaseEncoding,
		},

		// Protocol version BIP0035Version with multiple inv vectors.
		{
			MultiInv,
			MultiInv,
			MultiInvEncoded,
			BIP0035Version,
			BaseEncoding,
		},

		// Protocol version BIP0031Version no inv vectors.
		{
			NoInv,
			NoInv,
			NoInvEncoded,
			BIP0031Version,
			BaseEncoding,
		},

		// Protocol version BIP0031Version with multiple inv vectors.
		{
			MultiInv,
			MultiInv,
			MultiInvEncoded,
			BIP0031Version,
			BaseEncoding,
		},

		// Protocol version NetAddressTimeVersion no inv vectors.
		{
			NoInv,
			NoInv,
			NoInvEncoded,
			NetAddressTimeVersion,
			BaseEncoding,
		},

		// Protocol version NetAddressTimeVersion with multiple inv vectors.
		{
			MultiInv,
			MultiInv,
			MultiInvEncoded,
			NetAddressTimeVersion,
			BaseEncoding,
		},

		// Protocol version MultipleAddressVersion no inv vectors.
		{
			NoInv,
			NoInv,
			NoInvEncoded,
			MultipleAddressVersion,
			BaseEncoding,
		},

		// Protocol version MultipleAddressVersion with multiple inv vectors.
		{
			MultiInv,
			MultiInv,
			MultiInvEncoded,
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
		var msg MsgInv

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

// TestInvWireErrors performs negative tests against wire encode and decode
// of MsgInv to confirm error paths work correctly.
func TestInvWireErrors(t *testing.T) {
	pver := ProtocolVersion
	wireErr := &MessageError{}

	// Block 203707 hash.
	hashStr := "3264bc2ac36a60840790ba1d475d01367e7c723da941069e9dc"

	blockHash, err := chainhash.NewHashFromStr(hashStr)
	if err != nil {
		t.Errorf("NewHashFromStr: %v", err)
	}

	iv := NewInvVect(InvTypeBlock, blockHash)

	// Base inv message used to induce errors.
	baseInv := NewMsgInv()
	err = baseInv.AddInvVect(iv)
	require.NoError(t, err)

	baseInvEncoded := []byte{
		0x02,                   // Varint for number of inv vectors
		0x02, 0x00, 0x00, 0x00, // InvTypeBlock
		0xdc, 0xe9, 0x69, 0x10, 0x94, 0xda, 0x23, 0xc7,
		0xe7, 0x67, 0x13, 0xd0, 0x75, 0xd4, 0xa1, 0x0b,
		0x79, 0x40, 0x08, 0xa6, 0x36, 0xac, 0xc2, 0x4b,
		0x26, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Block 203707 hash
	}

	// Inv message that forces an error by having more than the max allowed
	// inv vectors.
	maxInv := NewMsgInv()
	for i := 0; i < MaxInvPerMsg; i++ {
		err = maxInv.AddInvVect(iv)
		require.NoError(t, err)
	}

	maxInv.InvList = append(maxInv.InvList, iv)
	maxInvEncoded := []byte{
		0xfd, 0x51, 0xc3, // Varint for number of inv vectors (50001)
	}

	tests := []struct {
		in       *MsgInv         // Value to encode
		buf      []byte          // Wire encoding
		pver     uint32          // Protocol version for wire encoding
		enc      MessageEncoding // Message encoding format
		max      int             // Max size of fixed buffer to induce errors
		writeErr error           // Expected write error
		readErr  error           // Expected read error
	}{
		// Latest protocol version with intentional read/write errors.
		// Force error in inventory vector count
		{baseInv, baseInvEncoded, pver, BaseEncoding, 0, io.ErrShortWrite, io.EOF},
		// Force error in an inventory list.
		{baseInv, baseInvEncoded, pver, BaseEncoding, 1, io.ErrShortWrite, io.EOF},
		// Force error with greater than max inventory vectors.
		{maxInv, maxInvEncoded, pver, BaseEncoding, 3, wireErr, wireErr},
	}

	t.Logf(runningTestsFmt, len(tests))

	for i, test := range tests {
		// Encode to wire format.
		w := newFixedWriter(test.max)

		err = test.in.BsvEncode(w, test.pver, test.enc)
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
		var msg MsgInv

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
