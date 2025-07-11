// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
	"github.com/davecgh/go-spew/spew"
)

// TestTx tests the MsgTx API.
func TestTx(t *testing.T) {
	pver := ProtocolVersion

	// Block 100000 hash.
	hashStr := "3ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"

	hash, err := chainhash.NewHashFromStr(hashStr)
	if err != nil {
		t.Errorf("NewHashFromStr: %v", err)
	}

	// Ensure the command is expected value.
	wantCmd := "tx"
	msg := NewMsgTx(1)

	if cmd := msg.Command(); cmd != wantCmd {
		t.Errorf("NewMsgAddr: wrong command - got %v want %v",
			cmd, wantCmd)
	}

	// Ensure max payload is expected value for the latest protocol version.
	wantPayload := fixedExcessiveBlockSize
	maxPayload := msg.MaxPayloadLength(pver)

	if maxPayload != wantPayload {
		t.Errorf("MaxPayloadLength: wrong max payload length for "+
			"protocol version %d - got %v, want %v", pver,
			maxPayload, wantPayload)
	}

	// Ensure we get the same transaction output point data back out.
	// NOTE: This is a block hash and made up index, but we're only
	// testing package functionality.
	prevOutIndex := uint32(1)

	prevOut := NewOutPoint(hash, prevOutIndex)
	if !prevOut.Hash.IsEqual(hash) {
		t.Errorf("NewOutPoint: wrong hash - got %v, want %v",
			spew.Sprint(&prevOut.Hash), spew.Sprint(hash))
	}

	if prevOut.Index != prevOutIndex {
		t.Errorf("NewOutPoint: wrong index - got %v, want %v",
			prevOut.Index, prevOutIndex)
	}

	prevOutStr := fmt.Sprintf("%s:%d", hash.String(), prevOutIndex)
	if s := prevOut.String(); s != prevOutStr {
		t.Errorf("OutPoint.String: unexpected result - got %v, "+
			"want %v", s, prevOutStr)
	}

	// Ensure we get the same transaction input back out.
	sigScript := []byte{0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62}

	txIn := NewTxIn(prevOut, sigScript)
	if !reflect.DeepEqual(&txIn.PreviousOutPoint, prevOut) {
		t.Errorf("NewTxIn: wrong prev outpoint - got %v, want %v",
			spew.Sprint(&txIn.PreviousOutPoint),
			spew.Sprint(prevOut))
	}

	if !bytes.Equal(txIn.SignatureScript, sigScript) {
		t.Errorf("NewTxIn: wrong signature script - got %v, want %v",
			spew.Sdump(txIn.SignatureScript),
			spew.Sdump(sigScript))
	}

	// Ensure we get the same transaction output back out.
	txValue := int64(5000000000)
	pkScript := []byte{
		0x41, // OP_DATA_65
		0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
		0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
		0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
		0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
		0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
		0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
		0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
		0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
		0xa6, // 65-byte signature
		0xac, // OP_CHECKSIG
	}

	txOut := NewTxOut(txValue, pkScript)
	if txOut.Value != txValue {
		t.Errorf("NewTxOut: wrong pk script - got %v, want %v",
			txOut.Value, txValue)
	}

	if !bytes.Equal(txOut.PkScript, pkScript) {
		t.Errorf("NewTxOut: wrong pk script - got %v, want %v",
			spew.Sdump(txOut.PkScript),
			spew.Sdump(pkScript))
	}

	// Ensure transaction inputs are added properly.
	msg.AddTxIn(txIn)

	if !reflect.DeepEqual(msg.TxIn[0], txIn) {
		t.Errorf("AddTxIn: wrong transaction input added - got %v, want %v",
			spew.Sprint(msg.TxIn[0]), spew.Sprint(txIn))
	}

	// Ensure transaction outputs are added properly.
	msg.AddTxOut(txOut)

	if !reflect.DeepEqual(msg.TxOut[0], txOut) {
		t.Errorf("AddTxIn: wrong transaction output added - got %v, want %v",
			spew.Sprint(msg.TxOut[0]), spew.Sprint(txOut))
	}

	// Ensure the copy produced an identical transaction message.
	newMsg := msg.Copy()
	if !reflect.DeepEqual(newMsg, msg) {
		t.Errorf("Copy: mismatched tx messages - got %v, want %v",
			spew.Sdump(newMsg), spew.Sdump(msg))
	}
}

// TestTxHash tests the ability to generate the hash of a transaction accurately.
func TestTxHash(t *testing.T) {
	// Hash of first transaction from block 113875.
	hashStr := "f051e59b5e2503ac626d03aaeac8ab7be2d72ba4b7e97119c5852d70d52dcb86"

	wantHash, err := chainhash.NewHashFromStr(hashStr)
	if err != nil {
		t.Errorf("NewHashFromStr: %v", err)
		return
	}

	// First transaction from block 113875.
	msgTx := NewMsgTx(1)
	txIn := TxIn{
		PreviousOutPoint: OutPoint{
			Hash:  chainhash.Hash{},
			Index: 0xffffffff,
		},
		SignatureScript: []byte{0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62},
		Sequence:        0xffffffff,
	}
	txOut := TxOut{
		Value: 5000000000,
		PkScript: []byte{
			0x41, // OP_DATA_65
			0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
			0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
			0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
			0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
			0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
			0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
			0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
			0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
			0xa6, // 65-byte signature
			0xac, // OP_CHECKSIG
		},
	}

	msgTx.AddTxIn(&txIn)
	msgTx.AddTxOut(&txOut)
	msgTx.LockTime = 0

	// Ensure the hash produced is expected.
	txHash := msgTx.TxHash()
	if !txHash.IsEqual(wantHash) {
		t.Errorf("TxHash: wrong hash - got %v, want %v",
			spew.Sprint(txHash), spew.Sprint(wantHash))
	}
}

// TestTxSha tests the ability to generate the wtxid, and txid of a transaction
// with witness inputs accurately.
func TestWTxSha(t *testing.T) {
	hashStrTxid := "0f167d1385a84d1518cfee208b653fc9163b605ccf1b75347e2850b3e2eb19f3"

	wantHashTxid, err := chainhash.NewHashFromStr(hashStrTxid)
	if err != nil {
		t.Errorf("NewShaHashFromStr: %v", err)
		return
	}

	// From block 23157 in a past version of segnet.
	msgTx := NewMsgTx(1)
	txIn := TxIn{
		PreviousOutPoint: OutPoint{
			Hash: chainhash.Hash{
				0xa5, 0x33, 0x52, 0xd5, 0x13, 0x57, 0x66, 0xf0,
				0x30, 0x76, 0x59, 0x74, 0x18, 0x26, 0x3d, 0xa2,
				0xd9, 0xc9, 0x58, 0x31, 0x59, 0x68, 0xfe, 0xa8,
				0x23, 0x52, 0x94, 0x67, 0x48, 0x1f, 0xf9, 0xcd,
			},
			Index: 19,
		},
		Sequence: 0xffffffff,
	}
	txOut := TxOut{
		Value: 395019,
		PkScript: []byte{
			0x00, // Version 0 witness program
			0x14, // OP_DATA_20
			0x9d, 0xda, 0xc6, 0xf3, 0x9d, 0x51, 0xe0, 0x39,
			0x8e, 0x53, 0x2a, 0x22, 0xc4, 0x1b, 0xa1, 0x89,
			0x40, 0x6a, 0x85, 0x23, // 20-byte pub key hash
		},
	}

	msgTx.AddTxIn(&txIn)
	msgTx.AddTxOut(&txOut)
	msgTx.LockTime = 0

	// Ensure the correct txid, and wtxid is produced as expected.
	txid := msgTx.TxHash()
	if !txid.IsEqual(wantHashTxid) {
		t.Errorf("TxSha: wrong hash - got %v, want %v",
			spew.Sprint(txid), spew.Sprint(wantHashTxid))
	}
}

// TestTxWire tests the MsgTx wire encode and decode for various numbers
// of transaction inputs and outputs and protocol versions.
func TestTxWire(t *testing.T) {
	// Empty tx message.
	noTx := NewMsgTx(1)
	noTx.Version = 1
	noTxEncoded := []byte{
		0x01, 0x00, 0x00, 0x00, // Version
		0x00,                   // Varint for number of input transactions
		0x00,                   // Varint for number of output transactions
		0x00, 0x00, 0x00, 0x00, // Lock time
	}

	tests := []struct {
		in   *MsgTx          // Message to encode
		out  *MsgTx          // Expected decoded message
		buf  []byte          // Wire encoding
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encoding format
	}{
		// Latest protocol version with no transactions.
		{
			noTx,
			noTx, noTxEncoded,
			ProtocolVersion,
			BaseEncoding,
		},

		// Latest protocol version with multiple transactions.
		{
			multiTx,
			multiTx,
			multiTxEncoded,
			ProtocolVersion,
			BaseEncoding,
		},

		// Protocol version BIP0035Version with no transactions.
		{
			noTx,
			noTx,
			noTxEncoded,
			BIP0035Version,
			BaseEncoding,
		},

		// Protocol version BIP0035Version with multiple transactions.
		{
			multiTx,
			multiTx,
			multiTxEncoded,
			BIP0035Version,
			BaseEncoding,
		},

		// Protocol version BIP0031Version with no transactions.
		{
			noTx,
			noTx,
			noTxEncoded,
			BIP0031Version,
			BaseEncoding,
		},

		// Protocol version BIP0031Version with multiple transactions.
		{
			multiTx,
			multiTx,
			multiTxEncoded,
			BIP0031Version,
			BaseEncoding,
		},

		// Protocol version NetAddressTimeVersion with no transactions.
		{
			noTx,
			noTx,
			noTxEncoded,
			NetAddressTimeVersion,
			BaseEncoding,
		},

		// Protocol version NetAddressTimeVersion with multiple transactions.
		{
			multiTx,
			multiTx,
			multiTxEncoded,
			NetAddressTimeVersion,
			BaseEncoding,
		},

		// Protocol version MultipleAddressVersion with no transactions.
		{
			noTx,
			noTx,
			noTxEncoded,
			MultipleAddressVersion,
			BaseEncoding,
		},

		// Protocol version MultipleAddressVersion with multiple transactions.
		{
			multiTx,
			multiTx,
			multiTxEncoded,
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
		var msg MsgTx

		rbuf := bytes.NewReader(test.buf)

		err = msg.Bsvdecode(rbuf, test.pver, test.enc)
		if err != nil {
			t.Errorf("Bsvdecode #%d error %v", i, err)
			continue
		}

		if !reflect.DeepEqual(&msg, test.out) {
			t.Errorf("Bsvdecode #%d\n got: %s want: %s", i,
				spew.Sdump(&msg), spew.Sdump(test.out))
			continue
		}
	}
}

// TestTxWireErrors performs negative tests against wire encode and decode
// of MsgTx to confirm error paths work correctly.
func TestTxWireErrors(t *testing.T) {
	// Use protocol version 60002 specifically here instead of the latest
	// because the test data is using bytes encoded with that protocol
	// version.
	pver := uint32(60002)

	tests := []struct {
		in       *MsgTx          // Value to encode
		buf      []byte          // Wire encoding
		pver     uint32          // Protocol version for wire encoding
		enc      MessageEncoding // Message encoding format
		max      int             // Max size of fixed buffer to induce errors
		writeErr error           // Expected write error
		readErr  error           // Expected read error
	}{
		// Force error in version.
		{multiTx, multiTxEncoded, pver, BaseEncoding, 0, io.ErrShortWrite, io.EOF},
		// Force error in number of transaction inputs.
		{multiTx, multiTxEncoded, pver, BaseEncoding, 4, io.ErrShortWrite, io.EOF},
		// Force error in transaction input previous block hash.
		{multiTx, multiTxEncoded, pver, BaseEncoding, 5, io.ErrShortWrite, io.EOF},
		// Force error in transaction input previous block output index.
		{multiTx, multiTxEncoded, pver, BaseEncoding, 37, io.ErrShortWrite, io.EOF},
		// Force error in transaction input signature script length.
		{multiTx, multiTxEncoded, pver, BaseEncoding, 41, io.ErrShortWrite, io.EOF},
		// Force error in transaction input signature script.
		{multiTx, multiTxEncoded, pver, BaseEncoding, 42, io.ErrShortWrite, io.EOF},
		// Force error in transaction input sequence.
		{multiTx, multiTxEncoded, pver, BaseEncoding, 49, io.ErrShortWrite, io.EOF},
		// Force error in number of transaction outputs.
		{multiTx, multiTxEncoded, pver, BaseEncoding, 53, io.ErrShortWrite, io.EOF},
		// Force error in transaction output value.
		{multiTx, multiTxEncoded, pver, BaseEncoding, 54, io.ErrShortWrite, io.EOF},
		// Force error in transaction output pk script length.
		{multiTx, multiTxEncoded, pver, BaseEncoding, 62, io.ErrShortWrite, io.EOF},
		// Force error in transaction output pk script.
		{multiTx, multiTxEncoded, pver, BaseEncoding, 63, io.ErrShortWrite, io.EOF},
		// Force error in transaction output lock time.
		{multiTx, multiTxEncoded, pver, BaseEncoding, 206, io.ErrShortWrite, io.EOF},
	}

	t.Logf(runningTestsFmt, len(tests))

	for i, test := range tests {
		// Encode to wire format.
		w := newFixedWriter(test.max)

		err := test.in.BsvEncode(w, test.pver, test.enc)
		if !errors.Is(err, test.writeErr) {
			t.Errorf("BsvEncode #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// Decode from wire format.
		var msg MsgTx

		r := newFixedReader(test.max, test.buf)

		err = msg.Bsvdecode(r, test.pver, test.enc)
		if !errors.Is(err, test.readErr) {
			t.Errorf("Bsvdecode #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}
	}
}

// TestTxSerialize tests MsgTx serialize and deserialize.
func TestTxSerialize(t *testing.T) {
	noTx := NewMsgTx(1)
	noTx.Version = 1
	noTxEncoded := []byte{
		0x01, 0x00, 0x00, 0x00, // Version
		0x00,                   // Varint for number of input transactions
		0x00,                   // Varint for number of output transactions
		0x00, 0x00, 0x00, 0x00, // Lock time
	}

	tests := []struct {
		in           *MsgTx // Message to encode
		out          *MsgTx // Expected decoded message
		buf          []byte // Serialized data
		pkScriptLocs []int  // Expected output script locations
	}{
		// No transactions.
		{
			noTx,
			noTx,
			noTxEncoded,
			nil,
		},

		// Multiple transactions.
		{
			multiTx,
			multiTx,
			multiTxEncoded,
			multiTxPkScriptLocs,
		},
	}

	t.Logf(runningTestsFmt, len(tests))

	for i, test := range tests {
		// Serialize the transaction.
		var buf bytes.Buffer

		err := test.in.Serialize(&buf)
		if err != nil {
			t.Errorf("Serialize #%d error %v", i, err)
			continue
		}

		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("Serialize #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Deserialize the transaction.
		var tx MsgTx

		rbuf := bytes.NewReader(test.buf)

		err = tx.Deserialize(rbuf)
		if err != nil {
			t.Errorf("Deserialize #%d error %v", i, err)
			continue
		}

		if !reflect.DeepEqual(&tx, test.out) {
			t.Errorf("Deserialize #%d\n got: %s want: %s", i,
				spew.Sdump(&tx), spew.Sdump(test.out))
			continue
		}

		// Ensure the public key script locations are accurate.
		pkScriptLocs := test.in.PkScriptLocs()
		if !reflect.DeepEqual(pkScriptLocs, test.pkScriptLocs) {
			t.Errorf("PkScriptLocs #%d\n got: %s want: %s", i,
				spew.Sdump(pkScriptLocs),
				spew.Sdump(test.pkScriptLocs))

			continue
		}

		for j, loc := range pkScriptLocs {
			wantPkScript := test.in.TxOut[j].PkScript
			gotPkScript := test.buf[loc : loc+len(wantPkScript)]

			if !bytes.Equal(gotPkScript, wantPkScript) {
				t.Errorf("PkScriptLocs #%d:%d\n unexpected "+
					"script got: %s want: %s", i, j,
					spew.Sdump(gotPkScript),
					spew.Sdump(wantPkScript))
			}
		}
	}
}

// TestTxSerializeErrors performs negative tests against wire encode and decode
// of MsgTx to confirm error paths work correctly.
func TestTxSerializeErrors(t *testing.T) {
	tests := []struct {
		in       *MsgTx // Value to encode
		buf      []byte // Serialized data
		max      int    // Max size of fixed buffer to induce errors
		writeErr error  // Expected write error
		readErr  error  // Expected read error
	}{
		// Force error in version.
		{multiTx, multiTxEncoded, 0, io.ErrShortWrite, io.EOF},
		// Force error in the number of transaction inputs.
		{multiTx, multiTxEncoded, 4, io.ErrShortWrite, io.EOF},
		// Force error in transaction input previous block hash.
		{multiTx, multiTxEncoded, 5, io.ErrShortWrite, io.EOF},
		// Force error in transaction input previous block output index.
		{multiTx, multiTxEncoded, 37, io.ErrShortWrite, io.EOF},
		// Force error in transaction input signature script length.
		{multiTx, multiTxEncoded, 41, io.ErrShortWrite, io.EOF},
		// Force error in transaction input signature script.
		{multiTx, multiTxEncoded, 42, io.ErrShortWrite, io.EOF},
		// Force error in a transaction input sequence.
		{multiTx, multiTxEncoded, 49, io.ErrShortWrite, io.EOF},
		// Force error in the number of transaction outputs.
		{multiTx, multiTxEncoded, 53, io.ErrShortWrite, io.EOF},
		// Force error in transaction output value.
		{multiTx, multiTxEncoded, 54, io.ErrShortWrite, io.EOF},
		// Force error in transaction output pk script length.
		{multiTx, multiTxEncoded, 62, io.ErrShortWrite, io.EOF},
		// Force error in transaction output pk script.
		{multiTx, multiTxEncoded, 63, io.ErrShortWrite, io.EOF},
		// Force error in transaction output lock time.
		{multiTx, multiTxEncoded, 206, io.ErrShortWrite, io.EOF},
	}

	t.Logf(runningTestsFmt, len(tests))

	for i, test := range tests {
		// Serialize the transaction.
		w := newFixedWriter(test.max)

		err := test.in.Serialize(w)
		if !errors.Is(err, test.writeErr) {
			t.Errorf("Serialize #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// Deserialize the transaction.
		var tx MsgTx

		r := newFixedReader(test.max, test.buf)

		err = tx.Deserialize(r)
		if !errors.Is(err, test.readErr) {
			t.Errorf("Deserialize #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}
	}
}

// TestTxOverflowErrors performs tests to ensure deserializing transactions
// which are intentionally crafted to use large values for the variable number
// of inputs and outputs are handled properly.  This could otherwise potentially
// be used as an attack vector.
func TestTxOverflowErrors(t *testing.T) {
	// Use protocol version 70001 and transaction version 1 specifically
	// here instead of the latest values because the test data is using
	// bytes encoded with those versions.
	pver := uint32(70001)
	txVer := uint32(1)

	tests := []struct {
		buf     []byte          // Wire encoding
		pver    uint32          // Protocol version for wire encoding
		enc     MessageEncoding // Message encoding format
		version uint32          // Transaction version
		err     error           // Expected error
	}{
		// Transaction that claims to have ~uint64(0) inputs.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x01, // Version
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, // Varint for number of input transactions
			}, pver, BaseEncoding, txVer, &MessageError{},
		},

		// Transaction that claims to have ~uint64(0) outputs.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x01, // Version
				0x00, // Varint for number of input transactions
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, // Varint for number of output transactions
			}, pver, BaseEncoding, txVer, &MessageError{},
		},

		// Transaction that has an input with a signature script that
		// claims to have ~uint64(0) length.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x01, // Version
				0x01, // Varint for number of input transactions
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Previous output hash
				0xff, 0xff, 0xff, 0xff, // Previous output index
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, // Varint for length of signature script
			}, pver, BaseEncoding, txVer, &MessageError{},
		},

		// Transaction that has an output with a public key script
		// that claims to have ~uint64(0) length.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x01, // Version
				0x01, // Varint for number of input transactions
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Previous output hash
				0xff, 0xff, 0xff, 0xff, // Previous output index
				0x00,                   // Varint for length of signature script
				0xff, 0xff, 0xff, 0xff, // Sequence
				0x01,                                           // Varint for number of output transactions
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Transaction amount
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, // Varint for length of a public key script
			}, pver, BaseEncoding, txVer, &MessageError{},
		},
	}

	t.Logf(runningTestsFmt, len(tests))

	for i, test := range tests {
		// Decode from wire format.
		var msg MsgTx

		r := bytes.NewReader(test.buf)

		err := msg.Bsvdecode(r, test.pver, test.enc)
		if reflect.TypeOf(err) != reflect.TypeOf(test.err) {
			t.Errorf("Bsvdecode #%d wrong error got: %v, want: %v",
				i, err, reflect.TypeOf(test.err))
			continue
		}

		// Decode from wire format.
		r = bytes.NewReader(test.buf)

		err = msg.Deserialize(r)
		if reflect.TypeOf(err) != reflect.TypeOf(test.err) {
			t.Errorf("Deserialize #%d wrong error got: %v, want: %v",
				i, err, reflect.TypeOf(test.err))
			continue
		}
	}
}

// TestTxSerializeSizeStripped performs tests to ensure the serialize size for
// various transactions is accurate.
func TestTxSerializeSizeStripped(t *testing.T) {
	// Empty tx message.
	noTx := NewMsgTx(1)
	noTx.Version = 1

	tests := []struct {
		in   *MsgTx // Tx to encode
		size int    // Expected serialized size
	}{
		// No inputs or outputs.
		{noTx, 10},

		// Transaction with an input and an output.
		{multiTx, 210},
	}

	t.Logf(runningTestsFmt, len(tests))

	for i, test := range tests {
		serializedSize := test.in.SerializeSize()
		if serializedSize != test.size {
			t.Errorf("MsgTx.SerializeSizeStripped: #%d got: %d, want: %d", i,
				serializedSize, test.size)
			continue
		}
	}
}

// multiTx is a MsgTx with an input and output and used in various tests.
var multiTx = &MsgTx{
	Version: 1,
	TxIn: []*TxIn{
		{
			PreviousOutPoint: OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0xffffffff,
			},
			SignatureScript: []byte{
				0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62,
			},
			Sequence: 0xffffffff,
		},
	},
	TxOut: []*TxOut{
		{
			Value: 0x12a05f200,
			PkScript: []byte{
				0x41, // OP_DATA_65
				0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
				0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
				0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
				0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
				0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
				0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
				0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
				0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
				0xa6, // 65-byte signature
				0xac, // OP_CHECKSIG
			},
		},
		{
			Value: 0x5f5e100,
			PkScript: []byte{
				0x41, // OP_DATA_65
				0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
				0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
				0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
				0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
				0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
				0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
				0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
				0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
				0xa6, // 65-byte signature
				0xac, // OP_CHECKSIG
			},
		},
	},
	LockTime: 0,
}

// multiTxEncoded is the wire encoded bytes for multiTx using protocol version
// 60002 and is used in the various tests.
var multiTxEncoded = []byte{
	0x01, 0x00, 0x00, 0x00, // Version
	0x01, // Varint for number of input transactions
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Previous output hash
	0xff, 0xff, 0xff, 0xff, // Previous output index
	0x07,                                     // Varint for length of signature script
	0x04, 0x31, 0xdc, 0x00, 0x1b, 0x01, 0x62, // Signature script
	0xff, 0xff, 0xff, 0xff, // Sequence
	0x02,                                           // Varint for number of output transactions
	0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, // Transaction amount
	0x43, // Varint for length of pk script
	0x41, // OP_DATA_65
	0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
	0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
	0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
	0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
	0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
	0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
	0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
	0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
	0xa6,                                           // 65-byte signature
	0xac,                                           // OP_CHECKSIG
	0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00, // Transaction amount
	0x43, // Varint for length of pk script
	0x41, // OP_DATA_65
	0x04, 0xd6, 0x4b, 0xdf, 0xd0, 0x9e, 0xb1, 0xc5,
	0xfe, 0x29, 0x5a, 0xbd, 0xeb, 0x1d, 0xca, 0x42,
	0x81, 0xbe, 0x98, 0x8e, 0x2d, 0xa0, 0xb6, 0xc1,
	0xc6, 0xa5, 0x9d, 0xc2, 0x26, 0xc2, 0x86, 0x24,
	0xe1, 0x81, 0x75, 0xe8, 0x51, 0xc9, 0x6b, 0x97,
	0x3d, 0x81, 0xb0, 0x1c, 0xc3, 0x1f, 0x04, 0x78,
	0x34, 0xbc, 0x06, 0xd6, 0xd6, 0xed, 0xf6, 0x20,
	0xd1, 0x84, 0x24, 0x1a, 0x6a, 0xed, 0x8b, 0x63,
	0xa6,                   // 65-byte signature
	0xac,                   // OP_CHECKSIG
	0x00, 0x00, 0x00, 0x00, // Lock time
}

// multiTxPkScriptLocs is the location information for the public key scripts
// located in multiTx.
var multiTxPkScriptLocs = []int{63, 139}
