// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

// TestMerkleBlock tests the MsgMerkleBlock API.
func TestMerkleBlock(t *testing.T) {
	pver := ProtocolVersion
	enc := BaseEncoding

	// Block 1 header.
	prevHash := &blockOne.Header.PrevBlock
	merkleHash := &blockOne.Header.MerkleRoot
	bits := blockOne.Header.Bits
	nonce := blockOne.Header.Nonce
	bh := NewBlockHeader(1, prevHash, merkleHash, bits, nonce)

	// Ensure the command is expected value.
	wantCmd := "merkleblock"
	msg := NewMsgMerkleBlock(bh)

	if cmd := msg.Command(); cmd != wantCmd {
		t.Errorf("NewMsgBlock: wrong command - got %v want %v",
			cmd, wantCmd)
	}

	// Ensure max payload is expected value for the latest protocol version.
	// Num addresses (varInt) + max allowed addresses.
	wantPayload := fixedExcessiveBlockSize
	maxPayload := msg.MaxPayloadLength(pver)

	if maxPayload != wantPayload {
		t.Errorf("MaxPayloadLength: wrong max payload length for "+
			"protocol version %d - got %v, want %v", pver,
			maxPayload, wantPayload)
	}

	// Load maxTxPerBlock hashes
	data := make([]byte, 32)
	for i := uint64(0); i < maxTxPerBlock(); i++ {
		_, err := rand.Read(data)
		require.NoError(t, err)

		var hash *chainhash.Hash
		hash, err = chainhash.NewHash(data)
		if err != nil {
			t.Errorf("NewHash failed: %v\n", err)
			return
		}

		if err = msg.AddTxHash(hash); err != nil {
			t.Errorf("AddTxHash failed: %v\n", err)
			return
		}
	}

	// Add one more Tx to test failure.
	_, err := rand.Read(data)
	require.NoError(t, err)

	var hash *chainhash.Hash
	hash, err = chainhash.NewHash(data)
	if err != nil {
		t.Errorf("NewHash failed: %v\n", err)
		return
	}

	if err = msg.AddTxHash(hash); err == nil {
		t.Errorf("AddTxHash succeeded when it should have failed")
		return
	}

	// Test encode with latest protocol version.
	var buf bytes.Buffer

	err = msg.BsvEncode(&buf, pver, enc)
	if err != nil {
		t.Errorf("encode of MsgMerkleBlock failed %v err <%v>", msg, err)
	}

	// Test decode with latest protocol version.
	readmsg := MsgMerkleBlock{}

	err = readmsg.Bsvdecode(&buf, pver, enc)
	if err != nil {
		t.Errorf("decode of MsgMerkleBlock failed [%v] err <%v>", buf, err)
	}

	// Force extra hash to test maxTxPerBlock.
	msg.Hashes = append(msg.Hashes, hash)

	err = msg.BsvEncode(&buf, pver, enc)
	if err == nil {
		t.Errorf("encode of MsgMerkleBlock succeeded with too many " +
			"tx hashes when it should have failed")
		return
	}

	// Force too many flag bytes to test maxFlagsPerMerkleBlock.
	// Reset the number of hashes back to a valid value.
	msg.Hashes = msg.Hashes[len(msg.Hashes)-1:]
	msg.Flags = make([]byte, int(maxFlagsPerMerkleBlock())+1) //nolint:gosec // G115 Conversion

	err = msg.BsvEncode(&buf, pver, enc)
	if err == nil {
		t.Errorf("encode of MsgMerkleBlock succeeded with too many " +
			"flag bytes when it should have failed")
		return
	}
}

// TestMerkleBlockCrossProtocol tests the MsgMerkleBlock API when encoding with
// the latest protocol version and decoding with BIP0031Version.
func TestMerkleBlockCrossProtocol(t *testing.T) {
	// Block 1 header.
	prevHash := &blockOne.Header.PrevBlock
	merkleHash := &blockOne.Header.MerkleRoot
	bits := blockOne.Header.Bits
	nonce := blockOne.Header.Nonce
	bh := NewBlockHeader(1, prevHash, merkleHash, bits, nonce)

	msg := NewMsgMerkleBlock(bh)

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

// TestMerkleBlockWire tests the MsgMerkleBlock wire encode and decode for
// various numbers of transaction hashes and protocol versions.
func TestMerkleBlockWire(t *testing.T) {
	tests := []struct {
		in   *MsgMerkleBlock // Message to encode
		out  *MsgMerkleBlock // Expected decoded message
		buf  []byte          // Wire encoding
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encoding format
	}{
		// Latest protocol version.
		{
			&merkleBlockOne, &merkleBlockOne, merkleBlockOneBytes,
			ProtocolVersion, BaseEncoding,
		},

		// Protocol version BIP0037Version.
		{
			&merkleBlockOne, &merkleBlockOne, merkleBlockOneBytes,
			BIP0037Version, BaseEncoding,
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
		var msg MsgMerkleBlock

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

// TestMerkleBlockWireErrors performs negative tests against wire encode and
// decode of MsgBlock to confirm error paths work correctly.
func TestMerkleBlockWireErrors(t *testing.T) {
	// Use protocol version 70001 specifically here instead of the latest
	// because the test data is using bytes encoded with that protocol
	// version.
	pver := uint32(70001)
	pverNoMerkleBlock := BIP0037Version - 1
	wireErr := &MessageError{}

	tests := []struct {
		in       *MsgMerkleBlock // Value to encode
		buf      []byte          // Wire encoding
		pver     uint32          // Protocol version for wire encoding
		enc      MessageEncoding // Message encoding format
		max      int             // Max size of fixed buffer to induce errors
		writeErr error           // Expected write error
		readErr  error           // Expected read error
	}{
		// Force error in version.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 0,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in prev block hash.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 4,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in merkle root.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 36,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in timestamp.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 68,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in difficulty bits.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 72,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in header nonce.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 76,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in transaction count.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 80,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in num hashes.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 84,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in hashes.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 85,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in num flag bytes.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 117,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in flag bytes.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 118,
			io.ErrShortWrite, io.EOF,
		},
		// Force error due to unsupported protocol version.
		{
			&merkleBlockOne, merkleBlockOneBytes, pverNoMerkleBlock,
			BaseEncoding, 119, wireErr, wireErr,
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
		var msg MsgMerkleBlock

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

// TestMerkleBlockOverflowErrors performs tests to ensure encoding and decoding
// merkle blocks that are intentionally crafted to use large values for the
// number of hashes and flags are handled properly.  This could otherwise
// potentially be used as an attack vector.
func TestMerkleBlockOverflowErrors(t *testing.T) {
	// Use protocol version 70001 specifically here instead of the latest
	// protocol version because the test data is using bytes encoded with
	// that version.
	pver := uint32(70001)

	// Create bytes for a merkle block that claims to have more than the max
	// allowed tx hashes.
	var buf bytes.Buffer

	err := WriteVarInt(&buf, pver, maxTxPerBlock()+1)
	require.NoError(t, err)

	numHashesOffset := 84
	exceedMaxHashes := append([]byte{}, merkleBlockOneBytes[:numHashesOffset]...)
	exceedMaxHashes = append(exceedMaxHashes, buf.Bytes()...)

	// Create bytes for a merkle block that claims to have more than the max
	// allowed flag bytes.
	buf.Reset()
	err = WriteVarInt(&buf, pver, maxFlagsPerMerkleBlock()+1)
	require.NoError(t, err)

	numFlagBytesOffset := 117
	exceedMaxFlagBytes := append([]byte{}, merkleBlockOneBytes[:numFlagBytesOffset]...)
	exceedMaxFlagBytes = append(exceedMaxFlagBytes, buf.Bytes()...)

	tests := []struct {
		buf  []byte          // Wire encoding
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encoding format
		err  error           // Expected error
	}{
		// Block that claims to have more than max allowed hashes.
		{exceedMaxHashes, pver, BaseEncoding, &MessageError{}},
		// Block that claims to have more than max allowed flag bytes.
		{exceedMaxFlagBytes, pver, BaseEncoding, &MessageError{}},
	}

	t.Logf(runningTestsFmt, len(tests))

	for i, test := range tests {
		// Decode from wire format.
		var msg MsgMerkleBlock

		r := bytes.NewReader(test.buf)

		err := msg.Bsvdecode(r, test.pver, test.enc)
		if reflect.TypeOf(err) != reflect.TypeOf(test.err) {
			t.Errorf("Bsvdecode #%d wrong error got: %v, want: %v",
				i, err, reflect.TypeOf(test.err))
			continue
		}
	}
}

// merkleBlockOne is a merkle block created from block one of the blockchains
// where the first transaction matches.
var merkleBlockOne = MsgMerkleBlock{
	Header: BlockHeader{
		Version: 1,
		PrevBlock: chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
			0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
			0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
			0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
			0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
		}),
		MerkleRoot: chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
			0x98, 0x20, 0x51, 0xfd, 0x1e, 0x4b, 0xa7, 0x44,
			0xbb, 0xbe, 0x68, 0x0e, 0x1f, 0xee, 0x14, 0x67,
			0x7b, 0xa1, 0xa3, 0xc3, 0x54, 0x0b, 0xf7, 0xb1,
			0xcd, 0xb6, 0x06, 0xe8, 0x57, 0x23, 0x3e, 0x0e,
		}),
		Timestamp: time.Unix(0x4966bc61, 0), // 2009-01-08 20:54:25 -0600 CST
		Bits:      0x1d00ffff,               // 486604799
		Nonce:     0x9962e301,               // 2573394689
	},
	Transactions: 1,
	Hashes: []*chainhash.Hash{
		(*chainhash.Hash)(&[chainhash.HashSize]byte{ // Make go vet happy.
			0x98, 0x20, 0x51, 0xfd, 0x1e, 0x4b, 0xa7, 0x44,
			0xbb, 0xbe, 0x68, 0x0e, 0x1f, 0xee, 0x14, 0x67,
			0x7b, 0xa1, 0xa3, 0xc3, 0x54, 0x0b, 0xf7, 0xb1,
			0xcd, 0xb6, 0x06, 0xe8, 0x57, 0x23, 0x3e, 0x0e,
		}),
	},
	Flags: []byte{0x80},
}

// merkleBlockOneBytes is the serialized bytes for a merkle block created from
// block one of the blockchains where the first transaction matches.
var merkleBlockOneBytes = []byte{
	0x01, 0x00, 0x00, 0x00, // Version 1
	0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
	0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
	0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
	0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, // PrevBlock
	0x98, 0x20, 0x51, 0xfd, 0x1e, 0x4b, 0xa7, 0x44,
	0xbb, 0xbe, 0x68, 0x0e, 0x1f, 0xee, 0x14, 0x67,
	0x7b, 0xa1, 0xa3, 0xc3, 0x54, 0x0b, 0xf7, 0xb1,
	0xcd, 0xb6, 0x06, 0xe8, 0x57, 0x23, 0x3e, 0x0e, // MerkleRoot
	0x61, 0xbc, 0x66, 0x49, // Timestamp
	0xff, 0xff, 0x00, 0x1d, // Bits
	0x01, 0xe3, 0x62, 0x99, // Nonce
	0x01, 0x00, 0x00, 0x00, // TxnCount
	0x01, // Num hashes
	0x98, 0x20, 0x51, 0xfd, 0x1e, 0x4b, 0xa7, 0x44,
	0xbb, 0xbe, 0x68, 0x0e, 0x1f, 0xee, 0x14, 0x67,
	0x7b, 0xa1, 0xa3, 0xc3, 0x54, 0x0b, 0xf7, 0xb1,
	0xcd, 0xb6, 0x06, 0xe8, 0x57, 0x23, 0x3e, 0x0e, // Hash
	0x01, // Num flag bytes
	0x80, // Flags
}
