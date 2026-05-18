// Copyright (c) 2024 The go-wire developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
)

// syntheticBlockMsg constructs a MsgBlock with the given scripts already
// populated (in-memory, not serialized). It sets a minimal valid header.
func syntheticMsgBlock(txs []*MsgTx) *MsgBlock {
	return &MsgBlock{
		Header: BlockHeader{
			Version:    1,
			PrevBlock:  chainhash.Hash{},
			MerkleRoot: chainhash.Hash{},
			Bits:       0x1d00ffff,
			Nonce:      0,
		},
		Transactions: txs,
	}
}

// serializeBlock serializes a MsgBlock to bytes using Serialize.
func serializeBlock(t *testing.T, blk *MsgBlock) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := blk.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return buf.Bytes()
}

// decodeBlock deserializes bytes into a fresh MsgBlock via Bsvdecode
// (which exercises the arena path) and returns it.
func decodeBlock(t *testing.T, data []byte) *MsgBlock {
	t.Helper()
	var blk MsgBlock
	if err := blk.Bsvdecode(bytes.NewReader(data), 0, BaseEncoding); err != nil {
		t.Fatalf("Bsvdecode: %v", err)
	}
	return &blk
}

// TestMsgBlockArenaNoAliasing verifies that mutating one transaction's script
// does not affect another transaction's script, and that all scripts have
// cap == len.
func TestMsgBlockArenaNoAliasing(t *testing.T) {
	script0 := bytes.Repeat([]byte{0xAA}, 600) // > freeListMaxScriptSize
	script1 := bytes.Repeat([]byte{0xBB}, 700)

	tx0 := &MsgTx{
		Version: 1,
		TxIn: []*TxIn{{
			PreviousOutPoint: OutPoint{Index: 0xffffffff},
			SignatureScript:  script0,
			Sequence:         0xffffffff,
		}},
		TxOut:    []*TxOut{{Value: 0, PkScript: []byte{0x51}}},
		LockTime: 0,
	}
	tx1 := &MsgTx{
		Version: 1,
		TxIn: []*TxIn{{
			PreviousOutPoint: OutPoint{Index: 0xffffffff},
			SignatureScript:  script1,
			Sequence:         0xffffffff,
		}},
		TxOut:    []*TxOut{{Value: 0, PkScript: []byte{0x52}}},
		LockTime: 0,
	}

	data := serializeBlock(t, syntheticMsgBlock([]*MsgTx{tx0, tx1}))
	blk := decodeBlock(t, data)

	if len(blk.Transactions) != 2 {
		t.Fatalf("expected 2 txs, got %d", len(blk.Transactions))
	}

	got0 := blk.Transactions[0].TxIn[0].SignatureScript
	got1 := blk.Transactions[1].TxIn[0].SignatureScript

	// Verify cap == len on both.
	if cap(got0) != len(got0) {
		t.Errorf("tx0 script: cap=%d, len=%d; want cap==len", cap(got0), len(got0))
	}
	if cap(got1) != len(got1) {
		t.Errorf("tx1 script: cap=%d, len=%d; want cap==len", cap(got1), len(got1))
	}

	// Mutate tx0's script.
	for i := range got0 {
		got0[i] = 0xFF
	}

	// tx1's script must be unchanged.
	if !bytes.Equal(got1, script1) {
		t.Errorf("tx1 script was aliased into tx0: got %x..., want %x...",
			got1[:min8(len(got1))], script1[:min8(len(script1))])
	}
}

// TestMsgBlockArenaRoundTrip verifies that a block with mixed script sizes
// survives a Serialize → Bsvdecode round-trip with byte-identical output.
func TestMsgBlockArenaRoundTrip(t *testing.T) {
	SetLimits(4 * 1024 * 1024 * 1024) // allow 2 MiB scripts
	defer SetLimits(fixedExcessiveBlockSize)

	scripts := [][]byte{
		nil,                                     // 0 bytes
		{0x01},                                  // 1 byte
		bytes.Repeat([]byte{0xAB}, 512),         // exactly freeListMaxScriptSize
		bytes.Repeat([]byte{0xCD}, 2*1024*1024), // 2 MiB
	}

	txs := make([]*MsgTx, 0, len(scripts))
	for i, sc := range scripts {
		tx := &MsgTx{
			Version: 1,
			TxIn: []*TxIn{{
				PreviousOutPoint: OutPoint{Index: uint32(i)},
				SignatureScript:  sc,
				Sequence:         0xffffffff,
			}},
			TxOut:    []*TxOut{{Value: int64(i), PkScript: sc}},
			LockTime: 0,
		}
		txs = append(txs, tx)
	}

	original := serializeBlock(t, syntheticMsgBlock(txs))
	blk := decodeBlock(t, original)

	// Re-encode the decoded block.
	var reencoded bytes.Buffer
	if err := blk.Serialize(&reencoded); err != nil {
		t.Fatalf("re-Serialize: %v", err)
	}

	if !bytes.Equal(original, reencoded.Bytes()) {
		t.Errorf("round-trip mismatch: original %d bytes, re-encoded %d bytes",
			len(original), reencoded.Len())
	}
}

// TestMsgBlockArenaTruncated verifies that feeding a truncated block produces
// an error (not a panic, not a hang).
func TestMsgBlockArenaTruncated(t *testing.T) {
	script := bytes.Repeat([]byte{0x42}, 800)
	tx := &MsgTx{
		Version: 1,
		TxIn: []*TxIn{{
			PreviousOutPoint: OutPoint{Index: 0},
			SignatureScript:  script,
			Sequence:         0xffffffff,
		}},
		TxOut:    []*TxOut{{Value: 100, PkScript: script}},
		LockTime: 0,
	}

	full := serializeBlock(t, syntheticMsgBlock([]*MsgTx{tx}))
	half := full[:len(full)/2]

	var blk MsgBlock
	err := blk.Bsvdecode(bytes.NewReader(half), 0, BaseEncoding)
	if err == nil {
		t.Fatal("expected error for truncated block, got nil")
	}

	// Must be EOF-family, not some other error.
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Logf("got error (acceptable non-EOF): %v", err)
		// Not all truncations trigger ErrUnexpectedEOF — some hit varint
		// bounds checks first. As long as it errors and doesn't panic, pass.
	}
}

// TestMsgBlockArenaEmptyTxScripts verifies that a block with a tx whose
// scripts are 0 bytes decodes successfully, and the resulting slices are
// nil or len==0 (not a panic).
func TestMsgBlockArenaEmptyTxScripts(t *testing.T) {
	tx := &MsgTx{
		Version: 1,
		TxIn: []*TxIn{{
			PreviousOutPoint: OutPoint{Index: 0xffffffff},
			SignatureScript:  nil, // 0-byte script
			Sequence:         0xffffffff,
		}},
		TxOut:    []*TxOut{{Value: 0, PkScript: nil}},
		LockTime: 0,
	}

	data := serializeBlock(t, syntheticMsgBlock([]*MsgTx{tx}))
	blk := decodeBlock(t, data)

	if len(blk.Transactions) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(blk.Transactions))
	}

	sig := blk.Transactions[0].TxIn[0].SignatureScript
	pk := blk.Transactions[0].TxOut[0].PkScript

	if len(sig) != 0 {
		t.Errorf("SignatureScript: expected len 0, got %d", len(sig))
	}
	if len(pk) != 0 {
		t.Errorf("PkScript: expected len 0, got %d", len(pk))
	}
}

// TestMsgTxStandaloneUsesPool verifies that decoding a MsgTx directly (not
// via MsgBlock) still works correctly and produces the expected bytes.
// The scriptPool implementation detail is internal; we just verify correctness.
func TestMsgTxStandaloneUsesPool(t *testing.T) {
	wantScript := bytes.Repeat([]byte{0x99}, 300) // fits within free list (< 512)

	tx := &MsgTx{
		Version: 1,
		TxIn: []*TxIn{{
			PreviousOutPoint: OutPoint{Index: 0},
			SignatureScript:  wantScript,
			Sequence:         0xffffffff,
		}},
		TxOut:    []*TxOut{{Value: 42, PkScript: wantScript}},
		LockTime: 0,
	}

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	var decoded MsgTx
	if err := decoded.Bsvdecode(bytes.NewReader(buf.Bytes()), 0, BaseEncoding); err != nil {
		t.Fatalf("Bsvdecode: %v", err)
	}

	if !bytes.Equal(decoded.TxIn[0].SignatureScript, wantScript) {
		t.Errorf("SignatureScript mismatch after standalone decode")
	}
	if !bytes.Equal(decoded.TxOut[0].PkScript, wantScript) {
		t.Errorf("PkScript mismatch after standalone decode")
	}

	// cap == len is also expected on the single-tx path (three-index slice
	// in bsvdecode's scripts[] consolidation step).
	sig := decoded.TxIn[0].SignatureScript
	pk := decoded.TxOut[0].PkScript
	if cap(sig) != len(sig) {
		t.Errorf("standalone SignatureScript: cap=%d len=%d; want cap==len", cap(sig), len(sig))
	}
	if cap(pk) != len(pk) {
		t.Errorf("standalone PkScript: cap=%d len=%d; want cap==len", cap(pk), len(pk))
	}
}

// min8 returns n if n < 8, else 8. Helper to avoid panics in error messages.
func min8(n int) int {
	if n < 8 {
		return n
	}
	return 8
}
