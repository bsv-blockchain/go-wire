// Copyright (c) 2024 The bsv-blockchain developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
)

// synthBlock builds a MsgBlock with approximately targetBytes of payload
// by adding simple transactions with a script of the given size until the
// serialised size reaches targetBytes. It is used to generate realistic
// large-block bench inputs without reading from disk.
func synthBlock(targetBytes int) *MsgBlock {
	prevHash := chainhash.Hash{}

	hdr := NewBlockHeader(
		1,
		&prevHash,
		&prevHash,
		0x1d00ffff,
		0,
	)
	hdr.Timestamp = time.Unix(1_700_000_000, 0)

	block := NewMsgBlock(hdr)

	// Build a template transaction with a 500-byte output script so each tx
	// contributes roughly 600 bytes to the encoded block.
	script := make([]byte, 500)
	for i := range script {
		script[i] = 0x51 // OP_1 (valid no-op script)
	}

	txTemplate := &MsgTx{
		Version: 1,
		TxIn: []*TxIn{
			{
				PreviousOutPoint: OutPoint{Hash: chainhash.Hash{}, Index: 0},
				SignatureScript:  make([]byte, 100),
				Sequence:         0xffffffff,
			},
		},
		TxOut: []*TxOut{
			{Value: 5000000000, PkScript: script},
		},
		LockTime: 0,
	}

	// Serialised size per transaction (header overhead accounted for lazily).
	txSize := txTemplate.SerializeSize()

	for block.SerializeSize() < targetBytes {
		// Copy the template so each tx is independent.
		txCopy := txTemplate.Copy()
		_ = block.AddTransaction(txCopy)
		// Safety valve: if txSize is 0 (shouldn't happen) break.
		if txSize == 0 {
			break
		}
	}

	return block
}

const benchBlockTargetBytes = 10 * 1024 * 1024 // ~10 MiB

// encodedBenchBlock is the wire-format bytes for the bench block, computed
// once at package init time so the encoding cost is not counted in benchmarks.
var encodedBenchBlock []byte

func init() { //nolint:gochecknoinits // benchmark data setup
	block := synthBlock(benchBlockTargetBytes)

	var buf bytes.Buffer

	_, err := WriteMessageN(&buf, block, ProtocolVersion, MainNet)
	if err != nil {
		panic("synthBlock encode failed: " + err.Error())
	}

	encodedBenchBlock = buf.Bytes()
}

// BenchmarkReadMessageN_Block measures the baseline allocation-heavy path:
// ReadMessageWithEncodingN allocates a []byte of length==payload before decoding.
func BenchmarkReadMessageN_Block(b *testing.B) {
	b.SetBytes(int64(len(encodedBenchBlock)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encodedBenchBlock)

		_, _, _, err := ReadMessageN(r, ProtocolVersion, MainNet)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReadMessageStreamingN_Block measures the streaming path.
// No payload buffer is allocated; the payload is fed directly into Bsvdecode.
func BenchmarkReadMessageStreamingN_Block(b *testing.B) {
	b.SetBytes(int64(len(encodedBenchBlock)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(encodedBenchBlock)

		_, _, err := ReadMessageStreamingN(r, ProtocolVersion, MainNet, BaseEncoding)
		if err != nil {
			b.Fatal(err)
		}
	}
}
