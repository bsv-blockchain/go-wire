// Copyright (c) 2024 The go-wire developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildSyntheticBlock constructs a serialized MsgBlock with the given number
// of transactions, each carrying one input with a signatureScript of
// inputScriptLen bytes and one output with a pkScript of outputScriptLen bytes.
func buildSyntheticBlock(txCount int, inputScriptLen, outputScriptLen int) []byte {
	var buf bytes.Buffer

	// Block header: 80 bytes (version + prevblock + merkleroot + time + bits + nonce)
	buf.Write(make([]byte, 80))

	// Tx count varint
	writeVarIntBuf(&buf, uint64(txCount))

	inScript := makePaddedScript(inputScriptLen)
	outScript := makePaddedScript(outputScriptLen)

	for i := 0; i < txCount; i++ {
		// Version (int32 LE)
		var versionBytes [4]byte
		binary.LittleEndian.PutUint32(versionBytes[:], 1)
		buf.Write(versionBytes[:])

		// Input count: 1
		writeVarIntBuf(&buf, 1)

		// Outpoint: 32-byte hash + 4-byte index
		buf.Write(make([]byte, 32))
		var idxBytes [4]byte
		binary.LittleEndian.PutUint32(idxBytes[:], 0xffffffff)
		buf.Write(idxBytes[:])

		// SignatureScript length + data
		writeVarIntBuf(&buf, uint64(inputScriptLen))
		buf.Write(inScript)

		// Sequence
		var seqBytes [4]byte
		binary.LittleEndian.PutUint32(seqBytes[:], 0xffffffff)
		buf.Write(seqBytes[:])

		// Output count: 1
		writeVarIntBuf(&buf, 1)

		// Value (int64 LE)
		buf.Write(make([]byte, 8))

		// PkScript length + data
		writeVarIntBuf(&buf, uint64(outputScriptLen))
		buf.Write(outScript)

		// LockTime (uint32 LE)
		buf.Write(make([]byte, 4))
	}

	return buf.Bytes()
}

// makePaddedScript returns a deterministic byte slice of length n.
func makePaddedScript(n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = byte(i & 0xff)
	}
	return s
}

// writeVarIntBuf writes a Bitcoin-style variable-length integer to buf.
func writeVarIntBuf(buf *bytes.Buffer, v uint64) {
	switch {
	case v < 0xfd:
		buf.WriteByte(byte(v))
	case v <= 0xffff:
		buf.WriteByte(0xfd)
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], uint16(v))
		buf.Write(b[:])
	case v <= 0xffffffff:
		buf.WriteByte(0xfe)
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(v))
		buf.Write(b[:])
	default:
		buf.WriteByte(0xff)
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], v)
		buf.Write(b[:])
	}
}

// BenchmarkDecodeBlock_100MB benchmarks decoding a ~100 MB block with
// ~1000 transactions, each with ~50 KiB scripts.
func BenchmarkDecodeBlock_100MB(b *testing.B) {
	const txCount = 1000
	const scriptLen = 50 * 1024 // 50 KiB per script

	data := buildSyntheticBlock(txCount, scriptLen, scriptLen)
	b.SetBytes(int64(len(data)))
	r := bytes.NewReader(data)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = r.Seek(0, 0)
		var msg MsgBlock
		if err := msg.Bsvdecode(r, 0, BaseEncoding); err != nil {
			b.Fatalf("Bsvdecode: %v", err)
		}
	}
}

// BenchmarkDecodeBlock_ManySmall benchmarks decoding a block with many small
// transactions whose scripts are below freeListMaxScriptSize (512 bytes).
func BenchmarkDecodeBlock_ManySmall(b *testing.B) {
	const txCount = 50000
	const scriptLen = 200 // below freeListMaxScriptSize=512

	data := buildSyntheticBlock(txCount, scriptLen, scriptLen)
	b.SetBytes(int64(len(data)))
	r := bytes.NewReader(data)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = r.Seek(0, 0)
		var msg MsgBlock
		if err := msg.Bsvdecode(r, 0, BaseEncoding); err != nil {
			b.Fatalf("Bsvdecode: %v", err)
		}
	}
}

// BenchmarkDecodeBlock_FewLarge benchmarks decoding a block with a handful of
// transactions with very large scripts (5 MiB each). SetLimits is called to
// raise the ebs cap so the 5 MiB scripts pass validation; it is restored after.
func BenchmarkDecodeBlock_FewLarge(b *testing.B) {
	const txCount = 10
	const scriptLen = 5 * 1024 * 1024 // 5 MiB

	// Raise the excessive block size so large scripts pass validation.
	// 10 txs * 2 * 5 MiB = 100 MiB of scripts; set ebs well above that.
	SetLimits(4 * 1024 * 1024 * 1024) // 4 GiB
	defer SetLimits(fixedExcessiveBlockSize) // restore test default

	data := buildSyntheticBlock(txCount, scriptLen, scriptLen)
	b.SetBytes(int64(len(data)))
	r := bytes.NewReader(data)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = r.Seek(0, 0)
		var msg MsgBlock
		if err := msg.Bsvdecode(r, 0, BaseEncoding); err != nil {
			b.Fatalf("Bsvdecode: %v", err)
		}
	}
}

// BenchmarkArenaAllocPattern microbenchmarks the blockArena vs plain make for
// mixed-size allocations. The arena sub-benchmarks are added after the arena
// is implemented; both arena and make variants are defined here so the file
// covers the full before/after comparison.
func BenchmarkArenaAllocPattern(b *testing.B) {
	// sizes cycles through a realistic mix of script sizes.
	sizes := []int{
		25, 512, 1024, 25, 200, 50 * 1024, 25, 512, 5 * 1024 * 1024, 100,
	}

	for _, count := range []int{1000, 10000, 100000} {
		count := count
		b.Run("arena/"+benchItoa(count), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				a := newBlockArena()
				for j := 0; j < count; j++ {
					n := sizes[j%len(sizes)]
					s := a.Alloc(n)
					if n > 0 && s == nil {
						b.Fatal("unexpected nil from arena")
					}
				}
			}
		})

		b.Run("make/"+benchItoa(count), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := 0; j < count; j++ {
					n := sizes[j%len(sizes)]
					var s []byte
					if n > 0 {
						s = make([]byte, n)
					}
					_ = s
				}
			}
		})
	}
}

// benchItoa converts a non-negative integer to its decimal string representation.
func benchItoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 12)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

// buildSkewedBlock builds a block whose first transaction carries hugeScriptLen
// bytes of scripts (one big input + one big output) followed by smallTxCount
// transactions whose scripts are smallScriptLen bytes each.
//
// This matches the shape of the fat-block heap profile: a small number of
// outlier transactions pin the scratch buffer's capacity at a high water mark
// for the entire block decode. The pre-arena code retains both the scratch's
// peak capacity (~46% of the heap profile) AND the per-tx scripts buffer
// allocation (~13% of the heap profile) at the same time. The arena path
// holds only the arena chunks themselves.
func buildSkewedBlock(hugeScriptLen, smallScriptLen, smallTxCount int) []byte {
	var buf bytes.Buffer

	// Block header.
	buf.Write(make([]byte, 80))

	// txCount = 1 huge + smallTxCount.
	writeVarIntBuf(&buf, uint64(1+smallTxCount))

	hugeScript := makePaddedScript(hugeScriptLen)
	smallScript := makePaddedScript(smallScriptLen)

	writeTx := func(inScript, outScript []byte) {
		var versionBytes [4]byte
		binary.LittleEndian.PutUint32(versionBytes[:], 1)
		buf.Write(versionBytes[:])

		writeVarIntBuf(&buf, 1)
		buf.Write(make([]byte, 32))
		var idx [4]byte
		binary.LittleEndian.PutUint32(idx[:], 0xffffffff)
		buf.Write(idx[:])
		writeVarIntBuf(&buf, uint64(len(inScript)))
		buf.Write(inScript)
		var seq [4]byte
		binary.LittleEndian.PutUint32(seq[:], 0xffffffff)
		buf.Write(seq[:])

		writeVarIntBuf(&buf, 1)
		buf.Write(make([]byte, 8))
		writeVarIntBuf(&buf, uint64(len(outScript)))
		buf.Write(outScript)
		buf.Write(make([]byte, 4))
	}

	writeTx(hugeScript, hugeScript)
	for i := 0; i < smallTxCount; i++ {
		writeTx(smallScript, smallScript)
	}

	return buf.Bytes()
}

// BenchmarkDecodeBlock_Skewed benchmarks the case where a single large
// transaction pins the scratch buffer (in the pre-arena path) for the entire
// remainder of the block decode. This is the realistic shape of the BSV
// fat-block stress block where a handful of huge transactions outweigh the
// thousands of standard-size ones.
//
// Pre-arena behaviour on this shape: scratch.cap pinned at hugeScriptLen for
// the entire block; every small tx still allocates a per-tx scripts buffer.
// Post-arena: scratch is gone entirely. Arena chunks hold only the script data,
// no separate "high water mark" buffer.
func BenchmarkDecodeBlock_Skewed(b *testing.B) {
	const hugeScriptLen = 4 * 1024 * 1024  // 4 MiB per input/output script
	const smallScriptLen = 2 * 1024        // 2 KiB
	const smallTxCount = 500

	// Raise ebs so the huge scripts pass validation.
	SetLimits(4 * 1024 * 1024 * 1024)
	defer SetLimits(fixedExcessiveBlockSize)

	data := buildSkewedBlock(hugeScriptLen, smallScriptLen, smallTxCount)
	b.SetBytes(int64(len(data)))
	r := bytes.NewReader(data)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = r.Seek(0, 0)
		var msg MsgBlock
		if err := msg.Bsvdecode(r, 0, BaseEncoding); err != nil {
			b.Fatalf("Bsvdecode: %v", err)
		}
	}
}
