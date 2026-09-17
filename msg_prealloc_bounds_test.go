// Copyright (c) 2024 The go-wire developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"runtime"
	"testing"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover W-1 (CWE-789): decoders that read an attacker-controlled
// CompactSize element count must not eagerly allocate a count-sized slice before
// the elements are read. The decoders grow their slices as elements actually
// arrive, so a short frame declaring a huge count fails on EOF with a bounded
// allocation.
//
// Contract: the bound is grow-as-read, not a count-field rejection. On the two
// length-known read paths (a *bytes.Reader, and the *bytes.Buffer that buffered
// ReadMessageN hands the decoder) boundedReserve also caps the up-front reserve
// to what the in-memory bytes can back. On the streaming path the peer's declared
// length is deliberately NOT trusted (readerRemaining ignores *io.LimitedReader),
// so there is no count-field rejection there — the decode simply grows as bytes
// arrive and fails on EOF. Checksum verification on the streaming path is covered
// by message_streaming_test.go; here the truncated decode fails before the
// checksum step is reached.

// bigLimits is an excessive-block-size large enough that the per-message global
// maxima (maxTxPerBlock, maxTxInPerMessage, ...) sit in the hundreds of millions,
// so the moderate counts used below pass the global check and reach the
// allocation logic under test.
const bigLimits = 4 * 1024 * 1024 * 1024 // 4 GiB

// unbackedCount is well under every global maximum at bigLimits but, if allocated
// eagerly, would reserve hundreds of megabytes (e.g. 4M TxIn * 80 B = 320 MB).
const unbackedCount = 4_000_000

// allocCeiling is the upper bound on bytes a single truncated decode may allocate.
// The grow-as-read decoders stay well below it (at most streamPreallocReserve
// elements, a few hundred KB); the old eager make([]T, count) allocated from the
// peer count (hundreds of MB for the ebs-scaled decoders, ~0.8-1.8 MB for the
// inv/cfcheckpoint families), so this cleanly distinguishes them.
const allocCeiling = 512 * 1024 // 512 KiB

// allocBytesDuring returns the number of heap bytes allocated while fn runs.
func allocBytesDuring(fn func()) uint64 {
	var m1, m2 runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&m1)
	fn()
	runtime.ReadMemStats(&m2)

	return m2.TotalAlloc - m1.TotalAlloc
}

// requireBoundedDecodeError runs decode, requiring it to fail (truncated body)
// without allocating more than allocCeiling bytes.
func requireBoundedDecodeError(t *testing.T, decode func() error) {
	t.Helper()

	var err error

	allocated := allocBytesDuring(func() { err = decode() })

	require.Error(t, err)
	assert.Lessf(t, allocated, uint64(allocCeiling),
		"decode allocated %d bytes (want < %d): a count-sized allocation was not bounded",
		allocated, allocCeiling)
}

// streamingFrame builds a wire frame whose header declares declaredLen bytes of
// payload but carries only body. The checksum is irrelevant because the streaming
// reader verifies it only after a successful decode; a truncated body fails first.
func streamingFrame(command string, body []byte, declaredLen uint32) []byte {
	hdr := makeHeader(MainNet, command, declaredLen, 0)

	return append(hdr, body...)
}

// bufferedFrame builds a fully-checksummed wire frame. The buffered ReadMessageN
// path verifies the checksum before decoding, so it must be correct; this
// exercises the *bytes.Buffer branch of readerRemaining that the direct
// length-known case (a *bytes.Reader) does not.
func bufferedFrame(command string, body []byte) []byte {
	sum := chainhash.DoubleHashB(body)
	hdr := makeHeader(MainNet, command, uint32(len(body)), binary.LittleEndian.Uint32(sum[0:4]))

	return append(hdr, body...)
}

// txCountBody returns version + input-count varint (+ optional trailing bytes for
// a valid 0-input prefix so the output count can be reached).
func txBody(t *testing.T, inCount, outCount uint64, includeOut bool) []byte {
	t.Helper()

	var b bytes.Buffer
	require.NoError(t, binary.Write(&b, littleEndian, int32(1))) // version
	b.Write(varIntBytes(t, inCount))

	if includeOut {
		b.Write(varIntBytes(t, outCount))
	}

	return b.Bytes()
}

// TestReaderRemaining verifies readerRemaining reports a length only for readers
// backed by bytes already in memory, and NOT for *io.LimitedReader (whose N is a
// header-declared length, not proof the bytes are available).
func TestReaderRemaining(t *testing.T) {
	t.Run("bytes.Reader is length-aware", func(t *testing.T) {
		got, ok := readerRemaining(bytes.NewReader([]byte{1, 2, 3, 4, 5}))
		require.True(t, ok)
		assert.Equal(t, uint64(5), got)
	})

	t.Run("bytes.Buffer is length-aware", func(t *testing.T) {
		got, ok := readerRemaining(bytes.NewBuffer([]byte{1, 2, 3}))
		require.True(t, ok)
		assert.Equal(t, uint64(3), got)
	})

	t.Run("io.LimitedReader is NOT trusted", func(t *testing.T) {
		lr := &io.LimitedReader{R: bytes.NewReader(nil), N: 1 << 30}
		_, ok := readerRemaining(lr)
		assert.False(t, ok, "LimitedReader.N is a declared length, not available bytes")
	})

	t.Run("bufio.Reader is not length-aware", func(t *testing.T) {
		_, ok := readerRemaining(bufio.NewReader(bytes.NewReader(make([]byte, 100))))
		assert.False(t, ok)
	})
}

// TestBoundedReserve verifies the reserve is capped by real remaining bytes when
// known, and by streamPreallocReserve otherwise.
func TestBoundedReserve(t *testing.T) {
	t.Run("real reader caps at remaining/minElem", func(t *testing.T) {
		r := bytes.NewReader(make([]byte, 1000))
		// A huge declared count is reserved only up to what the bytes can back.
		assert.Equal(t, 100, boundedReserve(r, 1_000_000, 10))
	})

	t.Run("real reader reserves the full count when it fits", func(t *testing.T) {
		r := bytes.NewReader(make([]byte, 1000))
		assert.Equal(t, 50, boundedReserve(r, 50, 10))
	})

	t.Run("unknown reader caps at streamPreallocReserve", func(t *testing.T) {
		lr := &io.LimitedReader{R: bytes.NewReader(nil), N: 1 << 30}
		assert.Equal(t, streamPreallocReserve, boundedReserve(lr, 1_000_000, 10))
	})

	t.Run("unknown reader reserves the full count when small", func(t *testing.T) {
		lr := &io.LimitedReader{R: bytes.NewReader(nil), N: 1 << 30}
		assert.Equal(t, 3, boundedReserve(lr, 3, 10))
	})
}

// TestGrowByOne verifies in-place growth within capacity and reallocation beyond.
func TestGrowByOne(t *testing.T) {
	s := make([]int, 0, 2)

	s = growByOne(s)
	s[0] = 1
	s = growByOne(s)
	s[1] = 2
	require.Len(t, s, 2)
	assert.Equal(t, 2, cap(s), "growth within capacity must not reallocate")

	s = growByOne(s) // exceeds capacity -> reallocates and grows
	s[2] = 3
	require.Len(t, s, 3)
	assert.Equal(t, []int{1, 2, 3}, s)
}

// TestPointersTo verifies the pointer view references the backing elements.
func TestPointersTo(t *testing.T) {
	s := []int{10, 20, 30}
	ptrs := pointersTo(s)
	require.Len(t, ptrs, 3)

	*ptrs[1] = 99
	assert.Equal(t, 99, s[1], "pointers must alias the backing slice")
}

// TestDecodersDoNotEagerlyAllocate is the core regression: for EVERY decoder that
// reads a CompactSize element count, a short frame declaring the largest count the
// decoder accepts must fail with a bounded allocation (never sized from the peer
// count), through BOTH a length-known reader and the streaming reader (whose
// declared length must not be trusted). The body carries the fields up to and
// including the count, but none of the elements.
func TestDecodersDoNotEagerlyAllocate(t *testing.T) {
	SetLimits(bigLimits)
	defer SetLimits(fixedExcessiveBlockSize)

	header := blockHeaderOnly(t)

	cases := []struct {
		name    string
		command string
		count   uint64
		prefix  []byte // fields preceding the count varint
		decode  func(io.Reader) error
	}{
		// ebs-scaled counts (huge at bigLimits): the reported W-1 vectors.
		{
			"tx input", CmdTx, unbackedCount,
			[]byte{1, 0, 0, 0},
			func(r io.Reader) error { return (&MsgTx{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{"tx output", CmdTx, unbackedCount, []byte{1, 0, 0, 0, 0}, // version + 0 inputs
			func(r io.Reader) error { return (&MsgTx{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) }},
		{
			"extended tx input", CmdExtendedTx, unbackedCount,
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0xEF}, // version + count(0) + EF header
			func(r io.Reader) error { return (&MsgExtendedTx{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"block tx", CmdBlock, unbackedCount, header,
			func(r io.Reader) error { return (&MsgBlock{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"merkle hash", CmdMerkleBlock, unbackedCount, append(append([]byte{}, header...), 0, 0, 0, 0),
			func(r io.Reader) error { return (&MsgMerkleBlock{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},

		// Fixed-maximum counts: bounded by a small global max, but still must not
		// eagerly allocate the (up to 50k/100k) peer count from a short frame.
		{
			"inv", CmdInv, MaxInvPerMsg, nil,
			func(r io.Reader) error { return (&MsgInv{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"getdata", CmdGetData, MaxInvPerMsg, nil,
			func(r io.Reader) error { return (&MsgGetData{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"notfound", CmdNotFound, MaxInvPerMsg, nil,
			func(r io.Reader) error { return (&MsgNotFound{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"addr", CmdAddr, MaxAddrPerMsg, nil,
			func(r io.Reader) error { return (&MsgAddr{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"headers", CmdHeaders, MaxBlockHeadersPerMsg, nil,
			func(r io.Reader) error { return (&MsgHeaders{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{"getblocks", CmdGetBlocks, MaxBlockLocatorsPerMsg, []byte{0, 0, 0, 0}, // protocol version
			func(r io.Reader) error { return (&MsgGetBlocks{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) }},
		{
			"getheaders", CmdGetHeaders, MaxBlockLocatorsPerMsg,
			[]byte{0, 0, 0, 0},
			func(r io.Reader) error { return (&MsgGetHeaders{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{"cfcheckpoint", CmdCFCheckpt, maxCFHeadersLen, make([]byte, 1+chainhash.HashSize), // filterType + stopHash
			func(r io.Reader) error { return (&MsgCFCheckpt{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) }},
		{"cfheaders", CmdCFHeaders, MaxCFHeadersPerMsg, make([]byte, 1+2*chainhash.HashSize), // filterType + stopHash + prevHeader
			func(r io.Reader) error { return (&MsgCFHeaders{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) }},
	}

	for _, tc := range cases {
		body := append(append([]byte{}, tc.prefix...), varIntBytes(t, tc.count)...)

		// Direct decode from a *bytes.Reader (length-known branch of readerRemaining).
		t.Run(tc.name+"/length-known reader", func(t *testing.T) {
			requireBoundedDecodeError(t, func() error {
				return tc.decode(bytes.NewReader(body))
			})
		})

		// Buffered ReadMessageN: the full payload is read into a *bytes.Buffer
		// before decode (the other length-aware branch of readerRemaining).
		t.Run(tc.name+"/buffered ReadMessageN reader", func(t *testing.T) {
			frame := bufferedFrame(tc.command, body)
			requireBoundedDecodeError(t, func() error {
				_, _, _, err := ReadMessageN(bytes.NewReader(frame), ProtocolVersion, MainNet)
				return err
			})
		})

		// Streaming ReadMessageStreamingN: the reader's declared length is NOT
		// trusted, so there is no count-field rejection here — grow-as-read alone
		// bounds the allocation and the decode fails on EOF.
		t.Run(tc.name+"/streaming reader", func(t *testing.T) {
			frame := streamingFrame(tc.command, body, uint32(len(body)))
			requireBoundedDecodeError(t, func() error {
				_, _, err := ReadMessageStreamingN(bytes.NewReader(frame),
					ProtocolVersion, MainNet, BaseEncoding)
				return err
			})
		})
	}
}

// TestStreamingLargeDeclaredLengthIsBounded is the specific case flagged in review:
// a streaming frame whose header declares a large payload length but delivers only
// version + a huge input count. The decoder must not trust the declared length and
// must fail with a bounded allocation.
func TestStreamingLargeDeclaredLengthIsBounded(t *testing.T) {
	SetLimits(bigLimits)
	defer SetLimits(fixedExcessiveBlockSize)

	body := append([]byte{1, 0, 0, 0}, varIntBytes(t, unbackedCount)...) // version + input count
	frame := streamingFrame(CmdTx, body, 100*1024*1024)                  // declare 100 MiB, deliver ~9 bytes

	requireBoundedDecodeError(t, func() error {
		_, _, err := ReadMessageStreamingN(bytes.NewReader(frame),
			ProtocolVersion, MainNet, BaseEncoding)
		return err
	})
}

// blockHeaderOnly returns the 80 wire bytes of blockOne's header.
func blockHeaderOnly(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, writeBlockHeader(&buf, ProtocolVersion, &blockOne.Header))
	require.Equal(t, blockHeaderLen, buf.Len())

	return buf.Bytes()
}

// TestDecodeValidMessagesStillWork guards against false rejection: real, fully
// backed messages must still decode after the grow-as-read change.
func TestDecodeValidMessagesStillWork(t *testing.T) {
	t.Run("transaction", func(t *testing.T) {
		var msg MsgTx
		require.NoError(t, msg.Bsvdecode(bytes.NewReader(multiTxEncoded),
			ProtocolVersion, BaseEncoding))
		assert.Len(t, msg.TxIn, len(multiTx.TxIn))
		assert.Len(t, msg.TxOut, len(multiTx.TxOut))
	})

	t.Run("block", func(t *testing.T) {
		var msg MsgBlock
		require.NoError(t, msg.Bsvdecode(bytes.NewReader(blockOneBytes), 0, BaseEncoding))
		assert.Len(t, msg.Transactions, len(blockOne.Transactions))
	})

	t.Run("block DeserializeTxLoc", func(t *testing.T) {
		var msg MsgBlock
		locs, err := msg.DeserializeTxLoc(bytes.NewBuffer(blockOneBytes))
		require.NoError(t, err)
		assert.Equal(t, blockOneTxLocs, locs)
	})
}

// TestGlobalMaximumStillRejects confirms the existing "too many ..." global bound
// still fires (and unchanged) for a count above the per-message maximum.
func TestGlobalMaximumStillRejects(t *testing.T) {
	payload := append(blockHeaderOnly(t), varIntBytes(t, maxTxPerBlock()+1)...)

	var msg MsgBlock
	err := msg.Bsvdecode(bytes.NewReader(payload), ProtocolVersion, BaseEncoding)

	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Contains(t, err.Error(), "too many transactions")
}

// TestStreamingRealignsAfterTruncatedDecode verifies that a truncated streaming
// message with a large declared length still leaves the stream positioned at the
// next message (the LimitedReader/drain path), so a following message decodes.
func TestStreamingRealignsAfterTruncatedDecode(t *testing.T) {
	// A self-consistent tx frame (declared length == delivered) whose decode
	// fails on the impossible input count after consuming the short payload.
	body := txBody(t, unbackedCount, 0, false)
	first := streamingFrame(CmdTx, body, uint32(len(body)))

	// A valid following verack frame.
	sum := chainhash.DoubleHashB(nil)
	second := makeHeader(MainNet, CmdVerAck, 0, binary.LittleEndian.Uint32(sum[0:4]))

	r := bytes.NewReader(append(first, second...))

	_, _, err := ReadMessageStreamingN(r, ProtocolVersion, MainNet, BaseEncoding)
	require.Error(t, err)

	_, next, err := ReadMessageStreamingN(r, ProtocolVersion, MainNet, BaseEncoding)
	require.NoError(t, err)
	require.NotNil(t, next)
	assert.Equal(t, CmdVerAck, next.Command())
}

// BenchmarkBoundedReserve documents the per-count-field cost of the reserve
// helper: a single type switch, a division and a comparison, no allocation.
func BenchmarkBoundedReserve(b *testing.B) {
	r := bytes.NewReader(make([]byte, 1<<20))

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = boundedReserve(r, 1000, minTxInPayload)
	}
}
