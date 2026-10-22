// Copyright (c) 2024 The go-wire developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the byte-length counterpart of W-1 (CWE-789, issue #179):
// fields encoded as a CompactSize byte length followed by that many bytes
// (var strings, var bytes, scripts, protoconf stream policies) must not allocate
// a length-sized buffer before the bytes are read. The length is checked only
// against a global maximum that scales with SetLimits, so a few bytes declaring
// a huge length used to force a huge allocation before failing on EOF.
//
// The contract mirrors msg_prealloc_bounds_test.go: on the length-known readers
// (*bytes.Reader, and the *bytes.Buffer that buffered ReadMessageN decodes from)
// a fully backed field is still read with one exact allocation, and an unbacked
// one reserves at most what the in-memory bytes can back. On the streaming path
// the declared payload length is not trusted, so the buffer grows only as bytes
// actually arrive.

// unbackedVarLen is a declared byte length that every affected field accepts at
// bigLimits (it is below maxFlagsPerMerkleBlock, the smallest of their maxima, and
// above blockArenaChunkSize so the block decoder takes its oversize-script path),
// yet allocating it eagerly costs 32 MiB, far above allocCeiling.
const unbackedVarLen = 32 * 1024 * 1024

// requireTruncatedDecode runs decode, requiring it to fail with an EOF-class
// error (proving the decoder accepted the declared length and reached the read
// of the field's bytes, rather than rejecting it against a maximum) without
// allocating more than allocCeiling bytes.
func requireTruncatedDecode(t *testing.T, decode func() error) {
	t.Helper()

	var err error

	allocated := allocBytesDuring(func() { err = decode() })

	require.Error(t, err)
	require.Truef(t, errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF),
		"want an EOF-class error from reading the field bytes, got %v", err)
	assert.Lessf(t, allocated, uint64(allocCeiling),
		"decode allocated %d bytes (want < %d): a length-sized allocation was not bounded",
		allocated, allocCeiling)
}

// concatBytes joins byte slices into a new slice.
func concatBytes(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

// TestIssue179RejectReproduction is the exact reproduction from issue #179: with
// raised limits, a 5-byte reject payload whose command string declares a
// ~1.66 GB length allocated the full declared length before failing with EOF.
func TestIssue179RejectReproduction(t *testing.T) {
	SetLimits(4_000_000_000)
	defer SetLimits(fixedExcessiveBlockSize)

	payload := []byte("\xfe000c") // varint 0xfe + 4 bytes => count 0x63303030 (~1.66 GB)
	frame := bufferedFrame(CmdReject, payload)

	var err error

	allocated := allocBytesDuring(func() {
		_, _, _, err = ReadMessageWithEncodingN(bytes.NewReader(frame),
			ProtocolVersion, MainNet, BaseEncoding)
	})

	t.Logf("5-byte reject payload declaring a 0x63303030-byte command allocated %d bytes", allocated)
	require.ErrorIs(t, err, io.EOF)
	assert.Lessf(t, allocated, uint64(16*1024),
		"a 5-byte reject payload allocated %d bytes", allocated)
}

// TestVarLenFieldsDoNotEagerlyAllocate is the regression matrix: for every field
// that reads a byte length and then the bytes, a short frame declaring a large
// length must fail with a bounded allocation through a length-known reader, the
// buffered ReadMessageN reader and the streaming reader. The body carries every
// field up to and including the length, but none of the field's bytes.
func TestVarLenFieldsDoNotEagerlyAllocate(t *testing.T) {
	SetLimits(bigLimits)
	defer SetLimits(fixedExcessiveBlockSize)

	length := varIntBytes(t, unbackedVarLen)
	header := blockHeaderOnly(t)
	version := []byte{1, 0, 0, 0}
	outPoint := make([]byte, 36)
	sequence := make([]byte, 4)
	value := make([]byte, 8)
	efMarker := []byte{0, 0, 0, 0, 0, 0xEF} // zero input count + EF header

	cases := []struct {
		name    string
		command string // empty when the field is not reachable as a message
		body    []byte
		decode  func(io.Reader) error
	}{
		{
			"ReadVarString", "", length,
			func(r io.Reader) error { _, err := ReadVarString(r, ProtocolVersion); return err },
		},
		{
			"ReadVarBytes", "", length,
			func(r io.Reader) error {
				_, err := ReadVarBytes(r, ProtocolVersion, maxMessagePayload(), "field")
				return err
			},
		},
		{
			"reject command", CmdReject, length,
			func(r io.Reader) error { return (&MsgReject{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"reject reason", CmdReject, concatBytes([]byte{2, 't', 'x', byte(RejectInvalid)}, length),
			func(r io.Reader) error { return (&MsgReject{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"createstream policy name", CmdCreateStream,
			concatBytes([]byte{1, 0xAA, byte(StreamTypeGeneral)}, length),
			func(r io.Reader) error { return (&MsgCreateStream{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"protoconf stream policies", CmdProtoconf, concatBytes([]byte{2, 0, 0, 0x10, 0}, length),
			func(r io.Reader) error { return (&MsgProtoconf{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"merkleblock flags", CmdMerkleBlock, concatBytes(header, []byte{0, 0, 0, 0, 0}, length),
			func(r io.Reader) error { return (&MsgMerkleBlock{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"tx input script", CmdTx, concatBytes(version, []byte{1}, outPoint, length),
			func(r io.Reader) error { return (&MsgTx{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"tx output script", CmdTx, concatBytes(version, []byte{0, 1}, value, length),
			func(r io.Reader) error { return (&MsgTx{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"extended tx input script", CmdExtendedTx,
			concatBytes(version, efMarker, []byte{1}, outPoint, length),
			func(r io.Reader) error { return (&MsgExtendedTx{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"extended tx previous script", CmdExtendedTx,
			concatBytes(version, efMarker, []byte{1}, outPoint, []byte{0}, sequence, value, length),
			func(r io.Reader) error { return (&MsgExtendedTx{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"block tx input script", CmdBlock, concatBytes(header, []byte{1}, version, []byte{1}, outPoint, length),
			func(r io.Reader) error { return (&MsgBlock{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
		{
			"block tx output script", CmdBlock, concatBytes(header, []byte{1}, version, []byte{0, 1}, value, length),
			func(r io.Reader) error { return (&MsgBlock{}).Bsvdecode(r, ProtocolVersion, BaseEncoding) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/length-known reader", func(t *testing.T) {
			requireTruncatedDecode(t, func() error { return tc.decode(bytes.NewReader(tc.body)) })
		})

		// The streaming path's reader: its N is a declared length, not proof the
		// bytes exist, so it must not size the allocation.
		t.Run(tc.name+"/streaming reader", func(t *testing.T) {
			r := &io.LimitedReader{R: bytes.NewReader(tc.body), N: unbackedVarLen}
			requireTruncatedDecode(t, func() error { return tc.decode(r) })
		})

		if tc.command == "" {
			continue
		}

		t.Run(tc.name+"/buffered ReadMessageN", func(t *testing.T) {
			frame := bufferedFrame(tc.command, tc.body)
			requireTruncatedDecode(t, func() error {
				_, _, _, err := ReadMessageN(bytes.NewReader(frame), ProtocolVersion, MainNet)
				return err
			})
		})

		t.Run(tc.name+"/ReadMessageStreamingN", func(t *testing.T) {
			frame := streamingFrame(tc.command, tc.body, uint32(len(tc.body)))
			requireTruncatedDecode(t, func() error {
				_, _, err := ReadMessageStreamingN(bytes.NewReader(frame), ProtocolVersion, MainNet, BaseEncoding)
				return err
			})
		})
	}
}

// TestStreamingVarStringLargeDeclaredLengthIsBounded covers a streaming reject
// frame whose header declares a payload as large as the string it announces but
// delivers only the length prefix: the declared payload length is not proof the
// bytes exist, so it must not size the allocation either.
func TestStreamingVarStringLargeDeclaredLengthIsBounded(t *testing.T) {
	SetLimits(bigLimits)
	defer SetLimits(fixedExcessiveBlockSize)

	body := varIntBytes(t, unbackedVarLen)
	frame := streamingFrame(CmdReject, body, unbackedVarLen+uint32(len(body)))

	requireTruncatedDecode(t, func() error {
		_, _, err := ReadMessageStreamingN(bytes.NewReader(frame), ProtocolVersion, MainNet, BaseEncoding)
		return err
	})
}

// varLenTestSizes are field lengths around the streaming growth boundaries.
var varLenTestSizes = []int{
	0, 1, 7,
	varLenPreallocReserve - 1, varLenPreallocReserve, varLenPreallocReserve + 1,
	3*varLenPreallocReserve + 5,
	1<<20 + 7,
}

// varLenReaders wraps data in each reader shape a decoder may be handed: the two
// length-known in-memory readers, the streaming path's LimitedReader, and readers
// that return short reads, so the grow-as-read loop is exercised across chunks.
func varLenReaders(data []byte) map[string]io.Reader {
	return map[string]io.Reader{
		"bytes.Reader":  bytes.NewReader(data),
		"bytes.Buffer":  bytes.NewBuffer(append([]byte(nil), data...)),
		"LimitedReader": &io.LimitedReader{R: bytes.NewReader(data), N: int64(len(data))},
		"OneByteReader": iotest.OneByteReader(bytes.NewReader(data)),
		"HalfReader":    iotest.HalfReader(bytes.NewReader(data)),
		"DataErrReader": iotest.DataErrReader(bytes.NewReader(data)),
	}
}

// TestReadVarLenBytesRoundTrip verifies that fully backed fields of every size
// decode byte-for-byte through every reader shape, leave the reader positioned
// right after the field, and that legitimate strings and byte slices still
// round-trip through the public helpers.
func TestReadVarLenBytesRoundTrip(t *testing.T) {
	const trailer = "next"

	for _, size := range varLenTestSizes {
		want := bytes.Repeat([]byte{0xA5, 0x5A, 0x01}, size/3+1)[:size]

		for name, r := range varLenReaders(append(append([]byte(nil), want...), trailer...)) {
			t.Run(name, func(t *testing.T) {
				got, err := readVarLenBytes(r, uint64(size))
				require.NoError(t, err)
				require.Len(t, got, size)
				assert.Equal(t, size, cap(got), "len must equal cap, as with make([]byte, count)")
				assert.True(t, bytes.Equal(want, got), "decoded bytes differ (size %d)", size)

				rest, err := io.ReadAll(r)
				require.NoError(t, err)
				assert.Equal(t, trailer, string(rest), "reader not positioned after the field")
			})
		}

		var buf bytes.Buffer
		require.NoError(t, WriteVarString(&buf, ProtocolVersion, string(want)))
		require.NoError(t, WriteVarBytes(&buf, ProtocolVersion, want))
		encoded := buf.Bytes()

		for name, r := range varLenReaders(encoded) {
			t.Run("public helpers/"+name, func(t *testing.T) {
				str, err := ReadVarString(r, ProtocolVersion)
				require.NoError(t, err)
				assert.Equal(t, string(want), str)

				b, err := ReadVarBytes(r, ProtocolVersion, maxMessagePayload(), "field")
				require.NoError(t, err)
				assert.True(t, bytes.Equal(want, b), "ReadVarBytes differs (size %d)", size)
			})
		}
	}
}

// TestReadVarLenBytesTruncatedErrors verifies the bounded reader reports a short
// field exactly as the previous single io.ReadFull did: io.EOF when none of the
// field's bytes are present and io.ErrUnexpectedEOF when only some are, including
// when the stream ends exactly on an internal growth boundary.
func TestReadVarLenBytesTruncatedErrors(t *testing.T) {
	const declared = 4 * varLenPreallocReserve

	for _, available := range []int{
		0, 1, varLenPreallocReserve - 1, varLenPreallocReserve,
		varLenPreallocReserve + 1, 2 * varLenPreallocReserve, declared - 1,
	} {
		data := bytes.Repeat([]byte{0x42}, available)

		want := io.ErrUnexpectedEOF
		if available == 0 {
			want = io.EOF
		}

		// The reference behavior is the original implementation's single
		// io.ReadFull into a declared-length buffer.
		_, refErr := io.ReadFull(bytes.NewReader(data), make([]byte, declared))
		require.ErrorIs(t, refErr, want)

		for name, r := range varLenReaders(data) {
			t.Run(name, func(t *testing.T) {
				got, err := readVarLenBytes(r, declared)
				assert.Nil(t, got)
				assert.Equalf(t, want, err, "available %d of %d bytes", available, declared)
			})
		}
	}
}

// TestReadVarLenBytesUnbackedInMemoryDoesNotAllocate verifies that when an
// in-memory reader cannot back the declared length, the certain failure costs no
// allocation, yet the reader is left drained exactly as io.ReadFull would leave it.
func TestReadVarLenBytesUnbackedInMemoryDoesNotAllocate(t *testing.T) {
	// lenReader is an in-memory reader that reports its unread length.
	type lenReader interface {
		io.Reader
		Len() int
	}

	data := make([]byte, 1<<20)

	for name, newReader := range map[string]func() lenReader{
		"bytes.Reader": func() lenReader { return bytes.NewReader(data) },
		"bytes.Buffer": func() lenReader { return bytes.NewBuffer(data) },
	} {
		t.Run(name, func(t *testing.T) {
			r := newReader()

			var err error

			allocated := allocBytesDuring(func() { _, err = readVarLenBytes(r, 32<<20) })

			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			assert.Zero(t, r.Len(), "the available bytes must be consumed")
			assert.Lessf(t, allocated, uint64(4096), "unbacked in-memory field allocated %d bytes", allocated)
		})
	}
}

// errVarLenRead is the non-EOF read error TestReadVarLenBytesPropagatesReadErrors
// injects.
var errVarLenRead = errors.New("var len read failed")

// TestReadVarLenBytesPropagatesReadErrors verifies a non-EOF read error is
// returned unchanged, both before and after part of the field has been read.
func TestReadVarLenBytesPropagatesReadErrors(t *testing.T) {
	_, err := readVarLenBytes(iotest.ErrReader(errVarLenRead), 10)
	require.ErrorIs(t, err, errVarLenRead)

	partial := io.MultiReader(bytes.NewReader(make([]byte, varLenPreallocReserve+3)), iotest.ErrReader(errVarLenRead))
	_, err = readVarLenBytes(partial, 4*varLenPreallocReserve)
	require.ErrorIs(t, err, errVarLenRead)
}

// TestReadVarLenBytesFullyBackedIsSingleAllocation guards the common buffered
// path against regression: when the in-memory reader backs the whole field, it
// is read with one allocation of exactly the field's length.
func TestReadVarLenBytesFullyBackedIsSingleAllocation(t *testing.T) {
	data := make([]byte, 1<<20)

	for _, newReader := range []func() io.Reader{
		func() io.Reader { return bytes.NewReader(data) },
		func() io.Reader { return bytes.NewBuffer(data) },
	} {
		got, err := readVarLenBytes(newReader(), uint64(len(data)))
		require.NoError(t, err)
		assert.Equal(t, len(data), cap(got), "fully backed field must be allocated exactly once, at its length")

		r := newReader()
		allocs := testing.AllocsPerRun(10, func() {
			r = newReader()
			_, _ = readVarLenBytes(r, uint64(len(data)))
		})
		assert.LessOrEqual(t, allocs, 2.0, "reader construction plus one buffer")
	}
}

// TestReadVarLenBytesStreamingGrowthIsBounded verifies that on a streaming
// reader the buffer grows with the bytes that actually arrive: a field that
// delivers N of a much larger declared length allocates in proportion to N, not
// to the declaration.
func TestReadVarLenBytesStreamingGrowthIsBounded(t *testing.T) {
	const delivered = 256 * 1024

	r := &io.LimitedReader{R: bytes.NewReader(make([]byte, delivered)), N: 1 << 40}

	var err error

	allocated := allocBytesDuring(func() { _, err = readVarLenBytes(r, 1<<32) })

	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.Lessf(t, allocated, uint64(8*delivered),
		"streaming read of %d bytes allocated %d bytes", delivered, allocated)
}

// TestDecodeLegitimateVarLenMessages guards against false rejection: real,
// fully backed messages carrying long strings and scripts still decode through
// the buffered and streaming read paths.
func TestDecodeLegitimateVarLenMessages(t *testing.T) {
	longText := string(bytes.Repeat([]byte("reason "), varLenPreallocReserve/2))

	reject := NewMsgReject(CmdBlock, RejectInvalid, longText)
	reject.Hash = blockOne.Header.BlockHash()

	tx := NewMsgTx(1)
	tx.AddTxIn(NewTxIn(&OutPoint{Index: 1}, bytes.Repeat([]byte{0x51}, 5*varLenPreallocReserve)))
	tx.AddTxOut(NewTxOut(7, bytes.Repeat([]byte{0x6a}, 3*varLenPreallocReserve+1)))

	for _, msg := range []Message{reject, tx} {
		var buf bytes.Buffer
		require.NoError(t, msg.BsvEncode(&buf, ProtocolVersion, BaseEncoding))
		body := buf.Bytes()

		t.Run(msg.Command()+"/buffered ReadMessageN", func(t *testing.T) {
			_, got, _, err := ReadMessageN(bytes.NewReader(bufferedFrame(msg.Command(), body)),
				ProtocolVersion, MainNet)
			require.NoError(t, err)
			assert.Equal(t, msg, got)
		})

		t.Run(msg.Command()+"/ReadMessageStreamingN", func(t *testing.T) {
			_, got, err := ReadMessageStreamingN(bytes.NewReader(bufferedFrame(msg.Command(), body)),
				ProtocolVersion, MainNet, BaseEncoding)
			require.NoError(t, err)
			assert.Equal(t, msg, got)
		})
	}

	t.Run("protoconf", func(t *testing.T) {
		policies := []string{longText, DefaultStreamPolicy}
		msg := &MsgProtoconf{NumberOfFields: 2, MaxRecvPayloadLength: 1 << 20, StreamPolicies: policies}

		var buf bytes.Buffer
		require.NoError(t, msg.BsvEncode(&buf, ProtocolVersion, BaseEncoding))

		var got MsgProtoconf
		require.NoError(t, got.Bsvdecode(iotest.HalfReader(&buf), ProtocolVersion, BaseEncoding))
		assert.Equal(t, policies, got.StreamPolicies)
	})
}

// TestDecodeBlockOversizeScripts covers the block decoder's oversize-script path
// (scripts above blockArenaChunkSize, read outside the arena): legitimate oversize
// scripts decode intact through every read path, with cap == len so appending to
// one can never write into another.
func TestDecodeBlockOversizeScripts(t *testing.T) {
	// Raised limits, as on a node that accepts large blocks; at the default limit
	// an input script this size exceeds maxTxInPerMessage.
	SetLimits(bigLimits)
	defer SetLimits(fixedExcessiveBlockSize)

	sigScript := bytes.Repeat([]byte{0x51}, blockArenaChunkSize+3)
	pkScript := bytes.Repeat([]byte{0x6a}, blockArenaChunkSize+1)

	tx := NewMsgTx(1)
	tx.AddTxIn(NewTxIn(&OutPoint{Index: 1}, sigScript))
	tx.AddTxOut(NewTxOut(7, pkScript))
	tx.AddTxOut(NewTxOut(8, []byte{0x51}))

	block := NewMsgBlock(&blockOne.Header)
	require.NoError(t, block.AddTransaction(tx))

	var buf bytes.Buffer
	require.NoError(t, block.BsvEncode(&buf, ProtocolVersion, BaseEncoding))
	body := buf.Bytes()

	decoders := map[string]func() (Message, error){
		"bytes.Reader": func() (Message, error) {
			var msg MsgBlock
			return &msg, msg.Bsvdecode(bytes.NewReader(body), ProtocolVersion, BaseEncoding)
		},
		"buffered ReadMessageN": func() (Message, error) {
			_, msg, _, err := ReadMessageN(bytes.NewReader(bufferedFrame(CmdBlock, body)), ProtocolVersion, MainNet)
			return msg, err
		},
		"ReadMessageStreamingN": func() (Message, error) {
			_, msg, err := ReadMessageStreamingN(bytes.NewReader(bufferedFrame(CmdBlock, body)),
				ProtocolVersion, MainNet, BaseEncoding)
			return msg, err
		},
	}

	for name, decode := range decoders {
		t.Run(name, func(t *testing.T) {
			msg, err := decode()
			require.NoError(t, err)

			got, ok := msg.(*MsgBlock)
			require.True(t, ok)
			require.Len(t, got.Transactions, 1)

			gotTx := got.Transactions[0]
			assert.True(t, bytes.Equal(sigScript, gotTx.TxIn[0].SignatureScript), "signature script differs")
			assert.True(t, bytes.Equal(pkScript, gotTx.TxOut[0].PkScript), "public key script differs")
			assert.Equal(t, []byte{0x51}, gotTx.TxOut[1].PkScript)

			for _, script := range [][]byte{gotTx.TxIn[0].SignatureScript, gotTx.TxOut[0].PkScript} {
				assert.Equal(t, len(script), cap(script), "oversize script must keep cap == len")
			}

			assert.Equal(t, tx.TxHash(), gotTx.TxHash())
		})
	}
}

// chunkedReader returns at most n bytes per Read, to vary the short-read
// pattern a streaming peer can produce.
type chunkedReader struct {
	r io.Reader
	n int
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if len(p) > c.n {
		p = p[:c.n]
	}

	return c.r.Read(p)
}

// fuzzMaxAvailable caps the bytes a fuzz input makes available, keeping each
// execution cheap while still spanning several varLenPreallocReserve doublings.
const fuzzMaxAvailable = 1 << 20

// FuzzReadVarLenBytes checks readVarLenBytes against the original io.ReadFull
// semantics for arbitrary declared lengths, available byte counts and read
// sizes, through a length-known reader, the streaming path's LimitedReader and a
// reader that returns short reads. The field's bytes are generated from their
// position rather than fuzzed: their values do not affect the decoder, and
// keeping the fuzz input to a few integers keeps the engine's minimization of
// new inputs fast.
func FuzzReadVarLenBytes(f *testing.F) {
	f.Add(uint32(0), uint32(0), uint16(1))
	f.Add(uint32(5), uint32(5), uint16(5))
	f.Add(uint32(8), uint32(3), uint16(1))
	f.Add(uint32(0x63303030), uint32(0), uint16(4096)) // issue #179
	f.Add(uint32(0x63303030), uint32(7), uint16(3))
	f.Add(uint32(3*varLenPreallocReserve), uint32(varLenPreallocReserve), uint16(4096))

	f.Fuzz(func(t *testing.T, declared, available uint32, readSize uint16) {
		count := uint64(declared)

		data := make([]byte, available%(fuzzMaxAvailable+1))
		for i := range data {
			data[i] = byte(i ^ i>>8 ^ i>>16)
		}

		var (
			want    []byte
			wantErr error
		)

		switch {
		case count <= uint64(len(data)):
			want = data[:count]
		case len(data) == 0:
			wantErr = io.EOF
		default:
			wantErr = io.ErrUnexpectedEOF
		}

		readers := map[string]io.Reader{
			"bytes.Reader":  bytes.NewReader(data),
			"LimitedReader": &io.LimitedReader{R: bytes.NewReader(data), N: int64(count)},
			"chunkedReader": &chunkedReader{r: bytes.NewReader(data), n: max(int(readSize), 1)},
		}

		for name, r := range readers {
			got, err := readVarLenBytes(r, count)
			if wantErr != nil {
				if !errors.Is(err, wantErr) || got != nil {
					t.Fatalf("%s: declared %d, %d available: got (%d bytes, %v), want error %v",
						name, count, len(data), len(got), err, wantErr)
				}

				continue
			}

			if err != nil || !bytes.Equal(got, want) || len(got) != len(want) {
				t.Fatalf("%s: declared %d, %d available: got (%d bytes, %v)",
					name, count, len(data), len(got), err)
			}
		}
	})
}

// BenchmarkReadVarLenBytes documents the cost of the bounded reader for a fully
// backed field (the buffered decode path) and a streamed one.
func BenchmarkReadVarLenBytes(b *testing.B) {
	data := make([]byte, 64*1024)

	b.Run("fully backed", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = readVarLenBytes(bytes.NewReader(data), uint64(len(data)))
		}
	})

	b.Run("streaming", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, _ = readVarLenBytes(&io.LimitedReader{R: bytes.NewReader(data), N: int64(len(data))}, uint64(len(data)))
		}
	})
}
