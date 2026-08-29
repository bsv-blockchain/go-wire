package wire

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMsgCmpctBlockCommand ensures the command string is correct.
func TestMsgCmpctBlockCommand(t *testing.T) {
	msg := NewMsgCmpctBlock(&blockOne.Header, 42)

	assert.Equal(t, CmdCmpctBlock, msg.Command())
	assert.Equal(t, "cmpctblock", msg.Command())
}

// TestMsgCmpctBlockMaxPayloadLength checks the advertised payload ceiling.
func TestMsgCmpctBlockMaxPayloadLength(t *testing.T) {
	msg := NewMsgCmpctBlock(&blockOne.Header, 42)

	assert.Equal(t, MaxBlockPayload(), msg.MaxPayloadLength(ProtocolVersion))
}

// TestNewMsgCmpctBlockSetsFields verifies the constructor copies the header and
// keeps the nonce.
func TestNewMsgCmpctBlockSetsFields(t *testing.T) {
	msg := NewMsgCmpctBlock(&blockOne.Header, 0x0102030405060708)

	assert.Equal(t, blockOne.Header, msg.Header)
	assert.Equal(t, uint64(0x0102030405060708), msg.Nonce)
	assert.Empty(t, msg.ShortIDs)
	assert.Empty(t, msg.PrefilledTxn)
}

// TestMsgCmpctBlockRoundTrip exercises encode/decode round trips.
func TestMsgCmpctBlockRoundTrip(t *testing.T) {
	tests := []struct {
		name         string
		shortIDs     []uint64
		prefilledIdx []uint32
	}{
		{name: "empty", shortIDs: nil, prefilledIdx: nil},
		{name: "coinbase only", shortIDs: nil, prefilledIdx: []uint32{0}},
		{name: "one short id", shortIDs: []uint64{0x0000000000000001}, prefilledIdx: []uint32{0}},
		{
			name:         "many short ids",
			shortIDs:     []uint64{0, 1, 0xffffffffffff, 0x00000000ffffffff, 0x0000ffff00000000},
			prefilledIdx: []uint32{0, 3, 9},
		},
		{
			name:         "sparse prefilled",
			shortIDs:     []uint64{7},
			prefilledIdx: []uint32{0, 1, 65536, 1000000},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := NewMsgCmpctBlock(&blockOne.Header, 0xdeadbeefcafef00d)
			msg.ShortIDs = tt.shortIDs

			for i, idx := range tt.prefilledIdx {
				require.NoError(t, msg.AddPrefilledTransaction(idx, cmpctTestTx(t, int32(i+1))))
			}

			var decoded MsgCmpctBlock
			require.NoError(t, decoded.Bsvdecode(bytes.NewReader(encodeMsg(t, msg)),
				ProtocolVersion, BaseEncoding))

			assert.Equal(t, msg.Header, decoded.Header)
			assert.Equal(t, msg.Nonce, decoded.Nonce)
			// A nil short ID list round trips to an empty one, so compare
			// the contents rather than the nil-ness.
			require.Len(t, decoded.ShortIDs, len(tt.shortIDs))
			for i, id := range tt.shortIDs {
				assert.Equal(t, id, decoded.ShortIDs[i])
			}

			require.Len(t, decoded.PrefilledTxn, len(tt.prefilledIdx))

			for i, pt := range decoded.PrefilledTxn {
				assert.Equal(t, tt.prefilledIdx[i], pt.Index)
				assert.Equal(t, int32(i+1), pt.Tx.Version)
				assert.Equal(t, msg.PrefilledTxn[i].Tx.TxHash(), pt.Tx.TxHash())
			}
		})
	}
}

// TestMsgCmpctBlockShortIDWire pins the 6-byte little endian short ID encoding:
// a uint32 least significant word then a uint16 most significant word
// (blockencodings.h, CBlockHeaderAndShortTxIDs).
func TestMsgCmpctBlockShortIDWire(t *testing.T) {
	shortIDs := []uint64{0x0000000000000000, 0x0000112233445566, 0x0000ffffffffffff}

	msg := NewMsgCmpctBlock(&blockOne.Header, 1)
	msg.ShortIDs = shortIDs

	var headerBuf bytes.Buffer
	require.NoError(t, writeBlockHeader(&headerBuf, ProtocolVersion, &blockOne.Header))

	want := make([]byte, 0, 128)
	want = append(want, headerBuf.Bytes()...)
	want = binary.LittleEndian.AppendUint64(want, 1)
	want = append(want, varIntBytes(t, uint64(len(shortIDs)))...)

	for _, id := range shortIDs {
		want = binary.LittleEndian.AppendUint32(want, uint32(id&0xffffffff))
		want = binary.LittleEndian.AppendUint16(want, uint16((id>>32)&0xffff))
	}

	want = append(want, varIntBytes(t, 0)...)

	encoded := encodeMsg(t, msg)
	assert.Equal(t, want, encoded)
	assert.Len(t, encoded, headerBuf.Len()+8+1+len(shortIDs)*ShortIDSize+1)
}

// TestMsgCmpctBlockEncodeRejectsWideShortID ensures a short ID that does not
// fit in 6 bytes is rejected rather than silently truncated.
func TestMsgCmpctBlockEncodeRejectsWideShortID(t *testing.T) {
	msg := NewMsgCmpctBlock(&blockOne.Header, 1)
	msg.ShortIDs = []uint64{0x0001000000000000}

	var buf bytes.Buffer
	err := msg.BsvEncode(&buf, ProtocolVersion, BaseEncoding)

	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Contains(t, err.Error(), "short id exceeds 6 bytes")
}

// TestMsgCmpctBlockPrefilledDifferentialWire pins the differential index
// encoding for prefilled transactions (blockencodings.h, PrefilledTransaction).
func TestMsgCmpctBlockPrefilledDifferentialWire(t *testing.T) {
	tests := []struct {
		name     string
		indexes  []uint32
		wantWire []uint64
	}{
		{name: "contiguous from zero", indexes: []uint32{0, 1, 2}, wantWire: []uint64{0, 0, 0}},
		{name: "sparse", indexes: []uint32{5, 7}, wantWire: []uint64{5, 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := NewMsgCmpctBlock(&blockOne.Header, 1)
			for _, idx := range tt.indexes {
				require.NoError(t, msg.AddPrefilledTransaction(idx, cmpctTestTx(t, 1)))
			}

			var headerBuf bytes.Buffer
			require.NoError(t, writeBlockHeader(&headerBuf, ProtocolVersion, &blockOne.Header))

			var txBuf bytes.Buffer
			require.NoError(t, cmpctTestTx(t, 1).BsvEncode(&txBuf, ProtocolVersion, BaseEncoding))

			want := make([]byte, 0, 512)
			want = append(want, headerBuf.Bytes()...)
			want = binary.LittleEndian.AppendUint64(want, 1)
			want = append(want, varIntBytes(t, 0)...)
			want = append(want, varIntBytes(t, uint64(len(tt.indexes)))...)

			for _, v := range tt.wantWire {
				want = append(want, varIntBytes(t, v)...)
				want = append(want, txBuf.Bytes()...)
			}

			assert.Equal(t, want, encodeMsg(t, msg))
		})
	}
}

// TestMsgCmpctBlockEncodeRejectsNonMonotonicPrefilled ensures prefilled indexes
// that are not strictly increasing are refused by the encoder.
func TestMsgCmpctBlockEncodeRejectsNonMonotonicPrefilled(t *testing.T) {
	tests := []struct {
		name    string
		indexes []uint32
	}{
		{name: "repeated index", indexes: []uint32{4, 4}},
		{name: "decreasing index", indexes: []uint32{9, 2}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := NewMsgCmpctBlock(&blockOne.Header, 1)
			for _, idx := range tt.indexes {
				msg.PrefilledTxn = append(msg.PrefilledTxn,
					PrefilledTransaction{Index: idx, Tx: cmpctTestTx(t, 1)})
			}

			var buf bytes.Buffer
			err := msg.BsvEncode(&buf, ProtocolVersion, BaseEncoding)

			var msgErr *MessageError
			require.ErrorAs(t, err, &msgErr)
			assert.Contains(t, err.Error(), "non-strictly-monotonic")
		})
	}
}

// TestMsgCmpctBlockAddPrefilledTransactionRejectsNonMonotonic ensures the
// helper refuses an out of order append.
func TestMsgCmpctBlockAddPrefilledTransactionRejectsNonMonotonic(t *testing.T) {
	msg := NewMsgCmpctBlock(&blockOne.Header, 1)
	require.NoError(t, msg.AddPrefilledTransaction(5, cmpctTestTx(t, 1)))

	err := msg.AddPrefilledTransaction(5, cmpctTestTx(t, 2))
	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Len(t, msg.PrefilledTxn, 1)
}

// TestMsgCmpctBlockDecodeRejectsPrefilledOverflow ensures a prefilled index
// that pushes past 32 bits is rejected, mirroring the C++ throw.
func TestMsgCmpctBlockDecodeRejectsPrefilledOverflow(t *testing.T) {
	var headerBuf bytes.Buffer
	require.NoError(t, writeBlockHeader(&headerBuf, ProtocolVersion, &blockOne.Header))

	t.Run("single index above uint32", func(t *testing.T) {
		payload := make([]byte, 0, 128)
		payload = append(payload, headerBuf.Bytes()...)
		payload = binary.LittleEndian.AppendUint64(payload, 1)
		payload = append(payload, varIntBytes(t, 0)...)
		payload = append(payload, varIntBytes(t, 1)...)
		payload = append(payload, varIntBytes(t, uint64(math.MaxUint32)+1)...)

		var msg MsgCmpctBlock
		err := msg.Bsvdecode(bytes.NewReader(payload), ProtocolVersion, BaseEncoding)

		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Contains(t, err.Error(), "index overflowed 32 bits")
	})

	t.Run("accumulated index above uint32", func(t *testing.T) {
		var txBuf bytes.Buffer
		require.NoError(t, cmpctTestTx(t, 1).BsvEncode(&txBuf, ProtocolVersion, BaseEncoding))

		payload := make([]byte, 0, 512)
		payload = append(payload, headerBuf.Bytes()...)
		payload = binary.LittleEndian.AppendUint64(payload, 1)
		payload = append(payload, varIntBytes(t, 0)...)
		payload = append(payload, varIntBytes(t, 2)...)
		payload = append(payload, varIntBytes(t, uint64(math.MaxUint32-1))...)
		payload = append(payload, txBuf.Bytes()...)
		payload = append(payload, varIntBytes(t, 1)...)
		payload = append(payload, txBuf.Bytes()...)

		var msg MsgCmpctBlock
		err := msg.Bsvdecode(bytes.NewReader(payload), ProtocolVersion, BaseEncoding)

		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Contains(t, err.Error(), "indexes overflowed 32 bits")
	})
}

// TestMsgCmpctBlockDecodeRejectsTooManyEntries ensures bogus counts are
// rejected before any allocation happens.
func TestMsgCmpctBlockDecodeRejectsTooManyEntries(t *testing.T) {
	var headerBuf bytes.Buffer
	require.NoError(t, writeBlockHeader(&headerBuf, ProtocolVersion, &blockOne.Header))

	t.Run("too many short ids", func(t *testing.T) {
		payload := make([]byte, 0, 128)
		payload = append(payload, headerBuf.Bytes()...)
		payload = binary.LittleEndian.AppendUint64(payload, 1)
		payload = append(payload, varIntBytes(t, maxTxPerBlock()+1)...)

		var msg MsgCmpctBlock
		err := msg.Bsvdecode(bytes.NewReader(payload), ProtocolVersion, BaseEncoding)

		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Contains(t, err.Error(), "too many short ids")
	})

	t.Run("too many prefilled transactions", func(t *testing.T) {
		payload := make([]byte, 0, 128)
		payload = append(payload, headerBuf.Bytes()...)
		payload = binary.LittleEndian.AppendUint64(payload, 1)
		payload = append(payload, varIntBytes(t, 0)...)
		payload = append(payload, varIntBytes(t, maxTxPerBlock()+1)...)

		var msg MsgCmpctBlock
		err := msg.Bsvdecode(bytes.NewReader(payload), ProtocolVersion, BaseEncoding)

		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Contains(t, err.Error(), "too many prefilled transactions")
	})
}

// TestMsgCmpctBlockBlockTxCount reports the total transaction count the compact
// block describes.
func TestMsgCmpctBlockBlockTxCount(t *testing.T) {
	msg := NewMsgCmpctBlock(&blockOne.Header, 1)
	msg.ShortIDs = []uint64{1, 2, 3}
	require.NoError(t, msg.AddPrefilledTransaction(0, cmpctTestTx(t, 1)))

	assert.Equal(t, 4, msg.BlockTxCount())
}

// TestMsgCmpctBlockMakeEmptyMessage ensures the command dispatches.
func TestMsgCmpctBlockMakeEmptyMessage(t *testing.T) {
	msg, err := makeEmptyMessage(CmdCmpctBlock)
	require.NoError(t, err)
	assert.IsType(t, &MsgCmpctBlock{}, msg)
}
