package wire

import (
	"bytes"
	"math"
	"testing"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMsgGetBlockTxnCommand ensures the command string is correct.
func TestMsgGetBlockTxnCommand(t *testing.T) {
	msg := NewMsgGetBlockTxn(&blockOne.Header.PrevBlock, nil)

	assert.Equal(t, CmdGetBlockTxn, msg.Command())
	assert.Equal(t, "getblocktxn", msg.Command())
}

// TestMsgGetBlockTxnMaxPayloadLength checks the advertised payload ceiling.
func TestMsgGetBlockTxnMaxPayloadLength(t *testing.T) {
	msg := NewMsgGetBlockTxn(&blockOne.Header.PrevBlock, nil)

	want := uint64(chainhash.HashSize) + MaxVarIntPayload + MaxVarIntPayload*maxTxPerBlock()
	if want > maxMessagePayload() {
		want = maxMessagePayload()
	}

	assert.Equal(t, want, msg.MaxPayloadLength(ProtocolVersion))
	assert.LessOrEqual(t, msg.MaxPayloadLength(ProtocolVersion), maxMessagePayload())
}

// TestMsgGetBlockTxnRoundTrip exercises encode/decode round trips.
func TestMsgGetBlockTxnRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		indexes []uint32
	}{
		{name: "no indexes", indexes: []uint32{}},
		{name: "single index zero", indexes: []uint32{0}},
		{name: "single index high", indexes: []uint32{123456}},
		{name: "contiguous run", indexes: []uint32{0, 1, 2}},
		{name: "sparse run", indexes: []uint32{5, 7}},
		{name: "many indexes", indexes: sequentialIndexes(2500)},
		{name: "near uint32 max", indexes: []uint32{math.MaxUint32 - 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := NewMsgGetBlockTxn(&blockOne.Header.PrevBlock, tt.indexes)

			var decoded MsgGetBlockTxn
			buf := bytes.NewReader(encodeMsg(t, msg))
			require.NoError(t, decoded.Bsvdecode(buf, ProtocolVersion, BaseEncoding))

			assert.Equal(t, msg.BlockHash, decoded.BlockHash)
			assert.Equal(t, tt.indexes, decoded.Indexes)
		})
	}
}

// TestMsgGetBlockTxnDifferentialWire pins the exact differential index encoding
// described in blockencodings.h (BlockTransactionsRequest).
func TestMsgGetBlockTxnDifferentialWire(t *testing.T) {
	tests := []struct {
		name     string
		indexes  []uint32
		wantWire []uint64
	}{
		{name: "contiguous from zero", indexes: []uint32{0, 1, 2}, wantWire: []uint64{0, 0, 0}},
		{name: "sparse", indexes: []uint32{5, 7}, wantWire: []uint64{5, 1}},
		{name: "single", indexes: []uint32{9}, wantWire: []uint64{9}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := NewMsgGetBlockTxn(&blockOne.Header.PrevBlock, tt.indexes)

			want := make([]byte, 0, 64)
			want = append(want, blockOne.Header.PrevBlock[:]...)
			want = append(want, varIntBytes(t, uint64(len(tt.indexes)))...)

			for _, v := range tt.wantWire {
				want = append(want, varIntBytes(t, v)...)
			}

			assert.Equal(t, want, encodeMsg(t, msg))
		})
	}
}

// TestMsgGetBlockTxnEncodeRejectsNonMonotonic ensures the encoder refuses index
// lists that are not strictly increasing, because the differential encoding
// cannot represent them.
func TestMsgGetBlockTxnEncodeRejectsNonMonotonic(t *testing.T) {
	tests := []struct {
		name    string
		indexes []uint32
	}{
		{name: "repeated index", indexes: []uint32{3, 3}},
		{name: "decreasing index", indexes: []uint32{7, 5}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := NewMsgGetBlockTxn(&blockOne.Header.PrevBlock, tt.indexes)

			var buf bytes.Buffer
			err := msg.BsvEncode(&buf, ProtocolVersion, BaseEncoding)

			var msgErr *MessageError
			require.ErrorAs(t, err, &msgErr)
			assert.Contains(t, err.Error(), "non-strictly-monotonic")
		})
	}
}

// TestMsgGetBlockTxnDecodeRejectsOverflow ensures a differential index that
// pushes the running index past 32 bits is rejected, mirroring the C++ throw.
func TestMsgGetBlockTxnDecodeRejectsOverflow(t *testing.T) {
	t.Run("single index above uint32", func(t *testing.T) {
		payload := make([]byte, 0, 64)
		payload = append(payload, blockOne.Header.PrevBlock[:]...)
		payload = append(payload, varIntBytes(t, 1)...)
		payload = append(payload, varIntBytes(t, uint64(math.MaxUint32)+1)...)

		var msg MsgGetBlockTxn
		err := msg.Bsvdecode(bytes.NewReader(payload), ProtocolVersion, BaseEncoding)

		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Contains(t, err.Error(), "index overflowed 32 bits")
	})

	t.Run("accumulated index above uint32", func(t *testing.T) {
		payload := make([]byte, 0, 64)
		payload = append(payload, blockOne.Header.PrevBlock[:]...)
		payload = append(payload, varIntBytes(t, 2)...)
		payload = append(payload, varIntBytes(t, uint64(math.MaxUint32-1))...)
		payload = append(payload, varIntBytes(t, 1)...)

		var msg MsgGetBlockTxn
		err := msg.Bsvdecode(bytes.NewReader(payload), ProtocolVersion, BaseEncoding)

		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Contains(t, err.Error(), "indexes overflowed 32 bits")
	})
}

// TestMsgGetBlockTxnDecodeRejectsTooManyIndexes ensures a bogus count is
// rejected before any allocation happens.
func TestMsgGetBlockTxnDecodeRejectsTooManyIndexes(t *testing.T) {
	payload := make([]byte, 0, 64)
	payload = append(payload, blockOne.Header.PrevBlock[:]...)
	payload = append(payload, varIntBytes(t, maxTxPerBlock()+1)...)

	var msg MsgGetBlockTxn
	err := msg.Bsvdecode(bytes.NewReader(payload), ProtocolVersion, BaseEncoding)

	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Contains(t, err.Error(), "too many transaction indexes")
}

// TestMsgGetBlockTxnMakeEmptyMessage ensures the command dispatches.
func TestMsgGetBlockTxnMakeEmptyMessage(t *testing.T) {
	msg, err := makeEmptyMessage(CmdGetBlockTxn)
	require.NoError(t, err)
	assert.IsType(t, &MsgGetBlockTxn{}, msg)
}

// sequentialIndexes returns n strictly increasing indexes with gaps.
func sequentialIndexes(n int) []uint32 {
	indexes := make([]uint32, n)
	for i := range indexes {
		indexes[i] = uint32(i) * 3
	}

	return indexes
}
