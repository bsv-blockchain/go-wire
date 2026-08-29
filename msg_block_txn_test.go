package wire

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMsgBlockTxnCommand ensures the command string is correct.
func TestMsgBlockTxnCommand(t *testing.T) {
	msg := NewMsgBlockTxn(&blockOne.Header.PrevBlock)

	assert.Equal(t, CmdBlockTxn, msg.Command())
	assert.Equal(t, "blocktxn", msg.Command())
}

// TestMsgBlockTxnMaxPayloadLength checks the advertised payload ceiling.
func TestMsgBlockTxnMaxPayloadLength(t *testing.T) {
	msg := NewMsgBlockTxn(&blockOne.Header.PrevBlock)

	assert.Equal(t, MaxBlockPayload(), msg.MaxPayloadLength(ProtocolVersion))
}

// TestMsgBlockTxnRoundTrip exercises encode/decode round trips.
func TestMsgBlockTxnRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		count int
	}{
		{name: "no transactions", count: 0},
		{name: "one transaction", count: 1},
		{name: "many transactions", count: 6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := NewMsgBlockTxn(&blockOne.Header.PrevBlock)
			for i := 0; i < tt.count; i++ {
				require.NoError(t, msg.AddTransaction(cmpctTestTx(t, int32(i+1))))
			}

			var decoded MsgBlockTxn
			require.NoError(t, decoded.Bsvdecode(bytes.NewReader(encodeMsg(t, msg)),
				ProtocolVersion, BaseEncoding))

			assert.Equal(t, msg.BlockHash, decoded.BlockHash)
			require.Len(t, decoded.Transactions, tt.count)

			for i, tx := range decoded.Transactions {
				assert.Equal(t, int32(i+1), tx.Version)
				assert.Equal(t, msg.Transactions[i].TxHash(), tx.TxHash())
			}
		})
	}
}

// TestMsgBlockTxnWireLayout pins the payload layout: block hash, then a var int
// transaction count, then the transactions in order.
func TestMsgBlockTxnWireLayout(t *testing.T) {
	msg := NewMsgBlockTxn(&blockOne.Header.PrevBlock)
	require.NoError(t, msg.AddTransaction(cmpctTestTx(t, 1)))
	require.NoError(t, msg.AddTransaction(cmpctTestTx(t, 2)))

	want := make([]byte, 0, 512)
	want = append(want, blockOne.Header.PrevBlock[:]...)
	want = append(want, varIntBytes(t, 2)...)

	for _, tx := range msg.Transactions {
		var txBuf bytes.Buffer
		require.NoError(t, tx.BsvEncode(&txBuf, ProtocolVersion, BaseEncoding))
		want = append(want, txBuf.Bytes()...)
	}

	assert.Equal(t, want, encodeMsg(t, msg))
}

// TestMsgBlockTxnDecodeRejectsTooManyTransactions ensures a bogus count is
// rejected before any allocation happens.
func TestMsgBlockTxnDecodeRejectsTooManyTransactions(t *testing.T) {
	payload := make([]byte, 0, 64)
	payload = append(payload, blockOne.Header.PrevBlock[:]...)
	payload = append(payload, varIntBytes(t, maxTxPerBlock()+1)...)

	var msg MsgBlockTxn
	err := msg.Bsvdecode(bytes.NewReader(payload), ProtocolVersion, BaseEncoding)

	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Contains(t, err.Error(), "too many transactions")
}

// TestMsgBlockTxnDecodeTruncated ensures a truncated transaction list fails.
func TestMsgBlockTxnDecodeTruncated(t *testing.T) {
	msg := NewMsgBlockTxn(&blockOne.Header.PrevBlock)
	require.NoError(t, msg.AddTransaction(cmpctTestTx(t, 1)))

	encoded := encodeMsg(t, msg)

	var decoded MsgBlockTxn
	err := decoded.Bsvdecode(bytes.NewReader(encoded[:len(encoded)-5]),
		ProtocolVersion, BaseEncoding)
	require.Error(t, err)
}

// TestMsgBlockTxnMakeEmptyMessage ensures the command dispatches.
func TestMsgBlockTxnMakeEmptyMessage(t *testing.T) {
	msg, err := makeEmptyMessage(CmdBlockTxn)
	require.NoError(t, err)
	assert.IsType(t, &MsgBlockTxn{}, msg)
}
