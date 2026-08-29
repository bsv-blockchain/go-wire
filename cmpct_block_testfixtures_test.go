package wire

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// cmpctTestTx returns a distinct, fully-formed transaction for use in the
// BIP152 message tests. The version varies so that round-trip comparisons
// detect a transaction that lands at the wrong position.
func cmpctTestTx(t *testing.T, version int32) *MsgTx {
	t.Helper()

	tx := blockOne.Transactions[0].Copy()
	tx.Version = version

	return tx
}

// encodeMsg encodes a message and returns the raw payload bytes.
func encodeMsg(t *testing.T, msg Message) []byte {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, msg.BsvEncode(&buf, ProtocolVersion, BaseEncoding))

	return buf.Bytes()
}

// varIntBytes returns the variable length integer encoding of val.
func varIntBytes(t *testing.T, val uint64) []byte {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, WriteVarInt(&buf, ProtocolVersion, val))

	return buf.Bytes()
}
