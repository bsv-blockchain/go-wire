package wire

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMsgExtMsgLatest tests the latest version of the MsgExtMsg message type.
func TestMsgExtMsgLatest(t *testing.T) {
	const recvLen uint64 = 12345
	msg := NewMsgExtMsg(recvLen)

	require.Equal(t, CmdProtoconf, msg.Command())
	require.Equal(t, uint64(1), msg.NumberOfFields)
	require.Equal(t, recvLen, msg.MaxRecvPayloadLength)
	require.Equal(t, uint64(MaxProtoconfPayload), msg.MaxPayloadLength(ProtocolVersion))

	var b bytes.Buffer
	require.NoError(t, msg.BsvEncode(&b, ProtocolVersion, BaseEncoding))
	require.Equal(t, "01000000000000003930000000000000", hex.EncodeToString(b.Bytes()))

	require.NoError(t, msg.Bsvdecode(bytes.NewReader(nil), ProtocolVersion, BaseEncoding))
}

// TestMsgExtMsgCrossProtocol tests the MsgExtMsg message type
func TestMsgExtMsgCrossProtocol(t *testing.T) {
	msg := NewMsgExtMsg(1)
	oldPver := ProtoconfVersion - 1

	require.Error(t, msg.BsvEncode(io.Discard, oldPver, BaseEncoding))
	require.Error(t, msg.Bsvdecode(bytes.NewReader(nil), oldPver, BaseEncoding))
}

// TestMsgExtMsgWireErrors tests error handling for MsgExtMsg encoding and decoding.
func TestMsgExtMsgWireErrors(t *testing.T) {
	msg := NewMsgExtMsg(1)

	err := msg.BsvEncode(newFixedWriter(0), ProtocolVersion, BaseEncoding)
	require.ErrorIs(t, err, io.ErrShortWrite)
}
