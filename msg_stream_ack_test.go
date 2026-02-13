package wire

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamAck(t *testing.T) {
	pver := ProtocolVersion

	assocID := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
	}
	msg := NewMsgStreamAck(assocID, StreamTypeData1)

	assert.Equal(t, assocID, msg.AssociationID)
	assert.Equal(t, StreamTypeData1, msg.StreamType)

	assertCommand(t, msg, "streamack")

	wantPayload := uint64(MaxVarIntPayload + MaxAssociationIDLen + 1)
	assertMaxPayload(t, msg, pver, wantPayload)

	// Roundtrip
	dst := &MsgStreamAck{}
	assertWireRoundTrip(t, msg, dst, pver, BaseEncoding)
}

func TestStreamAckEncodeDecode(t *testing.T) {
	pver := ProtocolVersion
	enc := BaseEncoding

	assocID := []byte{
		0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
	}

	msg := NewMsgStreamAck(assocID, StreamTypeData1)

	var buf bytes.Buffer
	require.NoError(t, msg.BsvEncode(&buf, pver, enc))

	decoded := &MsgStreamAck{}
	require.NoError(t, decoded.Bsvdecode(&buf, pver, enc))

	assert.Equal(t, msg.AssociationID, decoded.AssociationID)
	assert.Equal(t, msg.StreamType, decoded.StreamType)
}

func TestStreamAckEmptyAssocID(t *testing.T) {
	pver := ProtocolVersion
	enc := BaseEncoding

	// Empty assoc ID is valid for streamack (the field is still encoded as var_bytes)
	msg := NewMsgStreamAck(nil, StreamTypeData1)

	var buf bytes.Buffer
	require.NoError(t, msg.BsvEncode(&buf, pver, enc))

	decoded := &MsgStreamAck{}
	require.NoError(t, decoded.Bsvdecode(&buf, pver, enc))

	assert.Empty(t, decoded.AssociationID)
	assert.Equal(t, StreamTypeData1, decoded.StreamType)
}

func TestStreamAckWireErrors(t *testing.T) {
	pver := ProtocolVersion

	assocID := []byte{0x01, 0x02, 0x03}
	msg := NewMsgStreamAck(assocID, StreamTypeGeneral)

	tests := []struct {
		in       *MsgStreamAck
		buf      []byte
		pver     uint32
		enc      MessageEncoding
		max      int
		writeErr error
		readErr  error
	}{
		// Short write/read at association ID varint.
		{msg, []byte{}, pver, BaseEncoding, 0, io.ErrShortWrite, io.EOF},
	}

	for _, test := range tests {
		assertWireError(t, test.in, &MsgStreamAck{}, test.buf, test.pver,
			test.enc, test.max, test.writeErr, test.readErr)
	}
}

func TestStreamAckMakeEmptyMessage(t *testing.T) {
	msg, err := makeEmptyMessage(CmdStreamAck)
	require.NoError(t, err)
	_, ok := msg.(*MsgStreamAck)
	assert.True(t, ok)
}
