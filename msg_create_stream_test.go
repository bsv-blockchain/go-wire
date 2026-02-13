package wire

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateStream(t *testing.T) {
	pver := ProtocolVersion

	assocID := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
	}
	msg := NewMsgCreateStream(assocID, StreamTypeData1, "BlockPriority")

	assert.Equal(t, assocID, msg.AssociationID)
	assert.Equal(t, StreamTypeData1, msg.StreamType)
	assert.Equal(t, "BlockPriority", msg.StreamPolicyName)

	assertCommand(t, msg, "createstrm")

	wantPayload := uint64(MaxVarIntPayload + MaxAssociationIDLen + 1 + MaxVarIntPayload + MaxUserAgentLen)
	assertMaxPayload(t, msg, pver, wantPayload)

	// Roundtrip
	dst := &MsgCreateStream{}
	assertWireRoundTrip(t, msg, dst, pver, BaseEncoding)
}

func TestCreateStreamEncodeDecode(t *testing.T) {
	pver := ProtocolVersion
	enc := BaseEncoding

	assocID := []byte{
		0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
	}

	msg := NewMsgCreateStream(assocID, StreamTypeData1, "BlockPriority")

	var buf bytes.Buffer
	require.NoError(t, msg.BsvEncode(&buf, pver, enc))

	decoded := &MsgCreateStream{}
	require.NoError(t, decoded.Bsvdecode(&buf, pver, enc))

	assert.Equal(t, msg.AssociationID, decoded.AssociationID)
	assert.Equal(t, msg.StreamType, decoded.StreamType)
	assert.Equal(t, msg.StreamPolicyName, decoded.StreamPolicyName)
}

func TestCreateStreamEmptyAssocID(t *testing.T) {
	pver := ProtocolVersion
	enc := BaseEncoding

	msg := NewMsgCreateStream(nil, StreamTypeData1, "BlockPriority")

	var buf bytes.Buffer
	err := msg.BsvEncode(&buf, pver, enc)
	assert.Error(t, err)
}

func TestCreateStreamLargeAssocID(t *testing.T) {
	pver := ProtocolVersion
	enc := BaseEncoding

	largeID := make([]byte, MaxAssociationIDLen+1)
	msg := NewMsgCreateStream(largeID, StreamTypeData1, "BlockPriority")

	var buf bytes.Buffer
	err := msg.BsvEncode(&buf, pver, enc)
	assert.Error(t, err)
}

func TestCreateStreamWireErrors(t *testing.T) {
	pver := ProtocolVersion

	assocID := []byte{0x01, 0x02, 0x03}
	msg := NewMsgCreateStream(assocID, StreamTypeGeneral, "Default")

	tests := []struct {
		in       *MsgCreateStream
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
		assertWireError(t, test.in, &MsgCreateStream{}, test.buf, test.pver,
			test.enc, test.max, test.writeErr, test.readErr)
	}
}

func TestCreateStreamMakeEmptyMessage(t *testing.T) {
	msg, err := makeEmptyMessage(CmdCreateStream)
	require.NoError(t, err)
	_, ok := msg.(*MsgCreateStream)
	assert.True(t, ok)
}
