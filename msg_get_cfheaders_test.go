package wire

import (
	"bytes"
	"io"
	"testing"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMsgGetCFHeaders_SetsFields ensures the constructor initializes all fields.
func TestNewMsgGetCFHeaders_SetsFields(t *testing.T) {
	stopHash, err := chainhash.NewHashFromStr("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)

	msg := NewMsgGetCFHeaders(GCSFilterRegular, 5, stopHash)

	assert.Equal(t, GCSFilterRegular, msg.FilterType)
	assert.Equal(t, uint32(5), msg.StartHeight)
	assert.True(t, msg.StopHash.IsEqual(stopHash))
}

// TestMsgGetCFHeaders_Command verifies the command string matches the spec.
func TestMsgGetCFHeaders_Command(t *testing.T) {
	msg := NewMsgGetCFHeaders(GCSFilterRegular, 0, &chainhash.Hash{})

	assert.Equal(t, CmdGetCFHeaders, msg.Command())
}

// TestMsgGetCFHeaders_MaxPayloadLength checks the payload size is fixed.
func TestMsgGetCFHeaders_MaxPayloadLength(t *testing.T) {
	msg := NewMsgGetCFHeaders(GCSFilterRegular, 0, &chainhash.Hash{})

	expected := uint64(1 + 4 + chainhash.HashSize)
	assert.Equal(t, expected, msg.MaxPayloadLength(ProtocolVersion))
}

// TestMsgGetCFHeaders_EncodeDecode exercises encode/decode round trips.
func TestMsgGetCFHeaders_EncodeDecode(t *testing.T) {
	stopHash, err := chainhash.NewHashFromStr("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	require.NoError(t, err)

	msg := NewMsgGetCFHeaders(GCSFilterRegular, 100, stopHash)

	var buf bytes.Buffer
	require.NoError(t, msg.BsvEncode(&buf, ProtocolVersion, BaseEncoding))

	var expected bytes.Buffer
	require.NoError(t, writeElement(&expected, msg.FilterType))
	require.NoError(t, writeElement(&expected, &msg.StartHeight))
	require.NoError(t, writeElement(&expected, &msg.StopHash))
	assert.Equal(t, expected.Bytes(), buf.Bytes())

	var decoded MsgGetCFHeaders
	require.NoError(t, decoded.Bsvdecode(bytes.NewReader(buf.Bytes()), ProtocolVersion, BaseEncoding))
	assert.Equal(t, msg, &decoded)
}

// TestMsgGetCFHeaders_WireErrors verifies error paths during encode and decode.
func TestMsgGetCFHeaders_WireErrors(t *testing.T) {
	stopHash := &chainhash.Hash{}
	baseMsg := NewMsgGetCFHeaders(GCSFilterRegular, 1, stopHash)
	var baseBuf bytes.Buffer
	require.NoError(t, baseMsg.BsvEncode(&baseBuf, ProtocolVersion, BaseEncoding))
	encoded := baseBuf.Bytes()

	tests := []struct {
		name     string
		max      int
		writeErr error
		readErr  error
	}{
		{"filter type", 0, io.ErrShortWrite, io.EOF},
		{"start height", 1, io.ErrShortWrite, io.EOF},
		{"stop hash", 5, io.ErrShortWrite, io.EOF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newFixedWriter(tt.max)
			err := baseMsg.BsvEncode(w, ProtocolVersion, BaseEncoding)
			require.ErrorIs(t, err, tt.writeErr)

			r := newFixedReader(tt.max, encoded)
			var msg MsgGetCFHeaders
			err = msg.Bsvdecode(r, ProtocolVersion, BaseEncoding)
			require.ErrorIs(t, err, tt.readErr)
		})
	}
}
