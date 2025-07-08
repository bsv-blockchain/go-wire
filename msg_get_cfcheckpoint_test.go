package wire

import (
	"bytes"
	"io"
	"testing"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMsgGetCFCheckptInitializesFields ensures the constructor initializes all fields.
func TestNewMsgGetCFCheckptInitializesFields(t *testing.T) {
	stop := &chainhash.Hash{}
	msg := NewMsgGetCFCheckpt(GCSFilterRegular, stop)

	assert.Equal(t, GCSFilterRegular, msg.FilterType)
	assert.Equal(t, *stop, msg.StopHash)
}

// TestMsgGetCFCheckptCommand verifies the command string matches the spec.
func TestMsgGetCFCheckptCommand(t *testing.T) {
	msg := &MsgGetCFCheckpt{}
	assert.Equal(t, CmdGetCFCheckpt, msg.Command())
}

// TestMsgGetCFCheckptMaxPayloadLength checks the payload size is fixed.
func TestMsgGetCFCheckptMaxPayloadLength(t *testing.T) {
	msg := &MsgGetCFCheckpt{}
	expected := uint64(1 + chainhash.HashSize)
	assert.Equal(t, expected, msg.MaxPayloadLength(ProtocolVersion))
}

// TestMsgGetCFCheckptEncodeDecode exercises encode/decode round trips.
func TestMsgGetCFCheckptEncodeDecode(t *testing.T) {
	hashStr := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	stopHash, err := chainhash.NewHashFromStr(hashStr)
	require.NoError(t, err)

	msg := NewMsgGetCFCheckpt(GCSFilterRegular, stopHash)

	var buf bytes.Buffer
	require.NoError(t, msg.BsvEncode(&buf, ProtocolVersion, BaseEncoding))

	expected := append([]byte{byte(GCSFilterRegular)}, stopHash[:]...)
	assert.Equal(t, expected, buf.Bytes())

	var decoded MsgGetCFCheckpt
	require.NoError(t, decoded.Bsvdecode(bytes.NewReader(buf.Bytes()), ProtocolVersion, BaseEncoding))
	assert.Equal(t, msg, &decoded)
}

// TestMsgGetCFCheckptEncodeDecodeErrors tests the error handling during encoding and decoding.
func TestMsgGetCFCheckptEncodeDecodeErrors(t *testing.T) {
	stop := &chainhash.Hash{}
	msg := NewMsgGetCFCheckpt(GCSFilterRegular, stop)

	var good bytes.Buffer
	require.NoError(t, msg.BsvEncode(&good, ProtocolVersion, BaseEncoding))
	encoded := good.Bytes()

	tests := []struct {
		name     string
		max      int
		writeErr error
		readErr  error
	}{
		{"short writer filter type", 0, io.ErrShortWrite, io.EOF},
		{"short writer stop hash", 1, io.ErrShortWrite, io.EOF},
		{"unexpected EOF", len(encoded) - 1, io.ErrShortWrite, io.ErrUnexpectedEOF},
	}

	t.Logf(runningTestsFmt, len(tests))

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newFixedWriter(tc.max)
			err := msg.BsvEncode(w, ProtocolVersion, BaseEncoding)
			require.Error(t, err)
			require.ErrorIs(t, err, tc.writeErr)

			r := newFixedReader(tc.max, encoded)
			var decoded MsgGetCFCheckpt
			err = decoded.Bsvdecode(r, ProtocolVersion, BaseEncoding)
			require.Error(t, err)
			require.ErrorIs(t, err, tc.readErr)
		})
	}
}
