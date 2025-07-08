package wire

import (
	"bytes"
	"io"
	"testing"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMsgGetCFiltersDefaultValues tests the creation of a MsgGetCFilters
func TestNewMsgGetCFiltersDefaultValues(t *testing.T) {
	pver := ProtocolVersion

	stopHash, err := chainhash.NewHashFromStr("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)

	msg := NewMsgGetCFilters(GCSFilterRegular, 10, stopHash)

	require.Equal(t, GCSFilterRegular, msg.FilterType)
	require.Equal(t, uint32(10), msg.StartHeight)
	require.True(t, msg.StopHash.IsEqual(stopHash))

	assert.Equal(t, CmdGetCFilters, msg.Command())
	assert.Equal(t, uint64(1+4+chainhash.HashSize), msg.MaxPayloadLength(pver))
}

// TestMsgGetCFiltersEncodeDecode tests the encoding and decoding of MsgGetCFilters
func TestMsgGetCFiltersEncodeDecode(t *testing.T) {
	pver := ProtocolVersion

	stopHash := chainhash.Hash{}
	msg := NewMsgGetCFilters(GCSFilterRegular, 5, &stopHash)

	var buf bytes.Buffer
	require.NoError(t, msg.BsvEncode(&buf, pver, BaseEncoding))

	var decoded MsgGetCFilters
	require.NoError(t, decoded.Bsvdecode(bytes.NewReader(buf.Bytes()), pver, BaseEncoding))
	assert.Equal(t, msg, &decoded)
}

// TestMsgGetCFiltersEncodeDecodeErrors tests the error handling during encoding and decoding
func TestMsgGetCFiltersEncodeDecodeErrors(t *testing.T) {
	pver := ProtocolVersion
	stopHash := chainhash.Hash{}
	msg := NewMsgGetCFilters(GCSFilterRegular, 1, &stopHash)

	var good bytes.Buffer
	require.NoError(t, msg.BsvEncode(&good, pver, BaseEncoding))
	encoded := good.Bytes()

	tests := []struct {
		name     string
		max      int
		writeErr error
		readErr  error
	}{
		{"short filter type", 0, io.ErrShortWrite, io.EOF},
		{"short start height", 1, io.ErrShortWrite, io.EOF},
		{"short stop hash", 5, io.ErrShortWrite, io.EOF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newFixedWriter(tt.max)
			err := msg.BsvEncode(w, pver, BaseEncoding)
			require.ErrorIs(t, err, tt.writeErr)

			r := newFixedReader(tt.max, encoded)
			var dec MsgGetCFilters
			err = dec.Bsvdecode(r, pver, BaseEncoding)
			require.ErrorIs(t, err, tt.readErr)
		})
	}
}
