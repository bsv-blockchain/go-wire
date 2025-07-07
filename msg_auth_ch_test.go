package wire

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMsgAuthchSetsFields verifies the constructor and basic accessors.
func TestNewMsgAuthchSetsFields(t *testing.T) {
	msg := NewMsgAuthch("hello")

	assert.Equal(t, int32(1), msg.Version)
	assert.Equal(t, uint32(5), msg.Length)
	assert.Equal(t, []byte("hello"), msg.Challenge)
	assert.Equal(t, CmdAuthch, msg.Command())
	assert.Equal(t, uint64(40), msg.MaxPayloadLength(ProtocolVersion))
}

// TestMsgAuthchWire tests encode and decode round trip.
func TestMsgAuthchWire(t *testing.T) {
	orig := NewMsgAuthch("challenge")
	var buf bytes.Buffer
	require.NoError(t, orig.BsvEncode(&buf, ProtocolVersion, BaseEncoding))

	var decoded MsgAuthch
	require.NoError(t, decoded.Bsvdecode(&buf, ProtocolVersion, BaseEncoding))

	assert.Equal(t, orig.Version, decoded.Version)
	assert.Equal(t, uint32(len(decoded.Challenge)), decoded.Length) //nolint:gosec // G115 Conversion
	assert.NotEmpty(t, decoded.Challenge)
}

// TestMsgAuthchWireErrors exercises error paths for encoding and decoding.
func TestMsgAuthchWireErrors(t *testing.T) {
	base := NewMsgAuthch("abcde")
	var b bytes.Buffer
	require.NoError(t, base.BsvEncode(&b, ProtocolVersion, BaseEncoding))
	encoded := b.Bytes()

	longMsg := NewMsgAuthch(strings.Repeat("z", 41))
	var bLong bytes.Buffer
	require.NoError(t, longMsg.BsvEncode(&bLong, ProtocolVersion, BaseEncoding))
	longEncoded := bLong.Bytes()

	wireErr := &MessageError{}

	tests := []struct {
		name     string
		in       *MsgAuthch
		buf      []byte
		max      int
		writeErr error
		readErr  error
	}{
		{
			name:     "short write version",
			in:       base,
			buf:      encoded,
			max:      0,
			writeErr: io.ErrShortWrite,
			readErr:  io.EOF,
		},
		{
			name:     "short write length",
			in:       base,
			buf:      encoded,
			max:      4,
			writeErr: io.ErrShortWrite,
			readErr:  io.EOF,
		},
		{
			name:     "short write challenge",
			in:       base,
			buf:      encoded,
			max:      8,
			writeErr: io.ErrShortWrite,
			readErr:  io.ErrUnexpectedEOF,
		},
		{
			name:     "challenge too large",
			in:       longMsg,
			buf:      longEncoded,
			max:      len(longEncoded),
			writeErr: nil,
			readErr:  wireErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newFixedWriter(tt.max)
			err := tt.in.BsvEncode(w, ProtocolVersion, BaseEncoding)
			if tt.writeErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.writeErr)
			} else {
				require.NoError(t, err)
			}

			var msg MsgAuthch
			r := newFixedReader(tt.max, tt.buf)
			err = msg.Bsvdecode(r, ProtocolVersion, BaseEncoding)
			if tt.readErr != nil {
				require.Error(t, err)
				var mErr *MessageError
				if errors.As(tt.readErr, &mErr) {
					assert.IsType(t, mErr, err)
				} else {
					assert.ErrorIs(t, err, tt.readErr)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
