package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMsgSendcmpctSetsFields verifies the constructor initializes
// the message with the given value and default version.
func TestNewMsgSendcmpctSetsFields(t *testing.T) {
	msg := NewMsgSendcmpct(true)

	assert.True(t, msg.SendCmpct)
	assert.Equal(t, uint64(1), msg.Version)
}

// TestMsgSendcmpct_Command ensures the command string is correct.
func TestMsgSendcmpctCommand(t *testing.T) {
	msg := NewMsgSendcmpct(false)

	assert.Equal(t, CmdSendcmpct, msg.Command())
}

// TestMsgSendcmpctMaxPayloadLength checks the fixed payload size.
func TestMsgSendcmpctMaxPayloadLength(t *testing.T) {
	msg := NewMsgSendcmpct(true)

	assert.Equal(t, uint64(9), msg.MaxPayloadLength(ProtocolVersion))
}

// TestMsgSendcmpctEncodeDecode exercises encode/decode round trips.
func TestMsgSendcmpctEncodeDecode(t *testing.T) {
	cases := []struct {
		name      string
		sendCmpct bool
	}{
		{name: "sendcmpct true", sendCmpct: true},
		{name: "sendcmpct false", sendCmpct: false},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			msg := NewMsgSendcmpct(tt.sendCmpct)

			var b bytes.Buffer
			require.NoError(t, msg.BsvEncode(&b, ProtocolVersion, BaseEncoding))

			expected := make([]byte, 1, 9)
			if tt.sendCmpct {
				expected[0] = 0x01
			}
			expected = append(expected, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
			assert.Equal(t, expected, b.Bytes())

			var decoded MsgSendcmpct
			require.NoError(t, decoded.Bsvdecode(&b, ProtocolVersion, BaseEncoding))
			assert.Equal(t, msg, &decoded)
		})
	}
}

// TestMsgSendcmpctWireErrors covers error paths during encoding and decoding.
func TestMsgSendcmpctWireErrors(t *testing.T) {
	base := NewMsgSendcmpct(true)
	var buf bytes.Buffer
	require.NoError(t, base.BsvEncode(&buf, ProtocolVersion, BaseEncoding))
	encoded := buf.Bytes()

	wireErr := &MessageError{}

	tests := []struct {
		name     string
		max      int
		writeErr error
		readErr  error
	}{
		{name: "short write bool", max: 0, writeErr: io.ErrShortWrite, readErr: io.EOF},
		{name: "partial version", max: 5, writeErr: io.ErrShortWrite, readErr: io.ErrUnexpectedEOF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newFixedWriter(tt.max)
			err := base.BsvEncode(w, ProtocolVersion, BaseEncoding)
			require.ErrorIs(t, err, tt.writeErr)

			r := newFixedReader(tt.max, encoded)
			var msg MsgSendcmpct
			err = msg.Bsvdecode(r, ProtocolVersion, BaseEncoding)
			if errors.As(tt.readErr, &wireErr) {
				assert.ErrorAs(t, err, &wireErr)
			} else {
				require.ErrorIs(t, err, tt.readErr)
			}
		})
	}
}
