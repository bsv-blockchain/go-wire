package wire

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertCommand verifies that the message command matches the expected value.
func assertCommand(t *testing.T, msg Message, want string) {
	t.Helper()
	if cmd := msg.Command(); cmd != want {
		t.Errorf("%T: wrong command - got %v want %v", msg, cmd, want)
	}
}

// assertMaxPayload verifies the maximum payload for the given protocol version.
func assertMaxPayload(t *testing.T, msg Message, pver uint32, want uint64) {
	t.Helper()
	if got := msg.MaxPayloadLength(pver); got != want {
		t.Errorf("MaxPayloadLength: wrong max payload length for protocol version %d - got %v, want %v", pver, got, want)
	}
}

// assertWireRoundTrip encodes a message and then decodes it into dst, ensuring
// the two are equal.
func assertWireRoundTrip(t *testing.T, src, dst Message, pver uint32, enc MessageEncoding) {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, src.BsvEncode(&buf, pver, enc))
	require.NoError(t, dst.Bsvdecode(&buf, pver, enc))
	assert.True(t, reflect.DeepEqual(src, dst), "round trip mismatch")
}
