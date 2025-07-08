package wire

import (
	"bytes"
	"errors"
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

// assertWireError encodes a message using a fixed-size writer and decodes it
// using a fixed-size reader to force errors. It verifies the returned errors
// match the expected write and read errors respectively.
func assertWireError(t *testing.T, in, out Message, buf []byte, pver uint32,
	enc MessageEncoding, maxInt int, wantWriteErr, wantReadErr error,
) {
	t.Helper()

	w := newFixedWriter(maxInt)
	err := in.BsvEncode(w, pver, enc)
	assert.Equal(t, reflect.TypeOf(wantWriteErr), reflect.TypeOf(err),
		"unexpected encode error type")
	var msgError *MessageError
	if !errors.As(err, &msgError) {
		require.ErrorIs(t, err, wantWriteErr)
	}

	r := newFixedReader(maxInt, buf)
	err = out.Bsvdecode(r, pver, enc)
	assert.Equal(t, reflect.TypeOf(wantReadErr), reflect.TypeOf(err),
		"unexpected decode error type")
	if !errors.As(err, &msgError) {
		require.ErrorIs(t, err, wantReadErr)
	}
}
