package wire

import "testing"

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
