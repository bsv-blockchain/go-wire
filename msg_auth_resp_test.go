package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMsgAuthrespInitializesFields verifies that the constructor sets all
// fields according to the input values and generates nonce.
func TestNewMsgAuthrespInitializesFields(t *testing.T) {
	pubKey := bytes.Repeat([]byte{0x02}, SECP256K1_COMP_PUB_KEY_SIZE_IN_BYTES)
	sig := bytes.Repeat([]byte{0x03}, SECP256K1_DER_SIGN_MAX_SIZE_IN_BYTES)

	msg := NewMsgAuthresp(pubKey, sig)

	assert.Equal(t, uint32(len(pubKey)), msg.PublicKeyLength) //nolint:gosec // G115 Conversion
	assert.Equal(t, pubKey, msg.PublicKey)
	assert.Equal(t, uint32(len(sig)), msg.SignatureLength) //nolint:gosec // G115 Conversion
	assert.Equal(t, sig, msg.Signature)
	assert.NotZero(t, msg.ClientNonce)
}

// TestMsgAuthrespCommandReturnsAuthresp ensures the Command method reports the
// correct protocol command.
func TestMsgAuthrespCommandReturnsAuthresp(t *testing.T) {
	msg := &MsgAuthresp{}

	assert.Equal(t, CmdAuthresp, msg.Command())
}

// TestMsgAuthrespMaxPayloadLengthCalculatesLimit verifies the maximum payload
// computation.
func TestMsgAuthrespMaxPayloadLengthCalculatesLimit(t *testing.T) {
	msg := &MsgAuthresp{}
	expected := uint64(4 + SECP256K1_COMP_PUB_KEY_SIZE_IN_BYTES + 8 + 4 + SECP256K1_DER_SIGN_MAX_SIZE_IN_BYTES) //nolint:gosec // G115 Conversion

	assert.Equal(t, expected, msg.MaxPayloadLength(ProtocolVersion))
}

// TestMsgAuthrespEncodeDecodeRoundTrip exercises successful encoding and
// decoding of an auth response.
func TestMsgAuthrespEncodeDecodeRoundTrip(t *testing.T) {
	pubKey := bytes.Repeat([]byte{0x02}, SECP256K1_COMP_PUB_KEY_SIZE_IN_BYTES)
	sig := bytes.Repeat([]byte{0x03}, SECP256K1_DER_SIGN_MAX_SIZE_IN_BYTES)
	nonce := uint64(0x0102030405060708)

	msg := NewMsgAuthresp(pubKey, sig)
	msg.ClientNonce = nonce

	var want bytes.Buffer
	require.NoError(t, writeElements(&want, uint32(len(pubKey)), pubKey, nonce, uint32(len(sig)), sig)) //nolint:gosec // G115 Conversion

	var buf bytes.Buffer
	require.NoError(t, msg.BsvEncode(&buf, ProtocolVersion, BaseEncoding))
	assert.Equal(t, want.Bytes(), buf.Bytes())

	var decodeBuf bytes.Buffer
	decodeBuf.WriteByte(byte(len(pubKey)))
	decodeBuf.Write(pubKey)
	require.NoError(t, writeElement(&decodeBuf, nonce))
	decodeBuf.WriteByte(byte(len(sig)))
	decodeBuf.Write(sig)

	var decoded MsgAuthresp
	require.NoError(t, decoded.Bsvdecode(&decodeBuf, ProtocolVersion, BaseEncoding))
	assert.Equal(t, msg.PublicKey, decoded.PublicKey)
	assert.Equal(t, msg.Signature, decoded.Signature)
	assert.Equal(t, msg.ClientNonce, decoded.ClientNonce)
	assert.Equal(t, msg.PublicKeyLength, decoded.PublicKeyLength)
	assert.Equal(t, msg.SignatureLength, decoded.SignatureLength)
}

// TestMsgAuthrespEncodeDecodeErrors exercises error paths when encoding or
// decoding auth responses.
func TestMsgAuthrespEncodeDecodeErrors(t *testing.T) {
	pubKey := bytes.Repeat([]byte{0x02}, SECP256K1_COMP_PUB_KEY_SIZE_IN_BYTES)
	sig := bytes.Repeat([]byte{0x03}, SECP256K1_DER_SIGN_MAX_SIZE_IN_BYTES)

	msg := NewMsgAuthresp(pubKey, sig)

	var decBuf bytes.Buffer
	decBuf.WriteByte(byte(len(pubKey)))
	decBuf.Write(pubKey)
	_ = writeElement(&decBuf, msg.ClientNonce)
	decBuf.WriteByte(byte(len(sig)))
	decBuf.Write(sig)
	decodeBytes := decBuf.Bytes()

	overflow := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	wireErr := &MessageError{}

	cases := []struct {
		name     string
		buf      []byte
		max      int
		writeErr error
		readErr  error
	}{
		{"short writer at zero", decodeBytes, 0, io.ErrShortWrite, io.EOF},
		{"short writer partial", decodeBytes, 2, io.ErrShortWrite, io.ErrUnexpectedEOF},
		{"short reader", decodeBytes, len(decodeBytes) - 1, io.ErrShortWrite, io.ErrUnexpectedEOF},
		{"overflow", overflow, len(overflow), io.ErrShortWrite, wireErr},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := msg.BsvEncode(newFixedWriter(tc.max), ProtocolVersion, BaseEncoding)
			require.Error(t, err)
			require.ErrorIs(t, err, tc.writeErr)

			var readMsg MsgAuthresp
			err = readMsg.Bsvdecode(newFixedReader(tc.max, tc.buf), ProtocolVersion, BaseEncoding)
			require.Error(t, err)
			if errors.As(tc.readErr, &wireErr) {
				var me *MessageError
				assert.ErrorAs(t, err, &me)
			} else {
				assert.ErrorIs(t, err, tc.readErr)
			}
		})
	}
}
