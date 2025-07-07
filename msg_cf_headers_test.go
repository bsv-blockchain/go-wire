package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
	"github.com/stretchr/testify/suite"
)

// CFHeadersTestSuite is a test suite for the MsgCFHeaders message type.
type CFHeadersTestSuite struct {
	suite.Suite

	pver uint32
}

// SetupSuite initializes the protocol version for the test suite.
func (s *CFHeadersTestSuite) SetupSuite() {
	s.pver = ProtocolVersion
}

// TestNewMsgCFHeadersDefaultProperties tests that the NewMsgCFHeaders function
func (s *CFHeadersTestSuite) TestNewMsgCFHeadersDefaultProperties() {
	msg := NewMsgCFHeaders()
	expectedPayload := uint64(1 + chainhash.HashSize + chainhash.HashSize + MaxVarIntPayload + (MaxCFHeaderPayload * MaxCFHeadersPerMsg))

	s.Equal(CmdCFHeaders, msg.Command())
	s.Equal(expectedPayload, msg.MaxPayloadLength(s.pver))
	s.Require().Equal(MaxCFHeadersPerMsg, cap(msg.FilterHashes))
}

// TestAddCFHashLimitEnforced tests that the AddCFHash method enforces the maximum
func (s *CFHeadersTestSuite) TestAddCFHashLimitEnforced() {
	hash := &chainhash.Hash{}

	s.Run("within limit", func() {
		msg := NewMsgCFHeaders()
		s.Require().NoError(msg.AddCFHash(hash))
		s.Len(msg.FilterHashes, 1)
		s.True(msg.FilterHashes[0].IsEqual(hash))
	})

	s.Run("exceeds limit", func() {
		msg := NewMsgCFHeaders()
		for i := 0; i < MaxCFHeadersPerMsg; i++ {
			s.Require().NoError(msg.AddCFHash(hash))
		}
		err := msg.AddCFHash(hash)
		s.Error(err)
	})
}

// TestCFHeadersEncodeDecode tests encoding and decoding of MsgCFHeaders
func (s *CFHeadersTestSuite) TestCFHeadersEncodeDecode() {
	stopHash, err := chainhash.NewHashFromStr("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	s.Require().NoError(err)

	prevHash, err := chainhash.NewHashFromStr("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	s.Require().NoError(err)

	h1, err := chainhash.NewHashFromStr("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	s.Require().NoError(err)

	h2, err := chainhash.NewHashFromStr("f1f2f3f4f5f6f7f8f9fafbfcfdfeff00112233445566778899aabbccddeeff00")
	s.Require().NoError(err)

	msg := NewMsgCFHeaders()
	msg.FilterType = GCSFilterRegular
	msg.StopHash = *stopHash
	msg.PrevFilterHeader = *prevHash
	s.Require().NoError(msg.AddCFHash(h1))
	s.Require().NoError(msg.AddCFHash(h2))

	var buf bytes.Buffer
	s.Require().NoError(msg.BsvEncode(&buf, s.pver, BaseEncoding))

	s.Run("decode", func() {
		var decoded MsgCFHeaders
		s.Require().NoError(decoded.Bsvdecode(bytes.NewReader(buf.Bytes()), s.pver, BaseEncoding))
		s.Equal(msg, &decoded)
	})

	s.Run("deserialize", func() {
		var deser MsgCFHeaders
		s.Require().NoError(deser.Deserialize(bytes.NewReader(buf.Bytes())))
		s.Equal(msg, &deser)
	})
}

// TestCFHeadersErrors tests various error conditions for encoding and decoding
func (s *CFHeadersTestSuite) TestCFHeadersErrors() {
	hash := &chainhash.Hash{}
	baseMsg := NewMsgCFHeaders()
	s.Require().NoError(baseMsg.AddCFHash(hash))
	var baseBuf bytes.Buffer
	s.Require().NoError(baseMsg.BsvEncode(&baseBuf, s.pver, BaseEncoding))

	maxMsg := NewMsgCFHeaders()
	for i := 0; i < MaxCFHeadersPerMsg; i++ {
		s.Require().NoError(maxMsg.AddCFHash(hash))
	}
	maxMsg.FilterHashes = append(maxMsg.FilterHashes, hash)
	var maxBuf bytes.Buffer
	s.Require().NoError(writeElement(&maxBuf, maxMsg.FilterType))
	s.Require().NoError(writeElement(&maxBuf, maxMsg.StopHash))
	s.Require().NoError(writeElement(&maxBuf, maxMsg.PrevFilterHeader))
	s.Require().NoError(WriteVarInt(&maxBuf, s.pver, uint64(len(maxMsg.FilterHashes))))
	for range maxMsg.FilterHashes {
		s.Require().NoError(writeElement(&maxBuf, hash))
	}

	tests := []struct {
		name     string
		in       *MsgCFHeaders
		buf      []byte
		max      int
		writeErr error
		readErr  error
	}{
		{"short write", baseMsg, baseBuf.Bytes(), 0, io.ErrShortWrite, io.EOF},
		{"unexpected EOF", baseMsg, baseBuf.Bytes(), len(baseBuf.Bytes()) - 1, io.ErrShortWrite, io.ErrUnexpectedEOF},
		{"too many headers", maxMsg, maxBuf.Bytes(), len(maxBuf.Bytes()), &MessageError{}, &MessageError{}},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			w := newFixedWriter(tc.max)
			err := tc.in.BsvEncode(w, s.pver, BaseEncoding)
			var msgErr *MessageError
			if errors.As(tc.writeErr, &msgErr) {
				var mErr *MessageError
				s.Require().ErrorAs(err, &mErr)
			}

			r := newFixedReader(tc.max, tc.buf)
			var decoded MsgCFHeaders
			err = decoded.Bsvdecode(r, s.pver, BaseEncoding)
			if errors.As(tc.readErr, &msgErr) {
				var mErr *MessageError
				s.ErrorAs(err, &mErr)
			}
		})
	}
}

// TestCFHeadersSuite runs the CFHeadersTestSuite.
func TestCFHeadersSuite(t *testing.T) {
	suite.Run(t, new(CFHeadersTestSuite))
}
