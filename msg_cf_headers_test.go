package wire

import (
	"bytes"
	"io"
	"testing"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type CFHeadersTestSuite struct {
	suite.Suite
	pver uint32
}

func (s *CFHeadersTestSuite) SetupSuite() {
	s.pver = ProtocolVersion
}

func (s *CFHeadersTestSuite) TestNewMsgCFHeaders_DefaultProperties() {
	msg := NewMsgCFHeaders()
	expectedPayload := uint64(1 + chainhash.HashSize + chainhash.HashSize + MaxVarIntPayload + (MaxCFHeaderPayload * MaxCFHeadersPerMsg))

	assert.Equal(s.T(), CmdCFHeaders, msg.Command())
	assert.Equal(s.T(), expectedPayload, msg.MaxPayloadLength(s.pver))
	require.Equal(s.T(), MaxCFHeadersPerMsg, cap(msg.FilterHashes))
}

func (s *CFHeadersTestSuite) TestAddCFHash_LimitEnforced() {
	hash := &chainhash.Hash{}

	s.Run("within limit", func() {
		msg := NewMsgCFHeaders()
		require.NoError(s.T(), msg.AddCFHash(hash))
		require.Len(s.T(), msg.FilterHashes, 1)
		assert.True(s.T(), msg.FilterHashes[0].IsEqual(hash))
	})

	s.Run("exceeds limit", func() {
		msg := NewMsgCFHeaders()
		for i := 0; i < MaxCFHeadersPerMsg; i++ {
			require.NoError(s.T(), msg.AddCFHash(hash))
		}
		err := msg.AddCFHash(hash)
		assert.Error(s.T(), err)
	})
}

func (s *CFHeadersTestSuite) TestCFHeaders_EncodeDecode() {
	stopHash, err := chainhash.NewHashFromStr("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	require.NoError(s.T(), err)
	prevHash, err := chainhash.NewHashFromStr("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	require.NoError(s.T(), err)
	h1, err := chainhash.NewHashFromStr("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(s.T(), err)
	h2, err := chainhash.NewHashFromStr("f1f2f3f4f5f6f7f8f9fafbfcfdfeff00112233445566778899aabbccddeeff00")
	require.NoError(s.T(), err)

	msg := NewMsgCFHeaders()
	msg.FilterType = GCSFilterRegular
	msg.StopHash = *stopHash
	msg.PrevFilterHeader = *prevHash
	require.NoError(s.T(), msg.AddCFHash(h1))
	require.NoError(s.T(), msg.AddCFHash(h2))

	var buf bytes.Buffer
	require.NoError(s.T(), msg.BsvEncode(&buf, s.pver, BaseEncoding))

	s.Run("decode", func() {
		var decoded MsgCFHeaders
		require.NoError(s.T(), decoded.Bsvdecode(bytes.NewReader(buf.Bytes()), s.pver, BaseEncoding))
		assert.Equal(s.T(), msg, &decoded)
	})

	s.Run("deserialize", func() {
		var deser MsgCFHeaders
		require.NoError(s.T(), deser.Deserialize(bytes.NewReader(buf.Bytes())))
		assert.Equal(s.T(), msg, &deser)
	})
}

func (s *CFHeadersTestSuite) TestCFHeaders_Errors() {
	hash := &chainhash.Hash{}
	baseMsg := NewMsgCFHeaders()
	require.NoError(s.T(), baseMsg.AddCFHash(hash))
	var baseBuf bytes.Buffer
	require.NoError(s.T(), baseMsg.BsvEncode(&baseBuf, s.pver, BaseEncoding))

	maxMsg := NewMsgCFHeaders()
	for i := 0; i < MaxCFHeadersPerMsg; i++ {
		require.NoError(s.T(), maxMsg.AddCFHash(hash))
	}
	maxMsg.FilterHashes = append(maxMsg.FilterHashes, hash)
	var maxBuf bytes.Buffer
	require.NoError(s.T(), writeElement(&maxBuf, maxMsg.FilterType))
	require.NoError(s.T(), writeElement(&maxBuf, maxMsg.StopHash))
	require.NoError(s.T(), writeElement(&maxBuf, maxMsg.PrevFilterHeader))
	require.NoError(s.T(), WriteVarInt(&maxBuf, s.pver, uint64(len(maxMsg.FilterHashes))))
	for range maxMsg.FilterHashes {
		require.NoError(s.T(), writeElement(&maxBuf, hash))
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
			if _, ok := tc.writeErr.(*MessageError); ok {
				var merr *MessageError
				assert.ErrorAs(s.T(), err, &merr)
			} else {
				assert.ErrorIs(s.T(), err, tc.writeErr)
			}

			r := newFixedReader(tc.max, tc.buf)
			var decoded MsgCFHeaders
			err = decoded.Bsvdecode(r, s.pver, BaseEncoding)
			if _, ok := tc.readErr.(*MessageError); ok {
				var merr *MessageError
				assert.ErrorAs(s.T(), err, &merr)
			} else {
				assert.ErrorIs(s.T(), err, tc.readErr)
			}
		})
	}
}

func TestCFHeadersSuite(t *testing.T) {
	suite.Run(t, new(CFHeadersTestSuite))
}
