package wire

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// FuzzVarIntRoundTrip ensures encoding and then decoding a variable length
// integer yields the original value.
func FuzzVarIntRoundTrip(f *testing.F) {
	seed := []uint64{0, 1, 0xfc, 0xfd, 0xffff, 0x10000, 0xffffffff, 0x100000000, 0xffffffffffffffff}
	for _, v := range seed {
		f.Add(v)
	}

	f.Fuzz(func(t *testing.T, val uint64) {
		var buf bytes.Buffer
		require.NoError(t, WriteVarInt(&buf, ProtocolVersion, val))

		out, err := ReadVarInt(bytes.NewReader(buf.Bytes()), ProtocolVersion)
		require.NoError(t, err)
		require.Equal(t, val, out)
	})
}
