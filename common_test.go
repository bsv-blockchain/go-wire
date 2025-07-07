// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
	"github.com/davecgh/go-spew/spew"
)

// mainNetGenesisHash is the hash of the first block in the blockchain for the
// main network (genesis block).
var mainNetGenesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
	0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
	0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
	0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
})

// mainNetGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the main network.
var mainNetGenesisMerkleRoot = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2,
	0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61,
	0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32,
	0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
})

// fakeRandReader implements io.Reader and is used to force errors in RandomUint64.
type fakeRandReader struct {
	n   int
	err error
}

// fixedExcessiveBlockSize should not be the default – we want to ensure it works
// in all cases.
const fixedExcessiveBlockSize uint64 = 42111000

func init() { //nolint:gochecknoinits // this needs to be refactored to be called by tests
	SetLimits(fixedExcessiveBlockSize)
}

// Read reads bytes from the fake reader. It returns n bytes or an error
func (r *fakeRandReader) Read(p []byte) (int, error) {
	if r.n > len(p) {
		return len(p), r.err
	}
	return r.n, r.err
}

// ptrFor ensures we have a pointer to the concrete value behind v.
func ptrFor(v interface{}) interface{} {
	if reflect.TypeOf(v).Kind() == reflect.Ptr {
		return v
	}
	return reflect.New(reflect.TypeOf(v)).Interface()
}

// deref returns the concrete value behind a pointer (or v if already concrete).
func deref(v interface{}) interface{} {
	if reflect.TypeOf(v).Kind() == reflect.Ptr {
		return reflect.Indirect(reflect.ValueOf(v)).Interface()
	}
	return v
}

// roundTripElement encodes `in` with writeElement, checks the bytes and then
// decodes again with readElement.
func roundTripElement(t *testing.T, idx int, in interface{}, want []byte) {
	t.Helper()

	var buf bytes.Buffer
	if err := writeElement(&buf, in); err != nil {
		t.Errorf("writeElement #%d error %v", idx, err)
		return
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("writeElement #%d\n got: %s want: %s",
			idx, spew.Sdump(buf.Bytes()), spew.Sdump(want))
		return
	}

	valPtr := ptrFor(in)
	if err := readElement(bytes.NewReader(want), valPtr); err != nil {
		t.Errorf("readElement #%d error %v", idx, err)
		return
	}
	if !reflect.DeepEqual(deref(valPtr), in) {
		t.Errorf("readElement #%d\n got: %s want: %s",
			idx, spew.Sdump(deref(valPtr)), spew.Sdump(in))
	}
}

// negativeElement forces write/read errors via bounded readers/writers.
func negativeElement(t *testing.T, idx int, maxInt int, in interface{},
	wantWrite, wantRead error,
) {
	t.Helper()

	w := newFixedWriter(maxInt)
	if err := writeElement(w, in); !errors.Is(err, wantWrite) {
		t.Errorf("writeElement #%d wrong error got=%v want=%v",
			idx, err, wantWrite)
	}

	valPtr := ptrFor(in)
	r := newFixedReader(maxInt, nil)
	if err := readElement(r, valPtr); !errors.Is(err, wantRead) {
		t.Errorf("readElement #%d wrong error got=%v want=%v",
			idx, err, wantRead)
	}
}

// roundTripVarInt / VarString / VarBytes collapse the repetitive encode/decode
// pattern for those wire primitives – implementation mirrors roundTripElement.
func roundTripVarInt(t *testing.T, idx int, pver uint32,
	in, out uint64, want []byte,
) {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteVarInt(&buf, pver, in); err != nil {
		t.Errorf("WriteVarInt #%d error %v", idx, err)
		return
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("WriteVarInt #%d\n got: %s want: %s",
			idx, spew.Sdump(buf.Bytes()), spew.Sdump(want))
		return
	}

	val, err := ReadVarInt(bytes.NewReader(want), pver)
	if err != nil {
		t.Errorf("ReadVarInt #%d error %v", idx, err)
		return
	}
	if val != out {
		t.Errorf("ReadVarInt #%d got=%d want=%d", idx, val, out)
	}
}

func negativeVarInt(t *testing.T, idx int, pver uint32, in uint64, buf []byte,
	maxInt int, wantWrite, wantRead error,
) {
	t.Helper()

	if err := WriteVarInt(newFixedWriter(maxInt), pver, in); !errors.Is(err, wantWrite) {
		t.Errorf("WriteVarInt #%d wrong error got=%v want=%v",
			idx, err, wantWrite)
	}
	_, err := ReadVarInt(newFixedReader(maxInt, buf), pver)
	if !errors.Is(err, wantRead) {
		t.Errorf("ReadVarInt #%d wrong error got=%v want=%v",
			idx, err, wantRead)
	}
}

func roundTripVarString(t *testing.T, idx int, pver uint32,
	in, out string, want []byte,
) {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteVarString(&buf, pver, in); err != nil {
		t.Errorf("WriteVarString #%d error %v", idx, err)
		return
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("WriteVarString #%d\n got: %s want: %s",
			idx, spew.Sdump(buf.Bytes()), spew.Sdump(want))
		return
	}

	val, err := ReadVarString(bytes.NewReader(want), pver)
	if err != nil {
		t.Errorf("ReadVarString #%d error %v", idx, err)
		return
	}
	if val != out {
		t.Errorf("ReadVarString #%d got=%q want=%q", idx, val, out)
	}
}

/*func negativeVarString(t *testing.T, idx int, pver uint32, in string, buf []byte,
	max int, wantWrite, wantRead error,
) {
	t.Helper()

	if err := WriteVarString(newFixedWriter(max), pver, in); !errors.Is(err, wantWrite) {
		t.Errorf("WriteVarString #%d wrong error got=%v want=%v",
			idx, err, wantWrite)
	}
	_, err := ReadVarString(newFixedReader(max, buf), pver)
	if !errors.Is(err, wantRead) {
		t.Errorf("ReadVarString #%d wrong error got=%v want=%v",
			idx, err, wantRead)
	}
}*/

func roundTripVarBytes(t *testing.T, idx int, pver uint32,
	in, want []byte,
) {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteVarBytes(&buf, pver, in); err != nil {
		t.Errorf("WriteVarBytes #%d error %v", idx, err)
		return
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("WriteVarBytes #%d\n got: %s want: %s",
			idx, spew.Sdump(buf.Bytes()), spew.Sdump(want))
		return
	}

	val, err := ReadVarBytes(bytes.NewReader(want), pver, maxMessagePayload(),
		"test payload")
	if err != nil {
		t.Errorf("ReadVarBytes #%d error %v", idx, err)
		return
	}
	if !bytes.Equal(val, in) {
		t.Errorf("ReadVarBytes #%d got=%v want=%v", idx, val, in)
	}
}

func negativeVarBytes(t *testing.T, idx int, pver uint32, in, buf []byte,
	maxInt int, wantWrite, wantRead error,
) {
	t.Helper()

	if err := WriteVarBytes(newFixedWriter(maxInt), pver, in); !errors.Is(err, wantWrite) {
		t.Errorf("WriteVarBytes #%d wrong error got=%v want=%v",
			idx, err, wantWrite)
	}
	_, err := ReadVarBytes(newFixedReader(maxInt, buf), pver, maxMessagePayload(),
		"test payload")
	if !errors.Is(err, wantRead) {
		t.Errorf("ReadVarBytes #%d wrong error got=%v want=%v",
			idx, err, wantRead)
	}
}

// TestElementWire exercises the “fast-path” element encode/decode.
func TestElementWire(t *testing.T) {
	type writeElementReflect int32 // triggers the reflection path
	tests := []struct {
		in  interface{}
		buf []byte
	}{
		{int32(1), []byte{0x01, 0x00, 0x00, 0x00}},
		{uint32(256), []byte{0x00, 0x01, 0x00, 0x00}},
		{int64(65536), []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{uint64(4294967296), []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}},
		{true, []byte{0x01}},
		{false, []byte{0x00}},
		{[4]byte{0x01, 0x02, 0x03, 0x04}, []byte{0x01, 0x02, 0x03, 0x04}},
		{
			[CommandSize]byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c,
			},
			[]byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c,
			},
		},
		{
			[16]byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			},
			[]byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			},
		},
		// Reflection path
		{writeElementReflect(1), []byte{0x01, 0x00, 0x00, 0x00}},
	}

	for i, tt := range tests {
		roundTripElement(t, i, tt.in, tt.buf)
	}
}

// TestElementWireErrors – negative paths.
func TestElementWireErrors(t *testing.T) {
	tests := []struct {
		in                  interface{}
		max                 int
		wantWrite, wantRead error
	}{
		{int32(1), 0, io.ErrShortWrite, io.EOF},
		{uint32(256), 0, io.ErrShortWrite, io.EOF},
		{int64(65536), 0, io.ErrShortWrite, io.EOF},
		{true, 0, io.ErrShortWrite, io.EOF},
		{[4]byte{0x01, 0x02, 0x03, 0x04}, 0, io.ErrShortWrite, io.EOF},
		{
			[CommandSize]byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c,
			},
			0, io.ErrShortWrite, io.EOF,
		},
		{
			[16]byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			},
			0, io.ErrShortWrite, io.EOF,
		},
		{
			(*chainhash.Hash)(&[chainhash.HashSize]byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
			}),
			0, io.ErrShortWrite, io.EOF,
		},
		{SFNodeNetwork, 0, io.ErrShortWrite, io.EOF},
		{InvTypeTx, 0, io.ErrShortWrite, io.EOF},
		{MainNet, 0, io.ErrShortWrite, io.EOF},
	}

	for i, tt := range tests {
		negativeElement(t, i, tt.max, tt.in, tt.wantWrite, tt.wantRead)
	}
}

// TestVarIntWire tests wire encode and decode for variable length integers
func TestVarIntWire(t *testing.T) {
	pver := ProtocolVersion
	tests := []struct {
		in, out uint64
		buf     []byte
	}{
		{0, 0, []byte{0x00}},
		{0xfc, 0xfc, []byte{0xfc}},
		{0xfd, 0xfd, []byte{0xfd, 0xfd, 0x00}},
		{0xffff, 0xffff, []byte{0xfd, 0xff, 0xff}},
		{0x10000, 0x10000, []byte{0xfe, 0x00, 0x00, 0x01, 0x00}},
		{0xffffffff, 0xffffffff, []byte{0xfe, 0xff, 0xff, 0xff, 0xff}},
		{
			0x100000000, 0x100000000,
			[]byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
		},
		// Max 8-byte
		{
			0xffffffffffffffff, 0xffffffffffffffff,
			[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
	}

	for i, tt := range tests {
		roundTripVarInt(t, i, pver, tt.in, tt.out, tt.buf)
	}
}

// TestVarIntWireErrors tests wire encode and decode for variable length integers (errors).
func TestVarIntWireErrors(t *testing.T) {
	pver := ProtocolVersion
	tests := []struct {
		in                  uint64
		buf                 []byte
		max                 int
		wantWrite, wantRead error
	}{
		// Single byte
		{0, []byte{0x00}, 0, io.ErrShortWrite, io.EOF},
		// Single byte varint
		{0xfd, []byte{0xfd}, 2, io.ErrShortWrite, io.ErrUnexpectedEOF},
		// 2-byte varint
		{0x10000, []byte{0xfe}, 2, io.ErrShortWrite, io.ErrUnexpectedEOF},
		// 4-byte varint
		{0x100000000, []byte{0xff}, 2, io.ErrShortWrite, io.ErrUnexpectedEOF},
	}
	for i, tt := range tests {
		negativeVarInt(t, i, pver, tt.in, tt.buf, tt.max, tt.wantWrite, tt.wantRead)
	}
}

// TestVarStringWire tests wire encode and decode for variable length strings.
func TestVarStringWire(t *testing.T) {
	pver := ProtocolVersion
	str256 := strings.Repeat("test", 64)

	tests := []struct {
		in, out string
		buf     []byte
	}{
		// Empty string
		{"", "", []byte{0x00}},
		// Single byte varint + string
		{"Test", "Test", append([]byte{0x04}, []byte("Test")...)},
		// 2-byte varint + string
		{str256, str256, append([]byte{0xfd, 0x00, 0x01}, []byte(str256)...)},
	}

	for i, tt := range tests {
		roundTripVarString(t, i, pver, tt.in, tt.out, tt.buf)
	}
}

// TestVarStringWireErrors performs negative tests against wire encode and
// decode of variable length strings to confirm error paths work correctly.
func TestVarStringWireErrors(t *testing.T) {
	pver := ProtocolVersion
	str256 := strings.Repeat("test", 64)

	tests := []struct {
		in       string // Value to encode
		buf      []byte // Wire encoding
		pver     uint32 // Protocol version for wire encoding
		max      int    // Max size of fixed buffer to induce errors
		writeErr error  // Expected write error
		readErr  error  // Expected read error
	}{
		// Latest protocol version with intentional read/write errors.
		// Force errors on empty string.
		{"", []byte{0x00}, pver, 0, io.ErrShortWrite, io.EOF},
		// Force error on single byte varint + string.
		{"Test", []byte{0x04}, pver, 2, io.ErrShortWrite, io.ErrUnexpectedEOF},
		// Force errors on 2-byte varint + string.
		{str256, []byte{0xfd}, pver, 2, io.ErrShortWrite, io.ErrUnexpectedEOF},
	}

	t.Logf("Running %d tests", len(tests))

	for i, test := range tests {
		// Encode to wire format.
		w := newFixedWriter(test.max)

		err := WriteVarString(w, test.pver, test.in)
		if !errors.Is(err, test.writeErr) {
			t.Errorf("WriteVarString #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// Decode from wire format.
		r := newFixedReader(test.max, test.buf)
		_, err = ReadVarString(r, test.pver)

		if !errors.Is(err, test.readErr) {
			t.Errorf("ReadVarString #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}
	}
}

// TestVarStringOverflowErrors performs tests to ensure deserializing variable
// length strings intentionally crafted to use large values for the string
// length are handled properly.  This could otherwise potentially be used as an
// attack vector.
func TestVarStringOverflowErrors(t *testing.T) {
	pver := ProtocolVersion

	tests := []struct {
		buf  []byte // Wire encoding
		pver uint32 // Protocol version for wire encoding
		err  error  // Expected error
	}{
		{
			[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			pver, &MessageError{},
		},
		{
			[]byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			pver, &MessageError{},
		},
	}

	t.Logf("Running %d tests", len(tests))

	for i, test := range tests {
		// Decode from wire format.
		rbuf := bytes.NewReader(test.buf)

		_, err := ReadVarString(rbuf, test.pver)
		if reflect.TypeOf(err) != reflect.TypeOf(test.err) {
			t.Errorf("ReadVarString #%d wrong error got: %v, "+
				"want: %v", i, err, reflect.TypeOf(test.err))
			continue
		}
	}
}

// TestVarBytesWire tests wire encode and decode for variable length byte slices.
func TestVarBytesWire(t *testing.T) {
	pver := ProtocolVersion
	bytes256 := bytes.Repeat([]byte{0x01}, 256)

	tests := []struct {
		in  []byte
		buf []byte
	}{
		// Empty byte array
		{[]byte{}, []byte{0x00}},
		// Single byte varint + byte array
		{[]byte{0x01}, []byte{0x01, 0x01}},
		// 2-byte varint + byte array
		{bytes256, append([]byte{0xfd, 0x00, 0x01}, bytes256...)},
	}

	for i, tt := range tests {
		roundTripVarBytes(t, i, pver, tt.in, tt.buf)
	}
}

// TestVarBytesWireErrors performs negative tests against wire encode and
func TestVarBytesWireErrors(t *testing.T) {
	pver := ProtocolVersion
	bytes256 := bytes.Repeat([]byte{0x01}, 256)

	tests := []struct {
		in, buf             []byte
		max                 int
		wantWrite, wantRead error
	}{
		{[]byte{}, []byte{0x00}, 0, io.ErrShortWrite, io.EOF},
		{[]byte{0x01, 0x02, 0x03}, []byte{0x04}, 2, io.ErrShortWrite, io.ErrUnexpectedEOF},
		{bytes256, []byte{0xfd}, 2, io.ErrShortWrite, io.ErrUnexpectedEOF},
	}
	for i, tt := range tests {
		negativeVarBytes(t, i, pver, tt.in, tt.buf, tt.max, tt.wantWrite, tt.wantRead)
	}
}

// TestRandomUint64 exercises the randomness of the random number generator on
// the system by ensuring the probability of the generated numbers.  If the RNG
// is evenly distributed as a proper cryptographic RNG should be, there really
// should only be 1 number < 2^56 in 2^8 tries for a 64-bit number.  However,
// use a higher number of 5 to really ensure the test doesn't fail unless the
// RNG is just horrendous.
func TestRandomUint64(t *testing.T) {
	tries := 1 << 8              // 2^8
	watermark := uint64(1 << 56) // 2^56
	maxHits := 5
	badRNG := "The random number generator on this system is clearly " +
		"terrible since we got %d values less than %d in %d runs " +
		"when only %d was expected"

	numHits := 0

	for i := 0; i < tries; i++ {
		nonce, err := RandomUint64()
		if err != nil {
			t.Errorf("RandomUint64 iteration %d failed - err %v",
				i, err)
			return
		}

		if nonce < watermark {
			numHits++
		}

		if numHits > maxHits {
			str := fmt.Sprintf(badRNG, numHits, watermark, tries, maxHits)
			t.Errorf("Random Uint64 iteration %d failed - %v %v", i,
				str, numHits)

			return
		}
	}
}

// TestRandomUint64Errors uses a fake reader to force error paths to be executed
// and checks the results accordingly.
func TestRandomUint64Errors(t *testing.T) {
	// Test short reads.
	fr := &fakeRandReader{n: 2, err: io.EOF}
	nonce, err := randomUint64(fr)

	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("Error not expected value of %v [%v]",
			io.ErrUnexpectedEOF, err)
	}

	if nonce != 0 {
		t.Errorf("Nonce is not 0 [%v]", nonce)
	}
}
