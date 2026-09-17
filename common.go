// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
)

const (
	// MaxVarIntPayload is the maximum payload size for a variable length integer.
	MaxVarIntPayload = 9

	// binaryFreeListMaxItems is the number of buffers to keep in the free
	// list to use for binary serialization and deserialization.
	binaryFreeListMaxItems = 1024
)

var (
	// littleEndian have been a convenience variable since binary.LittleEndian is
	// quite long.
	littleEndian = binary.LittleEndian

	// bigEndian have been a convenience variable since binary.BigEndian is quite
	// long.
	bigEndian = binary.BigEndian
)

// binaryFreeList defines a concurrent safe free list of byte slices (up to the
// maximum number defined by the binaryFreeListMaxItems constant) that have a
// cap of 8 (thus it supports up to an uint64).  It is used to provide temporary
// buffers for serializing and deserializing primitive numbers to and from their
// binary encoding to greatly reduce the number of allocations
// required.
//
// For convenience, functions are provided for each of the primitive unsigned
// integers that automatically get a buffer from the free list, perform the
// necessary binary conversion, read from or write to the given io.Reader or
// io.Writer, and return the buffer to the free list.
type binaryFreeList chan []byte

// Borrow returns a byte slice from the free list with a length of 8.  A new
// buffer is allocated if there are not any available on the free list.
func (l binaryFreeList) Borrow() []byte {
	var buf []byte
	select {
	case buf = <-l:
	default:
		buf = make([]byte, 8)
	}

	return buf[:8]
}

// Return puts the provided byte slice back on the free list.  The buffer MUST
// have been obtained via the Borrow function and therefore have a cap of 8.
func (l binaryFreeList) Return(buf []byte) {
	select {
	case l <- buf:
	default:
		// Let it go to the garbage collector.
	}
}

// Uint8 reads a single byte from the provided reader using a buffer from the
// free list and returns it as an uint8.
func (l binaryFreeList) Uint8(r io.Reader) (uint8, error) {
	buf := l.Borrow()[:1]
	if _, err := io.ReadFull(r, buf); err != nil {
		l.Return(buf)
		return 0, err
	}

	rv := buf[0]
	l.Return(buf)

	return rv, nil
}

// Uint16 reads two bytes from the provided reader using a buffer from the
// free list, converts it to a number using the provided byte order, and returns
// the resulting uint16.
func (l binaryFreeList) Uint16(r io.Reader, byteOrder binary.ByteOrder) (uint16, error) {
	buf := l.Borrow()[:2]
	if _, err := io.ReadFull(r, buf); err != nil {
		l.Return(buf)
		return 0, err
	}

	rv := byteOrder.Uint16(buf)
	l.Return(buf)

	return rv, nil
}

// Uint32 reads four bytes from the provided reader using a buffer from the
// free list, converts it to a number using the provided byte order, and returns
// the resulting uint32.
func (l binaryFreeList) Uint32(r io.Reader, byteOrder binary.ByteOrder) (uint32, error) {
	buf := l.Borrow()[:4]
	if _, err := io.ReadFull(r, buf); err != nil {
		l.Return(buf)
		return 0, err
	}

	rv := byteOrder.Uint32(buf)
	l.Return(buf)

	return rv, nil
}

// Uint64 reads eight bytes from the provided reader using a buffer from the
// free list, converts it to a number using the provided byte order, and returns
// the resulting uint64.
func (l binaryFreeList) Uint64(r io.Reader, byteOrder binary.ByteOrder) (uint64, error) {
	buf := l.Borrow()[:8]
	if _, err := io.ReadFull(r, buf); err != nil {
		l.Return(buf)
		return 0, err
	}

	rv := byteOrder.Uint64(buf)
	l.Return(buf)

	return rv, nil
}

// PutUint8 copies the provided uint8 into a buffer from the free list and
// writes the resulting byte to the given writer.
func (l binaryFreeList) PutUint8(w io.Writer, val uint8) error {
	buf := l.Borrow()[:1]
	buf[0] = val
	_, err := w.Write(buf)
	l.Return(buf)

	return err
}

// PutUint16 serializes the provided uint16 using the given byte order into a
// buffer from the free list and writes the resulting two bytes to the given
// writer.
func (l binaryFreeList) PutUint16(w io.Writer, byteOrder binary.ByteOrder, val uint16) error {
	buf := l.Borrow()[:2]
	byteOrder.PutUint16(buf, val)
	_, err := w.Write(buf)
	l.Return(buf)

	return err
}

// PutUint32 serializes the provided uint32 using the given byte order into a
// buffer from the free list and writes the resulting four bytes to the given
// writer.
func (l binaryFreeList) PutUint32(w io.Writer, byteOrder binary.ByteOrder, val uint32) error {
	buf := l.Borrow()[:4]
	byteOrder.PutUint32(buf, val)
	_, err := w.Write(buf)
	l.Return(buf)

	return err
}

// PutUint64 serializes the provided uint64 using the given byte order into a
// buffer from the free list and writes the resulting eight bytes to the given
// writer.
func (l binaryFreeList) PutUint64(w io.Writer, byteOrder binary.ByteOrder, val uint64) error {
	buf := l.Borrow()[:8]
	byteOrder.PutUint64(buf, val)
	_, err := w.Write(buf)
	l.Return(buf)

	return err
}

// binarySerializer provides a free list of buffers to use for serializing and
// deserializing primitive integer values to and from io.Readers and io.Writers.
var binarySerializer binaryFreeList = make(chan []byte, binaryFreeListMaxItems)

// errNonCanonicalVarInt is the common format string used for non-canonically
// encoded variable length integer errors.
var errNonCanonicalVarInt = "non-canonical varint %x - discriminant %x must " +
	"encode a value greater than %x"

// uint32Time represents an unix timestamp encoded with an uint32.  It is used as
// a way to signal the readElement function how to decode a timestamp into a Go
// time.Time since it is otherwise ambiguous.
type uint32Time time.Time

// int64Time represents an unix timestamp encoded with an int64.  It is used as
// a way to signal the readElement function how to decode a timestamp into a Go
// time.Time since it is otherwise ambiguous.
type int64Time time.Time

// readElement reads the next sequence of bytes from r using little endian
// depending on the concrete type of element pointed to.
func readElement(r io.Reader, element interface{}) error {
	// Attempt to read the element based on the concrete type via fast
	// type assertions first.
	switch e := element.(type) {
	case *int32:
		rv, err := binarySerializer.Uint32(r, littleEndian)
		if err != nil {
			return err
		}

		*e = int32(rv)

		return nil

	case *uint32:
		rv, err := binarySerializer.Uint32(r, littleEndian)
		if err != nil {
			return err
		}

		*e = rv

		return nil

	case *int64:
		rv, err := binarySerializer.Uint64(r, littleEndian)
		if err != nil {
			return err
		}

		*e = int64(rv)

		return nil

	case *uint64:
		rv, err := binarySerializer.Uint64(r, littleEndian)
		if err != nil {
			return err
		}

		*e = rv

		return nil

	case *bool:
		rv, err := binarySerializer.Uint8(r)
		if err != nil {
			return err
		}

		if rv == 0x00 {
			*e = false
		} else {
			*e = true
		}

		return nil

	// Unix timestamp encoded as a uint32.
	case *uint32Time:
		rv, err := binarySerializer.Uint32(r, binary.LittleEndian)
		if err != nil {
			return err
		}

		*e = uint32Time(time.Unix(int64(rv), 0))

		return nil

	// Unix timestamp encoded as an int64.
	case *int64Time:
		rv, err := binarySerializer.Uint64(r, binary.LittleEndian)
		if err != nil {
			return err
		}

		*e = int64Time(time.Unix(int64(rv), 0))

		return nil

	// Message header checksum.
	case *[4]byte:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}

		return nil

	// Message header command.
	case *[CommandSize]uint8:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}

		return nil

	// IP address.
	case *[16]byte:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}

		return nil

	case *chainhash.Hash:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}

		return nil

	case *ServiceFlag:
		rv, err := binarySerializer.Uint64(r, littleEndian)
		if err != nil {
			return err
		}

		*e = ServiceFlag(rv)

		return nil

	case *InvType:
		rv, err := binarySerializer.Uint32(r, littleEndian)
		if err != nil {
			return err
		}

		*e = InvType(rv)

		return nil

	case *BitcoinNet:
		rv, err := binarySerializer.Uint32(r, littleEndian)
		if err != nil {
			return err
		}

		*e = BitcoinNet(rv)

		return nil

	case *BloomUpdateType:
		rv, err := binarySerializer.Uint8(r)
		if err != nil {
			return err
		}

		*e = BloomUpdateType(rv)

		return nil

	case *RejectCode:
		rv, err := binarySerializer.Uint8(r)
		if err != nil {
			return err
		}

		*e = RejectCode(rv)

		return nil
	}

	// Fall back to the slower binary.Read if a fast path was not available
	// above.
	return binary.Read(r, littleEndian, element)
}

// readElements reads multiple items from r.  It is equivalent to multiple
// calls to readElement.
func readElements(r io.Reader, elements ...interface{}) error {
	for _, element := range elements {
		err := readElement(r, element)
		if err != nil {
			return err
		}
	}

	return nil
}

// writeElement writes the little endian representation of an element to w.
func writeElement(w io.Writer, element interface{}) error {
	// Attempt to write the element based on the concrete type via fast
	// type assertions first.
	switch e := element.(type) {
	case int32:
		err := binarySerializer.PutUint32(w, littleEndian, uint32(e))
		if err != nil {
			return err
		}

		return nil

	case uint32:
		err := binarySerializer.PutUint32(w, littleEndian, e)
		if err != nil {
			return err
		}

		return nil

	case int64:
		err := binarySerializer.PutUint64(w, littleEndian, uint64(e))
		if err != nil {
			return err
		}

		return nil

	case uint64:
		err := binarySerializer.PutUint64(w, littleEndian, e)
		if err != nil {
			return err
		}

		return nil

	case bool:
		var err error
		if e {
			err = binarySerializer.PutUint8(w, 0x01)
		} else {
			err = binarySerializer.PutUint8(w, 0x00)
		}

		if err != nil {
			return err
		}

		return nil

	// Message header checksum.
	case [4]byte:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}

		return nil

	// Message header command.
	case [CommandSize]uint8:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}

		return nil

	// IP address.
	case [16]byte:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}

		return nil

	case *chainhash.Hash:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}

		return nil

	case ServiceFlag:
		err := binarySerializer.PutUint64(w, littleEndian, uint64(e))
		if err != nil {
			return err
		}

		return nil

	case InvType:
		err := binarySerializer.PutUint32(w, littleEndian, uint32(e))
		if err != nil {
			return err
		}

		return nil

	case BitcoinNet:
		err := binarySerializer.PutUint32(w, littleEndian, uint32(e))
		if err != nil {
			return err
		}

		return nil

	case BloomUpdateType:
		err := binarySerializer.PutUint8(w, uint8(e))
		if err != nil {
			return err
		}

		return nil

	case RejectCode:
		err := binarySerializer.PutUint8(w, uint8(e))
		if err != nil {
			return err
		}

		return nil
	}

	// Fall back to the slower binary.Write if a fast path was not available
	// above.
	return binary.Write(w, littleEndian, element)
}

// writeElements writes multiple items to w.  It is equivalent to multiple
// calls to writeElement.
func writeElements(w io.Writer, elements ...interface{}) error {
	for _, element := range elements {
		err := writeElement(w, element)
		if err != nil {
			return err
		}
	}

	return nil
}

// ReadVarInt reads a variable length integer from r and returns it as an uint64.
func ReadVarInt(r io.Reader, _ uint32) (uint64, error) {
	discriminant, err := binarySerializer.Uint8(r)
	if err != nil {
		return 0, err
	}

	var rv uint64

	switch discriminant {
	case 0xff:
		var sv uint64
		sv, err = binarySerializer.Uint64(r, littleEndian)
		if err != nil {
			return 0, err
		}

		rv = sv

		// The encoding is not canonical if the value could have been
		// encoded using fewer bytes.
		minVal := uint64(0x100000000)
		if rv < minVal {
			return 0, messageError("ReadVarInt", fmt.Sprintf(
				errNonCanonicalVarInt, rv, discriminant, minVal,
			))
		}

	case 0xfe:
		var sv uint32

		sv, err = binarySerializer.Uint32(r, littleEndian)
		if err != nil {
			return 0, err
		}

		rv = uint64(sv)

		// The encoding is not canonical if the value could have been
		// encoded using fewer bytes.
		minVal := uint64(0x10000)
		if rv < minVal {
			return 0, messageError("ReadVarInt", fmt.Sprintf(
				errNonCanonicalVarInt, rv, discriminant, minVal,
			))
		}

	case 0xfd:
		var sv uint16

		sv, err = binarySerializer.Uint16(r, littleEndian)
		if err != nil {
			return 0, err
		}

		rv = uint64(sv)

		// The encoding is not canonical if the value could have been
		// encoded using fewer bytes.
		minVal := uint64(0xfd)
		if rv < minVal {
			return 0, messageError("ReadVarInt", fmt.Sprintf(
				errNonCanonicalVarInt, rv, discriminant, minVal,
			))
		}

	default:
		rv = uint64(discriminant)
	}

	return rv, nil
}

// streamPreallocReserve caps the number of elements a decoder reserves up front
// for a collection whose declared count is NOT backed by bytes known to be
// present (a streaming or bare io.Reader — see readerRemaining). The slice still
// grows to the real count as elements are actually read, so this only bounds the
// eager, up-front allocation: a huge declared count with a short body reserves at
// most this many elements and then fails on EOF, instead of allocating a
// count-sized slice before the first element is read (CWE-789). The value is
// generous enough that typical messages never grow beyond it.
const streamPreallocReserve = 2048

// readerRemaining reports the number of unread bytes ACTUALLY available from r
// and whether that count is known. It recognizes only readers whose remaining
// length reflects bytes already held in memory: *bytes.Buffer (the buffered
// ReadMessage path, which reads the whole payload before decoding) and
// *bytes.Reader (direct Deserialize callers).
//
// It deliberately does NOT report a remaining length for *io.LimitedReader: on
// the streaming read path that value is the payload length declared in the peer's
// header, which is not proof those bytes will arrive. Trusting it would let a
// truncated stream with a large declared length drive an eager count-sized
// allocation. For any reader whose real remaining length is unknown, callers fall
// back to bounded, grow-as-read allocation (see boundedReserve / growByOne).
//
// A consequence, by design: streaming decodes perform NO count-vs-remaining
// rejection at the count field. A count larger than the (untrusted) declared
// length is not rejected up front; the decode loop simply grows as bytes arrive
// and fails on EOF, having allocated at most streamPreallocReserve elements. The
// count-vs-remaining cap applies only to the in-memory readers above.
func readerRemaining(r io.Reader) (uint64, bool) {
	switch v := r.(type) {
	case *bytes.Buffer:
		return uint64(v.Len()), true
	case *bytes.Reader:
		return uint64(v.Len()), true
	default:
		return 0, false
	}
}

// boundedReserve returns a safe initial capacity for a slice that will hold count
// elements decoded from r, each occupying at least minElemSize on-wire bytes. It
// never returns a capacity larger than the bytes actually available can back, so a
// decoder can size its backing array without trusting an attacker-declared count:
//
//   - When r exposes its real remaining length (in-memory readers), the reserve is
//     capped at remaining/minElemSize — the most elements the remaining bytes could
//     possibly encode — so an impossible count reserves little and then fails on the
//     read, while a legitimate count is reserved in full (no growth, no regression).
//   - Otherwise (streaming / bare reader, where the declared length is not proof of
//     available bytes) the reserve is capped at streamPreallocReserve; the slice
//     grows as elements are actually read.
func boundedReserve(r io.Reader, count, minElemSize uint64) int {
	limit := uint64(streamPreallocReserve)

	if minElemSize > 0 {
		if remaining, ok := readerRemaining(r); ok {
			limit = remaining / minElemSize
		}
	}

	if count < limit {
		return int(count)
	}

	return int(limit)
}

// growByOne extends s by exactly one element and returns the result. When s has
// spare capacity the element is added in place without reallocating; otherwise s
// is grown (reallocated) via append. Decoders use it together with boundedReserve
// to read a list one element at a time, so the backing array is never sized
// directly from an untrusted count and only grows as elements actually arrive.
// The newly added element is the zero value of T; callers decode into it via the
// last index. Any []*T pointer view must be built AFTER the loop, since growth may
// move the backing array.
func growByOne[T any](s []T) []T {
	if len(s) < cap(s) {
		return s[:len(s)+1]
	}

	var zero T

	return append(s, zero)
}

// pointersTo returns a slice of pointers to each element of s. It is called after
// a grow-as-read decode loop completes, when s (and therefore the addresses of its
// elements) is stable, to build the []*T view the message types expose.
func pointersTo[T any](s []T) []*T {
	ptrs := make([]*T, len(s))
	for i := range s {
		ptrs[i] = &s[i]
	}

	return ptrs
}

// decodeHashList reads count 32-byte hashes from r into a slice that grows as
// each hash is read (never sized from the untrusted count, see growByOne /
// boundedReserve), and returns the []*chainhash.Hash view. The caller is
// responsible for having already rejected counts above its global maximum.
func decodeHashList(r io.Reader, count uint64) ([]*chainhash.Hash, error) {
	hashes := make([]chainhash.Hash, 0, boundedReserve(r, count, chainhash.HashSize))

	for i := uint64(0); i < count; i++ {
		hashes = growByOne(hashes)

		if err := readElement(r, &hashes[i]); err != nil {
			return nil, err
		}
	}

	return pointersTo(hashes), nil
}

// decodeInvVects reads count inventory vectors from r into a slice that grows as
// each vector is read, and returns the []*InvVect view. Like decodeHashList it
// never sizes the backing array from the untrusted count.
func decodeInvVects(r io.Reader, pver uint32, count uint64) ([]*InvVect, error) {
	invList := make([]InvVect, 0, boundedReserve(r, count, maxInvVectPayload))

	for i := uint64(0); i < count; i++ {
		invList = growByOne(invList)

		if err := readInvVect(r, pver, &invList[i]); err != nil {
			return nil, err
		}
	}

	return pointersTo(invList), nil
}

// WriteVarInt serializes val to w using a variable number of bytes depending
// on its value.
func WriteVarInt(w io.Writer, _ uint32, val uint64) error {
	if val < 0xfd {
		return binarySerializer.PutUint8(w, uint8(val))
	}

	if val <= math.MaxUint16 {
		err := binarySerializer.PutUint8(w, 0xfd)
		if err != nil {
			return err
		}

		return binarySerializer.PutUint16(w, littleEndian, uint16(val))
	}

	if val <= math.MaxUint32 {
		err := binarySerializer.PutUint8(w, 0xfe)
		if err != nil {
			return err
		}

		return binarySerializer.PutUint32(w, littleEndian, uint32(val))
	}

	err := binarySerializer.PutUint8(w, 0xff)
	if err != nil {
		return err
	}

	return binarySerializer.PutUint64(w, littleEndian, val)
}

// VarIntSerializeSize returns the number of bytes it would take to serialize
// val as a variable length integer.
func VarIntSerializeSize(val uint64) int {
	// The value is small enough to be represented by itself, so it's
	// just 1 byte.
	if val < 0xfd {
		return 1
	}

	// Discriminant 1 byte plus 2 bytes for the uint16.
	if val <= math.MaxUint16 {
		return 3
	}

	// Discriminant 1 byte plus 4 bytes for the uint32.
	if val <= math.MaxUint32 {
		return 5
	}

	// Discriminant 1 byte plus 8 bytes for the uint64.
	return 9
}

// ReadVarString reads a variable length string from r and returns it as a Go
// string.  A variable length string is encoded as a variable length integer
// containing the length of the string followed by the bytes that represent the
// string itself.  An error is returned if the length is greater than the
// maximum block payload size since it helps protect against memory exhaustion
// attacks and forced panics through malformed messages.
func ReadVarString(r io.Reader, pver uint32) (string, error) {
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return "", err
	}

	// Prevent variable length strings that are larger than the maximum
	// message size.  It would be possible to cause memory exhaustion and
	//  panic without a sane upper bound on this count.
	if count > maxMessagePayload() {
		str := fmt.Sprintf("variable length string is too long "+
			"[count %d, max %d]", count, maxMessagePayload())

		return "", messageError("ReadVarString", str)
	}

	buf := make([]byte, count)

	_, err = io.ReadFull(r, buf)
	if err != nil {
		return "", err
	}

	return string(buf), nil
}

// WriteVarString serializes str to w as a variable length integer containing
// the length of the string followed by the bytes that represent the string
// itself.
func WriteVarString(w io.Writer, pver uint32, str string) error {
	err := WriteVarInt(w, pver, uint64(len(str)))
	if err != nil {
		return err
	}

	_, err = w.Write([]byte(str))

	return err
}

// ReadVarBytes reads a variable length byte array.  A byte array is encoded
// as a varInt containing the length of the array followed by the bytes
// themselves.  An error is returned if the length is greater than the
// passed maxAllowed parameter which helps protect against memory exhaustion
// attacks and forced panics through malformed messages.  The fieldName
// parameter is only used for the error message so it provides more context in
// the error.
func ReadVarBytes(r io.Reader, pver uint32, maxAllowed uint64,
	fieldName string,
) ([]byte, error) {
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return nil, err
	}

	// Prevent a byte array larger than the max message size.  It would
	// be possible to cause memory exhaustion and panic without a sane
	// upper bound on this count.
	if count > maxAllowed {
		str := fmt.Sprintf("%s is larger than the max allowed size "+
			"[count %d, max %d]", fieldName, count, maxAllowed)

		return nil, messageError("ReadVarBytes", str)
	}

	b := make([]byte, count)

	_, err = io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// WriteVarBytes serializes a variable length byte array to w as a varInt
// containing the number of bytes, followed by the bytes themselves.
func WriteVarBytes(w io.Writer, pver uint32, bytes []byte) error {
	slen := uint64(len(bytes))

	err := WriteVarInt(w, pver, slen)
	if err != nil {
		return err
	}

	_, err = w.Write(bytes)

	return err
}

// randomUint64 returns a cryptographically random uint64 value.  This
// unexported version takes a reader primarily to ensure the error paths
// can be properly tested by passing a fake reader in the tests.
func randomUint64(r io.Reader) (uint64, error) {
	rv, err := binarySerializer.Uint64(r, bigEndian)
	if err != nil {
		return 0, err
	}

	return rv, nil
}

// RandomUint64 returns a cryptographically random uint64 value.
func RandomUint64() (uint64, error) {
	return randomUint64(rand.Reader)
}
