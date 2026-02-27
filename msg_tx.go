// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
)

const (
	// TxVersion is the current latest supported transaction version.
	TxVersion = 1

	// MaxTxInSequenceNum is the maximum sequence number the sequence field
	// of a transaction input can be.
	MaxTxInSequenceNum uint32 = 0xffffffff

	// MaxPrevOutIndex is the maximum index the index field of a previous
	// outpointing can be.
	MaxPrevOutIndex uint32 = 0xffffffff

	// SequenceLockTimeDisabled is a flag that if set on a transaction
	// input's sequence number, the sequence number will not be interpreted
	// as a relative locktime.
	SequenceLockTimeDisabled = 1 << 31

	// SequenceLockTimeIsSeconds is a flag that if set on a transaction
	// input's sequence number, the relative locktime has units of 512
	// seconds.
	SequenceLockTimeIsSeconds = 1 << 22

	// SequenceLockTimeMask is a mask that extracts the relative locktime
	// when masked against the transaction input sequence number.
	SequenceLockTimeMask = 0x0000ffff

	// SequenceLockTimeGranularity is the defined time-based granularity
	// for seconds-based relative time locks. When converting from seconds
	// to a sequence number, the value is right shifted by this amount,
	// therefore the granularity of relative time locks in 512 or 2^9
	// seconds. Enforced relative lock times are multiples of 512 seconds.
	SequenceLockTimeGranularity = 9

	// defaultTxInOutAlloc is the default size used for the backing array for
	// transaction inputs and outputs.  The array will dynamically grow as needed,
	// but this figure is intended to provide enough space for the number of
	// inputs and outputs in a typical transaction without needing to grow the
	// backing array multiple times.
	defaultTxInOutAlloc = 15

	// minTxInPayload is the minimum payload size for a transaction input.
	// PreviousOutPoint.Hash + PreviousOutPoint.Index 4 bytes + Varint for
	// SignatureScript length 1 byte + Sequence 4 bytes.
	minTxInPayload = 9 + chainhash.HashSize

	// MinTxOutPayload is the minimum payload size for a transaction output.
	// Value 8 bytes + Varint for PkScript length 1 byte.
	MinTxOutPayload = 9

	// minTxPayload is the minimum payload size for a transaction.  Note
	// that any realistically usable transaction must have at least one
	// input or output, but that is a rule enforced at a higher layer, so
	// it is intentionally not included here.
	// Version 4 bytes + Varint number of transaction inputs 1 byte + Varint
	// number of transaction outputs 1 byte + LockTime 4 bytes + min input
	// payload + min output payload.
	minTxPayload = 10

	// freeListMaxScriptSize is the size of each buffer in the free list
	// that	is used for deserializing scripts from the wire before they are
	// concatenated into a single contiguous buffers.  This value was chosen
	// because it is slightly more than twice the size of the vast majority
	// of all "standard" scripts.  Larger scripts are still deserialized
	// properly as the free list will simply be bypassed for them.
	freeListMaxScriptSize = 512

	// freeListMaxItems is the number of buffers to keep in the free list
	// to use for script deserialization.  This value allows up to 100
	// scripts per transaction being simultaneously deserialized by 125
	// peers.  Thus, the peak usage of the free list is 12,500 * 512 =
	// 6,400,000 bytes.
	freeListMaxItems = 12500
)

// maxTxInPerMessage returns the maximum number of transaction inputs that
// a transaction which fits into a message could possibly have.
func maxTxInPerMessage() uint64 {
	return (maxMessagePayload() / minTxInPayload) + 1
}

// maxTxOutPerMessage returns the maximum number of transaction outputs that
// a transaction which fits into a message could possibly have.
func maxTxOutPerMessage() uint64 {
	return (maxMessagePayload() / MinTxOutPayload) + 1
}

// scriptFreeList defines a free list of byte slices (up to the maximum number
// defined by the freeListMaxItems constant) that has a cap according to the
// freeListMaxScriptSize constant.  It is used to provide temporary buffers for
// deserializing scripts to greatly reduce the number of allocations
// required.
//
// The caller can get a buffer from the free list by calling the Borrow
// function and should return it via the Return function when done using it.
type scriptFreeList chan []byte

// Borrow returns a byte slice from the free list with a length according the
// provided size.  A new buffer is allocated if there are any items available.
//
// When the size is larger than the max size allowed for items on the free list,
// a new buffer of the appropriate size is allocated and returned.  It is safe
// to attempt to return said buffer via the Return function as it will be
// ignored and allowed to go the garbage collector.
func (c scriptFreeList) Borrow(size uint64) []byte {
	if size > freeListMaxScriptSize {
		return make([]byte, size)
	}

	var buf []byte
	select {
	case buf = <-c:
	default:
		buf = make([]byte, freeListMaxScriptSize)
	}

	return buf[:size]
}

// Return puts the provided byte slice back on the free list when it has a cap
// of the expected length.  The buffer is expected to have been obtained via
// the Borrow function.  Any slices that are not of the appropriate size, such
// as those whose size is greater than the largest allowed free list item size,
// are simply ignored so they can go to the garbage collector.
func (c scriptFreeList) Return(buf []byte) {
	// Ignore any buffers returned that aren't the expected size for the
	// free list.
	if cap(buf) != freeListMaxScriptSize {
		return
	}

	// Return the buffer to the free list when it's not full.  Otherwise, let
	// it be garbage collected.
	select {
	case c <- buf:
	default:
		// Let it go to the garbage collector.
	}
}

// Create the concurrent safe free list to use for script deserialization.  As
// previously described, this free list is maintained to significantly reduce
// the number of allocations.
var scriptPool scriptFreeList = make(chan []byte, freeListMaxItems)

// OutPoint defines a bitcoin data type used to track previous
// transaction outputs.
type OutPoint struct {
	Hash  chainhash.Hash
	Index uint32
}

// NewOutPoint returns a new bitcoin transaction outpoint point with the
// provided hash and index.
func NewOutPoint(hash *chainhash.Hash, index uint32) *OutPoint {
	return &OutPoint{
		Hash:  *hash,
		Index: index,
	}
}

// String returns the OutPoint in the human-readable form "hash:index".
func (o OutPoint) String() string {
	// Allocate enough for hash string, colon, and 10 digits.  Although
	// at the time of writing, the number of digits can be no greater than
	// the length of the decimal representation of maxTxOutPerMessage, the
	// maximum message payload may increase in the future and this
	// optimization may go unnoticed, so allocate space for 10 decimal
	// digits, which will fit any uint32.
	buf := make([]byte, 2*chainhash.HashSize+1, 2*chainhash.HashSize+1+10)
	copy(buf, o.Hash.String())
	buf[2*chainhash.HashSize] = ':'
	buf = strconv.AppendUint(buf, uint64(o.Index), 10)

	return string(buf)
}

// TxIn defines a bitcoin transaction input.
type TxIn struct {
	PreviousOutPoint OutPoint
	SignatureScript  []byte
	Sequence         uint32
}

// SerializeSize returns the number of bytes it would take to serialize the
//
//	transaction input.
func (t *TxIn) SerializeSize() int {
	// Outpoint Hash 32 bytes + Outpoint Index 4 bytes + Sequence 4 bytes +
	// serialized varint size for the length of SignatureScript +
	// SignatureScript bytes.
	return 40 + VarIntSerializeSize(uint64(len(t.SignatureScript))) +
		len(t.SignatureScript)
}

// NewTxIn returns a new bitcoin transaction input with the provided
// previous outpointed point and signature script with a default sequence of
// MaxTxInSequenceNum.
func NewTxIn(prevOut *OutPoint, signatureScript []byte) *TxIn {
	return &TxIn{
		PreviousOutPoint: *prevOut,
		SignatureScript:  signatureScript,
		Sequence:         MaxTxInSequenceNum,
	}
}

// TxOut defines a bitcoin transaction output.
type TxOut struct {
	Value    int64
	PkScript []byte
}

// SerializeSize returns the number of bytes it would take to serialize the
//
//	transaction output.
func (t *TxOut) SerializeSize() int {
	// Value 8 bytes + serialized varint size for the length of PkScript +
	// PkScript bytes.
	return 8 + VarIntSerializeSize(uint64(len(t.PkScript))) + len(t.PkScript)
}

// NewTxOut returns a new bitcoin transaction output with the provided
// transaction value and public key script.
func NewTxOut(value int64, pkScript []byte) *TxOut {
	return &TxOut{
		Value:    value,
		PkScript: pkScript,
	}
}

// MsgTx implements the Message interface and represents a bitcoin tx message.
// It is used to deliver transaction information in response to a getdata
// message (MsgGetData) for a given transaction.
//
// Use the AddTxIn and AddTxOut functions to build up the list of transaction
// inputs and outputs.
type MsgTx struct {
	Version    int32
	TxIn       []*TxIn
	TxOut      []*TxOut
	LockTime   uint32
	cachedHash *chainhash.Hash // lazily computed and cached tx hash
}

// AddTxIn adds a transaction input to the message.
func (msg *MsgTx) AddTxIn(ti *TxIn) {
	msg.TxIn = append(msg.TxIn, ti)
	msg.cachedHash = nil
}

// AddTxOut adds a transaction output to the message.
func (msg *MsgTx) AddTxOut(to *TxOut) {
	msg.TxOut = append(msg.TxOut, to)
	msg.cachedHash = nil
}

// TxHash generates the Hash for the transaction. The result is cached so that
// subsequent calls do not re-serialize the transaction.
func (msg *MsgTx) TxHash() chainhash.Hash {
	if msg.cachedHash != nil {
		return *msg.cachedHash
	}

	// Serialize directly into a SHA-256 hasher to avoid allocating an
	// intermediate buffer. Double SHA-256 is computed as sha256(sha256(tx)).
	h := sha256.New()
	_ = msg.Serialize(h)
	var first [32]byte
	h.Sum(first[:0])
	hash := chainhash.Hash(sha256.Sum256(first[:]))
	msg.cachedHash = &hash
	return hash
}

// Copy creates a deep copy of a transaction so that the original does not get
// modified when the copy is manipulated.
func (msg *MsgTx) Copy() *MsgTx {
	// Create new tx and start by copying primitive values and making space
	// for the transaction inputs and outputs.
	newTx := MsgTx{
		Version:  msg.Version,
		TxIn:     make([]*TxIn, 0, len(msg.TxIn)),
		TxOut:    make([]*TxOut, 0, len(msg.TxOut)),
		LockTime: msg.LockTime,
	}

	// Deep copy the old TxIn data.
	for _, oldTxIn := range msg.TxIn {
		// Deep copy the old previous outpointing.
		oldOutPoint := oldTxIn.PreviousOutPoint
		newOutPoint := OutPoint{}
		_ = newOutPoint.Hash.SetBytes(oldOutPoint.Hash[:])
		newOutPoint.Index = oldOutPoint.Index

		// Deep copy the old signature script.
		var newScript []byte

		oldScript := oldTxIn.SignatureScript

		oldScriptLen := len(oldScript)
		if oldScriptLen > 0 {
			newScript = make([]byte, oldScriptLen)
			copy(newScript, oldScript[:oldScriptLen])
		}

		// Create new txIn with the deep copied data.
		newTxIn := TxIn{
			PreviousOutPoint: newOutPoint,
			SignatureScript:  newScript,
			Sequence:         oldTxIn.Sequence,
		}

		// Finally, append this fully copied txin.
		newTx.TxIn = append(newTx.TxIn, &newTxIn)
	}

	// Deep copy the old TxOut data.
	for _, oldTxOut := range msg.TxOut {
		// Deep copy the old PkScript
		var newScript []byte

		oldScript := oldTxOut.PkScript

		oldScriptLen := len(oldScript)
		if oldScriptLen > 0 {
			newScript = make([]byte, oldScriptLen)
			copy(newScript, oldScript[:oldScriptLen])
		}

		// Create new txOut with the deep copied data and append it to
		// new Tx.
		newTxOut := TxOut{
			Value:    oldTxOut.Value,
			PkScript: newScript,
		}
		newTx.TxOut = append(newTx.TxOut, &newTxOut)
	}

	return &newTx
}

// Bsvdecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding transactions stored to disk, such as in a
// database, as opposed to decoding transactions from the wire.
func (msg *MsgTx) Bsvdecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return msg.bsvdecode(r, pver, enc, nil)
}

// bsvdecode is the internal deserialization implementation. When largeBuf is
// non-nil, it is used as a reusable scratch buffer for scripts larger than
// the scriptFreeList threshold (512 bytes). This avoids a fresh heap
// allocation per large script when decoding many transactions (e.g., a block).
// The caller (MsgBlock.Bsvdecode) passes a shared buffer that persists across
// all transactions in the block.
func (msg *MsgTx) bsvdecode(r io.Reader, pver uint32, _ MessageEncoding, largeBuf *[]byte) error {
	version, err := binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}

	msg.Version = int32(version)

	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Prevent more input transactions than could possibly fit into a
	// message.  It would be possible to cause memory exhaustion and panic
	// without a sane upper bound on this count.
	if count > maxTxInPerMessage() {
		str := fmt.Sprintf("too many input transactions to fit into "+
			"max message size [count %d, max %d]", count, maxTxInPerMessage())
		return messageError("MsgTx.Bsvdecode", str)
	}

	// returnScriptBuffers is a closure that returns any script buffers that
	// were borrowed from the pool when there are any deserialization
	// errors.  This is only valid to call before the final step which
	// replaces the scripts with the location in a contiguous buffer and
	// returns them.
	returnScriptBuffers := func() {
		for _, txIn := range msg.TxIn {
			if txIn == nil {
				continue
			}

			if txIn.SignatureScript != nil {
				scriptPool.Return(txIn.SignatureScript)
			}
		}

		for _, txOut := range msg.TxOut {
			if txOut == nil || txOut.PkScript == nil {
				continue
			}

			scriptPool.Return(txOut.PkScript)
		}
	}

	// When largeBuf is provided (block-level decoding), all scripts are read
	// into a single scratch buffer that's reused across transactions. The
	// buffer grows to accommodate each tx's total script data, then is reset
	// (len=0, cap preserved) for the next tx. This avoids a fresh heap
	// allocation per large script (scripts >512 bytes bypass the pool in
	// scriptFreeList.Borrow), saving ~3.7 GB for a 3.6 GB block.
	//
	// When largeBuf is nil (single-tx decoding), the traditional script pool
	// approach is used for backward compatibility.
	if largeBuf != nil {
		return msg.bsvdecodeWithScratch(r, pver, count, largeBuf)
	}

	// Deserialize the inputs using script pool (single-tx path).
	var totalScriptSize uint64

	txIns := make([]TxIn, count)
	msg.TxIn = make([]*TxIn, count)

	for i := uint64(0); i < count; i++ {
		ti := &txIns[i]
		msg.TxIn[i] = ti

		err = readTxIn(r, pver, msg.Version, ti)
		if err != nil {
			returnScriptBuffers()
			return err
		}

		totalScriptSize += uint64(len(ti.SignatureScript))
	}

	count, err = ReadVarInt(r, pver)
	if err != nil {
		returnScriptBuffers()
		return err
	}

	if count > maxTxOutPerMessage() {
		returnScriptBuffers()

		str := fmt.Sprintf("too many output transactions to fit into "+
			"max message size [count %d, max %d]", count, maxTxOutPerMessage())

		return messageError("MsgTx.Bsvdecode", str)
	}

	txOuts := make([]TxOut, count)
	msg.TxOut = make([]*TxOut, count)

	for i := uint64(0); i < count; i++ {
		to := &txOuts[i]
		msg.TxOut[i] = to

		err = readTxOut(r, pver, msg.Version, to)
		if err != nil {
			returnScriptBuffers()
			return err
		}

		totalScriptSize += uint64(len(to.PkScript))
	}

	msg.LockTime, err = binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		returnScriptBuffers()
		return err
	}

	var offset uint64

	scripts := make([]byte, totalScriptSize)

	for i := 0; i < len(msg.TxIn); i++ {
		signatureScript := msg.TxIn[i].SignatureScript
		copy(scripts[offset:], signatureScript)

		scriptSize := uint64(len(signatureScript))
		end := offset + scriptSize
		msg.TxIn[i].SignatureScript = scripts[offset:end:end]
		offset += scriptSize

		scriptPool.Return(signatureScript)
	}

	for i := 0; i < len(msg.TxOut); i++ {
		pkScript := msg.TxOut[i].PkScript
		copy(scripts[offset:], pkScript)

		scriptSize := uint64(len(pkScript))
		end := offset + scriptSize
		msg.TxOut[i].PkScript = scripts[offset:end:end]
		offset += scriptSize

		scriptPool.Return(pkScript)
	}

	return nil
}

// bsvdecodeWithScratch deserializes a transaction using a shared scratch
// buffer for reading script data, avoiding per-script heap allocations.
// All scripts are read into scratch at successive offsets, then copied
// into an exact-size contiguous buffer. The scratch buffer persists
// across transactions when called from MsgBlock.Bsvdecode.
func (msg *MsgTx) bsvdecodeWithScratch(r io.Reader, pver uint32, inCount uint64, scratch *[]byte) error {
	// Reset scratch length but keep capacity from previous tx.
	*scratch = (*scratch)[:0]

	type scriptRef struct {
		offset int
		length int
	}

	// Read each input script into scratch.
	txIns := make([]TxIn, inCount)
	msg.TxIn = make([]*TxIn, inCount)
	sigRefs := make([]scriptRef, inCount)
	var totalScriptSize uint64

	for i := uint64(0); i < inCount; i++ {
		ti := &txIns[i]
		msg.TxIn[i] = ti

		err := readOutPoint(r, pver, msg.Version, &ti.PreviousOutPoint)
		if err != nil {
			return err
		}

		scriptLen, err := ReadVarInt(r, pver)
		if err != nil {
			return err
		}

		if scriptLen > maxTxInPerMessage() {
			str := fmt.Sprintf("transaction input signature script is larger than the max allowed size "+
				"[count %d, max %d]", scriptLen, maxTxInPerMessage())
			return messageError("MsgTx.bsvdecodeWithScratch", str)
		}

		start := len(*scratch)
		*scratch = growSlice(*scratch, int(scriptLen))
		_, err = io.ReadFull(r, (*scratch)[start:start+int(scriptLen)])
		if err != nil {
			return err
		}

		sigRefs[i] = scriptRef{offset: start, length: int(scriptLen)}
		totalScriptSize += scriptLen

		err = readElement(r, &ti.Sequence)
		if err != nil {
			return err
		}
	}

	outCount, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	if outCount > maxTxOutPerMessage() {
		str := fmt.Sprintf("too many output transactions to fit into "+
			"max message size [count %d, max %d]", outCount, maxTxOutPerMessage())
		return messageError("MsgTx.bsvdecodeWithScratch", str)
	}

	txOuts := make([]TxOut, outCount)
	msg.TxOut = make([]*TxOut, outCount)
	pkRefs := make([]scriptRef, outCount)

	for i := uint64(0); i < outCount; i++ {
		to := &txOuts[i]
		msg.TxOut[i] = to

		err = readElement(r, &to.Value)
		if err != nil {
			return err
		}

		var scriptLen uint64
		scriptLen, err = ReadVarInt(r, pver)
		if err != nil {
			return err
		}

		if scriptLen > maxMessagePayload() {
			str := fmt.Sprintf("transaction output public key script is larger than the max allowed size "+
				"[count %d, max %d]", scriptLen, maxMessagePayload())
			return messageError("MsgTx.bsvdecodeWithScratch", str)
		}

		start := len(*scratch)
		*scratch = growSlice(*scratch, int(scriptLen))
		_, err = io.ReadFull(r, (*scratch)[start:start+int(scriptLen)])
		if err != nil {
			return err
		}

		pkRefs[i] = scriptRef{offset: start, length: int(scriptLen)}
		totalScriptSize += scriptLen
	}

	msg.LockTime, err = binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}

	// Copy all scripts from scratch into an exact-size contiguous buffer.
	var offset uint64

	scripts := make([]byte, totalScriptSize)

	for i := range msg.TxIn {
		ref := sigRefs[i]
		copy(scripts[offset:], (*scratch)[ref.offset:ref.offset+ref.length])

		end := offset + uint64(ref.length)
		msg.TxIn[i].SignatureScript = scripts[offset:end:end]
		offset += uint64(ref.length)
	}

	for i := range msg.TxOut {
		ref := pkRefs[i]
		copy(scripts[offset:], (*scratch)[ref.offset:ref.offset+ref.length])

		end := offset + uint64(ref.length)
		msg.TxOut[i].PkScript = scripts[offset:end:end]
		offset += uint64(ref.length)
	}

	return nil
}

// growSlice extends buf by n bytes, growing the underlying array with
// amortized-doubling when capacity is insufficient.
func growSlice(buf []byte, n int) []byte {
	needed := len(buf) + n
	if needed <= cap(buf) {
		return buf[:needed]
	}

	newCap := cap(buf) * 2
	if newCap < needed {
		newCap = needed
	}

	newBuf := make([]byte, needed, newCap)
	copy(newBuf, buf)

	return newBuf
}

// Deserialize decodes a transaction from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field in the transaction.  This function differs from Bsvdecode
// in that Bsvdecode decodes from the bitcoin wire protocol as it was sent
// across the network.  The wire encoding can technically differ depending on
// the protocol version and doesn't even really need to match the format of a
// stored transaction at all.  As of the time this comment was written, the
// encoded transaction is the same in both instances, but there is a distinct
// difference and separating the two allows the API to be flexible enough to
// deal with changes.
func (msg *MsgTx) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of Bsvdecode.
	return msg.Bsvdecode(r, 0, BaseEncoding)
}

// BsvEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding transactions to be stored to disk, such as in a
// database, as opposed to encoding transactions for the wire.
func (msg *MsgTx) BsvEncode(w io.Writer, pver uint32, _ MessageEncoding) error {
	err := binarySerializer.PutUint32(w, littleEndian, uint32(msg.Version))
	if err != nil {
		return err
	}

	count := uint64(len(msg.TxIn))

	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, ti := range msg.TxIn {
		err = writeTxIn(w, pver, msg.Version, ti)
		if err != nil {
			return err
		}
	}

	count = uint64(len(msg.TxOut))

	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, to := range msg.TxOut {
		err = WriteTxOut(w, pver, msg.Version, to)
		if err != nil {
			return err
		}
	}

	return binarySerializer.PutUint32(w, littleEndian, msg.LockTime)
}

// Serialize encodes the transaction to w using a format that suitable for
// long-term storage such as a database while respecting the Version field in
// the transaction.  This function differs from BsvEncode in that BsvEncode
// encodes the transaction to the bitcoin wire protocol to be sent
// across the network.  The wire encoding can technically differ depending on
// the protocol version and doesn't even really need to match the format of a
// stored transaction at all.  As of the time this comment was written, the
// encoded transaction is the same in both instances, but there is a distinct
// difference and separating the two allows the API to be flexible enough to
// deal with changes.
func (msg *MsgTx) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BsvEncode.
	return msg.BsvEncode(w, 0, BaseEncoding)
}

// baseSize returns the serialized size of the transaction without accounting
// for any witness data.
func (msg *MsgTx) baseSize() int {
	// Version 4 bytes + LockTime 4 bytes and Serialized varint size for the
	// number of transaction inputs and outputs.
	n := 8 + VarIntSerializeSize(uint64(len(msg.TxIn))) +
		VarIntSerializeSize(uint64(len(msg.TxOut)))

	for _, txIn := range msg.TxIn {
		n += txIn.SerializeSize()
	}

	for _, txOut := range msg.TxOut {
		n += txOut.SerializeSize()
	}

	return n
}

// SerializeSize returns the number of bytes it would take to serialize the
//
//	transaction.
func (msg *MsgTx) SerializeSize() int {
	return msg.baseSize()
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgTx) Command() string {
	return CmdTx
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgTx) MaxPayloadLength(_ uint32) uint64 {
	return MaxBlockPayload()
}

// PkScriptLocs returns a slice containing the start of each public key script
// within the raw-serialized transaction.  The caller can easily get the
// length of each script by using len on the script available via the
// appropriate transaction output entry.
func (msg *MsgTx) PkScriptLocs() []int {
	numTxOut := len(msg.TxOut)
	if numTxOut == 0 {
		return nil
	}

	// The starting offset in the serialized transaction of the first
	// transaction output is:
	//
	// Version 4 bytes and serialized varint size for the number of
	// transaction inputs and outputs + serialized size of each transaction
	// input.
	n := 4 + VarIntSerializeSize(uint64(len(msg.TxIn))) +
		VarIntSerializeSize(uint64(numTxOut))

	for _, txIn := range msg.TxIn {
		n += txIn.SerializeSize()
	}

	// Calculate and set the appropriate offset for each public key script.
	pkScriptLocs := make([]int, numTxOut)

	for i, txOut := range msg.TxOut {
		// The offset of the script in the transaction output is:
		//
		// Value 8 bytes + serialized varint size for the length of
		// PkScript.
		n += 8 + VarIntSerializeSize(uint64(len(txOut.PkScript)))
		pkScriptLocs[i] = n
		n += len(txOut.PkScript)
	}

	return pkScriptLocs
}

// NewMsgTx returns a new bitcoin tx message that conforms to the Message
// interface.  The return instance has a default version of TxVersion, and there
// are no transaction inputs or outputs.  Also, the lock time is set to zero
// to indicate the transaction is valid immediately as opposed to some time in
// the future.
func NewMsgTx(version int32) *MsgTx {
	return &MsgTx{
		Version: version,
		TxIn:    make([]*TxIn, 0, defaultTxInOutAlloc),
		TxOut:   make([]*TxOut, 0, defaultTxInOutAlloc),
	}
}

// readOutPoint reads the next sequence of bytes from r as an OutPoint.
func readOutPoint(r io.Reader, _ uint32, _ int32, op *OutPoint) error {
	_, err := io.ReadFull(r, op.Hash[:])
	if err != nil {
		return err
	}

	op.Index, err = binarySerializer.Uint32(r, littleEndian)

	return err
}

// writeOutPoint encodes op to the bitcoin protocol encoding for an OutPoint
// to w.
func writeOutPoint(w io.Writer, _ uint32, _ int32, op *OutPoint) error {
	_, err := w.Write(op.Hash[:])
	if err != nil {
		return err
	}

	return binarySerializer.PutUint32(w, littleEndian, op.Index)
}

// readScript reads a variable length byte array that represents a transaction
// script.  It is encoded as a varInt containing the length of the array
// followed by the bytes themselves.  An error is returned if the length is
// greater than the passed maxAllowed parameter which helps protect against
// memory exhaustion attacks and forced panics through malformed messages.  The
// fieldName parameter is only used for the error message so it provides more
// context in the error.
func readScript(r io.Reader, pver uint32, maxAllowed uint64, fieldName string) ([]byte, error) {
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
		return nil, messageError("readScript", str)
	}

	b := scriptPool.Borrow(count)
	_, err = io.ReadFull(r, b)
	if err != nil {
		scriptPool.Return(b)
		return nil, err
	}

	return b, nil
}

// readTxIn reads the next sequence of bytes from r as a transaction input
// (TxIn).
func readTxIn(r io.Reader, pver uint32, version int32, ti *TxIn) error {
	err := readOutPoint(r, pver, version, &ti.PreviousOutPoint)
	if err != nil {
		return err
	}

	ti.SignatureScript, err = readScript(r, pver, maxTxInPerMessage(),
		"transaction input signature script")
	if err != nil {
		return err
	}

	return readElement(r, &ti.Sequence)
}

// writeTxIn encodes ti to the bitcoin protocol encoding for a transaction
// input (TxIn) to w.
func writeTxIn(w io.Writer, pver uint32, version int32, ti *TxIn) error {
	err := writeOutPoint(w, pver, version, &ti.PreviousOutPoint)
	if err != nil {
		return err
	}

	err = WriteVarBytes(w, pver, ti.SignatureScript)
	if err != nil {
		return err
	}

	return binarySerializer.PutUint32(w, littleEndian, ti.Sequence)
}

// readTxOut reads the next sequence of bytes from r as a transaction output
// (TxOut).
func readTxOut(r io.Reader, pver uint32, _ int32, to *TxOut) error {
	err := readElement(r, &to.Value)
	if err != nil {
		return err
	}

	to.PkScript, err = readScript(r, pver, maxMessagePayload(),
		"transaction output public key script")

	return err
}

// WriteTxOut encodes to into the bitcoin protocol encoding for a transaction
// output (TxOut) to w.
//
// NOTE: This function is exported to allow txscript to compute the
// new sighashes for witness transactions (BIP0143).
func WriteTxOut(w io.Writer, pver uint32, _ int32, to *TxOut) error {
	err := binarySerializer.PutUint64(w, littleEndian, uint64(to.Value))
	if err != nil {
		return err
	}

	return WriteVarBytes(w, pver, to.PkScript)
}
