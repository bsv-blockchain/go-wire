// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
	"math"
)

// ShortIDSize is the length in bytes of a BIP152 short transaction ID on the
// wire. A short ID is written as a little endian uint32 holding the least
// significant word, followed by a little endian uint16 holding the most
// significant word.
const ShortIDSize = 6

// maxShortID is the largest value a 6 byte short transaction ID can hold.
const maxShortID = uint64(1)<<(ShortIDSize*8) - 1

// PrefilledTransaction pairs a transaction with its absolute index inside the
// block that a compact block describes. On the wire the index is stored as the
// difference from the previous prefilled index plus one, so the indexes must be
// strictly increasing.
type PrefilledTransaction struct {
	Index uint32
	Tx    *MsgTx
}

// MsgCmpctBlock implements the Message interface and represents a bitcoin
// cmpctblock message. It carries a block header, the short transaction IDs of
// the transactions the sender expects the peer to hold already, and the full
// transactions the peer is unlikely to hold.
type MsgCmpctBlock struct {
	Header       BlockHeader
	Nonce        uint64
	ShortIDs     []uint64
	PrefilledTxn []PrefilledTransaction
}

// BlockTxCount returns the total number of transactions in the block that the
// compact block describes.
func (msg *MsgCmpctBlock) BlockTxCount() int {
	return len(msg.ShortIDs) + len(msg.PrefilledTxn)
}

// AddPrefilledTransaction appends a prefilled transaction at the given absolute
// index. The index must be greater than the index of the last prefilled
// transaction, because the wire encoding stores the difference between them.
func (msg *MsgCmpctBlock) AddPrefilledTransaction(index uint32, tx *MsgTx) error {
	if n := len(msg.PrefilledTxn); n > 0 {
		if last := msg.PrefilledTxn[n-1].Index; index <= last {
			str := fmt.Sprintf("non-strictly-monotonic prefilled index "+
				"[index %d, previous %d]", index, last)

			return messageError("MsgCmpctBlock.AddPrefilledTransaction", str)
		}
	}

	msg.PrefilledTxn = append(msg.PrefilledTxn, PrefilledTransaction{
		Index: index,
		Tx:    tx,
	})

	return nil
}

// Bsvdecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgCmpctBlock) Bsvdecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	const op = "MsgCmpctBlock.Bsvdecode"

	err := readBlockHeader(r, pver, &msg.Header)
	if err != nil {
		return err
	}

	err = readElement(r, &msg.Nonce)
	if err != nil {
		return err
	}

	shortIDCount, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	if shortIDCount > maxTxPerBlock() {
		str := fmt.Sprintf("too many short ids to fit into a block "+
			"[count %d, max %d]", shortIDCount, maxTxPerBlock())

		return messageError(op, str)
	}

	// The count is attacker controlled, so let append grow the slice
	// instead of preallocating a capacity the payload may not fill.
	msg.ShortIDs = make([]uint64, 0)

	for i := uint64(0); i < shortIDCount; i++ {
		var lsb uint32

		lsb, err = binarySerializer.Uint32(r, littleEndian)
		if err != nil {
			return err
		}

		var msb uint16

		msb, err = binarySerializer.Uint16(r, littleEndian)
		if err != nil {
			return err
		}

		msg.ShortIDs = append(msg.ShortIDs, uint64(msb)<<32|uint64(lsb))
	}

	prefilledCount, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	if prefilledCount > maxTxPerBlock() {
		str := fmt.Sprintf("too many prefilled transactions to fit into a "+
			"block [count %d, max %d]", prefilledCount, maxTxPerBlock())

		return messageError(op, str)
	}

	// The count is attacker controlled, so let append grow the slice
	// instead of preallocating a capacity the payload may not fill.
	msg.PrefilledTxn = make([]PrefilledTransaction, 0)

	var previous uint32

	for i := uint64(0); i < prefilledCount; i++ {
		var index uint32

		index, err = readDifferentialIndex(r, pver, op, previous, i > 0)
		if err != nil {
			return err
		}

		tx := &MsgTx{}

		err = tx.Bsvdecode(r, pver, enc)
		if err != nil {
			return err
		}

		msg.PrefilledTxn = append(msg.PrefilledTxn, PrefilledTransaction{
			Index: index,
			Tx:    tx,
		})
		previous = index
	}

	return nil
}

// BsvEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgCmpctBlock) BsvEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	const op = "MsgCmpctBlock.BsvEncode"

	err := writeBlockHeader(w, pver, &msg.Header)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.Nonce)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, uint64(len(msg.ShortIDs)))
	if err != nil {
		return err
	}

	for _, shortID := range msg.ShortIDs {
		if shortID > maxShortID {
			str := fmt.Sprintf("short id exceeds 6 bytes [id %d]", shortID)

			return messageError(op, str)
		}

		err = binarySerializer.PutUint32(w, littleEndian, uint32(shortID&math.MaxUint32))
		if err != nil {
			return err
		}

		err = binarySerializer.PutUint16(w, littleEndian, uint16(shortID>>32&math.MaxUint16))
		if err != nil {
			return err
		}
	}

	err = WriteVarInt(w, pver, uint64(len(msg.PrefilledTxn)))
	if err != nil {
		return err
	}

	var previous uint32

	for i, prefilled := range msg.PrefilledTxn {
		err = writeDifferentialIndex(w, pver, op, prefilled.Index, previous, i > 0)
		if err != nil {
			return err
		}

		err = prefilled.Tx.BsvEncode(w, pver, enc)
		if err != nil {
			return err
		}

		previous = prefilled.Index
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgCmpctBlock) Command() string {
	return CmdCmpctBlock
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgCmpctBlock) MaxPayloadLength(_ uint32) uint64 {
	// A compact block is always smaller than the block it describes, so the
	// block payload limit is the natural ceiling.
	return MaxBlockPayload()
}

// NewMsgCmpctBlock returns a new bitcoin cmpctblock message that conforms to
// the Message interface.  See MsgCmpctBlock for details.
func NewMsgCmpctBlock(header *BlockHeader, nonce uint64) *MsgCmpctBlock {
	return &MsgCmpctBlock{
		Header: *header,
		Nonce:  nonce,
	}
}

// readDifferentialIndex reads one differentially encoded index from r and
// returns the absolute index. previous holds the last absolute index and
// hasPrevious reports whether one exists. The wire value is the difference from
// the previous index plus one, so the indexes are always strictly increasing.
func readDifferentialIndex(r io.Reader, pver uint32, op string, previous uint32,
	hasPrevious bool,
) (uint32, error) {
	value, err := ReadVarInt(r, pver)
	if err != nil {
		return 0, err
	}

	if value > math.MaxUint32 {
		str := fmt.Sprintf("index overflowed 32 bits [value %d]", value)

		return 0, messageError(op, str)
	}

	var offset uint64
	if hasPrevious {
		offset = uint64(previous) + 1
	}

	if value+offset > math.MaxUint32 {
		str := fmt.Sprintf("indexes overflowed 32 bits [value %d, offset %d]",
			value, offset)

		return 0, messageError(op, str)
	}

	return uint32(value + offset), nil
}

// writeDifferentialIndex writes index to w as the difference from the previous
// absolute index plus one. It fails when the indexes are not strictly
// increasing, because the encoding cannot represent that.
func writeDifferentialIndex(w io.Writer, pver uint32, op string, index, previous uint32,
	hasPrevious bool,
) error {
	var offset uint64
	if hasPrevious {
		offset = uint64(previous) + 1
	}

	if uint64(index) < offset {
		str := fmt.Sprintf("non-strictly-monotonic index [index %d, previous %d]",
			index, previous)

		return messageError(op, str)
	}

	return WriteVarInt(w, pver, uint64(index)-offset)
}
