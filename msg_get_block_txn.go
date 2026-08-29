// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
)

// MsgGetBlockTxn implements the Message interface and represents a bitcoin
// getblocktxn message. A peer sends it after a cmpctblock message to ask for
// the full transactions it could not reconstruct from its own mempool.
//
// Indexes holds absolute transaction positions inside the block. On the wire
// each index is stored as the difference from the previous index plus one, so
// the indexes must be strictly increasing.
type MsgGetBlockTxn struct {
	BlockHash chainhash.Hash
	Indexes   []uint32
}

// Bsvdecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgGetBlockTxn) Bsvdecode(r io.Reader, pver uint32, _ MessageEncoding) error {
	const op = "MsgGetBlockTxn.Bsvdecode"

	err := readElement(r, &msg.BlockHash)
	if err != nil {
		return err
	}

	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	if count > maxTxPerBlock() {
		str := fmt.Sprintf("too many transaction indexes to fit into a block "+
			"[count %d, max %d]", count, maxTxPerBlock())

		return messageError(op, str)
	}

	msg.Indexes = make([]uint32, 0, count)

	var previous uint32

	for i := uint64(0); i < count; i++ {
		var index uint32

		index, err = readDifferentialIndex(r, pver, op, previous, i > 0)
		if err != nil {
			return err
		}

		msg.Indexes = append(msg.Indexes, index)
		previous = index
	}

	return nil
}

// BsvEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgGetBlockTxn) BsvEncode(w io.Writer, pver uint32, _ MessageEncoding) error {
	const op = "MsgGetBlockTxn.BsvEncode"

	err := writeElement(w, &msg.BlockHash)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, uint64(len(msg.Indexes)))
	if err != nil {
		return err
	}

	var previous uint32

	for i, index := range msg.Indexes {
		err = writeDifferentialIndex(w, pver, op, index, previous, i > 0)
		if err != nil {
			return err
		}

		previous = index
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgGetBlockTxn) Command() string {
	return CmdGetBlockTxn
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgGetBlockTxn) MaxPayloadLength(_ uint32) uint64 {
	// Block hash + index count (varInt) + one varInt per transaction that
	// could possibly fit into a block.
	length := uint64(chainhash.HashSize) + MaxVarIntPayload +
		MaxVarIntPayload*maxTxPerBlock()

	if length > maxMessagePayload() {
		return maxMessagePayload()
	}

	return length
}

// NewMsgGetBlockTxn returns a new bitcoin getblocktxn message that conforms to
// the Message interface.  See MsgGetBlockTxn for details.
func NewMsgGetBlockTxn(blockHash *chainhash.Hash, indexes []uint32) *MsgGetBlockTxn {
	return &MsgGetBlockTxn{
		BlockHash: *blockHash,
		Indexes:   indexes,
	}
}
