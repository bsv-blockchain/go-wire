// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
)

// maxFlagsPerMerkleBlock returns the maximum number of flag bytes that could
// possibly fit into a merkle block.  Since a single bit represents each transaction
// , this is the max number of transactions per block divided by
// 8 bits per byte.  Then an extra one to cover partials.
func maxFlagsPerMerkleBlock() uint64 {
	return maxTxPerBlock() / 8
}

// MsgMerkleBlock implements the Message interface and represents a bitcoin
// merkleblock message which is used to reset a Bloom filter.
//
// This message was not added until protocol version BIP0037Version.
type MsgMerkleBlock struct {
	Header       BlockHeader
	Transactions uint32
	Hashes       []*chainhash.Hash
	Flags        []byte
}

// AddTxHash adds a new transaction hash to the message.
func (msg *MsgMerkleBlock) AddTxHash(hash *chainhash.Hash) error {
	if uint64(len(msg.Hashes))+1 > maxTxPerBlock() {
		str := fmt.Sprintf("too many tx hashes for message [max %v]",
			maxTxPerBlock())
		return messageError("MsgMerkleBlock.AddTxHash", str)
	}

	msg.Hashes = append(msg.Hashes, hash)

	return nil
}

// Bsvdecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMerkleBlock) Bsvdecode(r io.Reader, pver uint32, _ MessageEncoding) error {
	if pver < BIP0037Version {
		str := fmt.Sprintf("merkleblock message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgMerkleBlock.Bsvdecode", str)
	}

	err := readBlockHeader(r, pver, &msg.Header)
	if err != nil {
		return err
	}

	err = readElement(r, &msg.Transactions)
	if err != nil {
		return err
	}

	// Read num block locator hashes and limit to max.
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	if count > maxTxPerBlock() {
		str := fmt.Sprintf("too many transaction hashes for message "+
			"[count %v, max %v]", count, maxTxPerBlock())
		return messageError("MsgMerkleBlock.Bsvdecode", str)
	}

	// Create a contiguous slice of hashes to deserialize into to
	// reduce the number of allocations.
	hashes := make([]chainhash.Hash, count)
	msg.Hashes = make([]*chainhash.Hash, 0, count)

	for i := uint64(0); i < count; i++ {
		hash := &hashes[i]

		err = readElement(r, hash)
		if err != nil {
			return err
		}

		err = msg.AddTxHash(hash)
		if err != nil {
			return err
		}
	}

	msg.Flags, err = ReadVarBytes(r, pver, maxFlagsPerMerkleBlock(),
		"merkle block flags size")

	return err
}

// BsvEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMerkleBlock) BsvEncode(w io.Writer, pver uint32, _ MessageEncoding) error {
	if pver < BIP0037Version {
		str := fmt.Sprintf("merkleblock message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgMerkleBlock.BsvEncode", str)
	}

	// Read num transaction hashes and limit to max.
	numHashes := len(msg.Hashes)
	if numHashes > int(maxTxPerBlock()) { //nolint:gosec // G115 conversion
		str := fmt.Sprintf("too many transaction hashes for message "+
			"[count %v, max %v]", numHashes, maxTxPerBlock())
		return messageError("MsgMerkleBlock.Bsvdecode", str)
	}

	numFlagBytes := len(msg.Flags)

	//nolint:gosec // G115 Conversion
	if numFlagBytes > int(maxFlagsPerMerkleBlock()) {
		str := fmt.Sprintf("too many flag bytes for message [count %v, "+
			"max %v]", numFlagBytes, maxFlagsPerMerkleBlock())
		return messageError("MsgMerkleBlock.Bsvdecode", str)
	}

	err := writeBlockHeader(w, pver, &msg.Header)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.Transactions)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, uint64(numHashes))
	if err != nil {
		return err
	}

	for _, hash := range msg.Hashes {
		err = writeElement(w, hash)
		if err != nil {
			return err
		}
	}

	return WriteVarBytes(w, pver, msg.Flags)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgMerkleBlock) Command() string {
	return CmdMerkleBlock
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMerkleBlock) MaxPayloadLength(_ uint32) uint64 {
	return MaxBlockPayload()
}

// NewMsgMerkleBlock returns a new bitcoin merkleblock message that conforms to
// the Message interface.  See MsgMerkleBlock for details.
func NewMsgMerkleBlock(bh *BlockHeader) *MsgMerkleBlock {
	return &MsgMerkleBlock{
		Header:       *bh,
		Transactions: 0,
		Hashes:       make([]*chainhash.Hash, 0),
		Flags:        make([]byte, 0),
	}
}
