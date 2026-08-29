// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
)

// MsgBlockTxn implements the Message interface and represents a bitcoin
// blocktxn message. It carries the full transactions a peer asked for with a
// getblocktxn message, in the order the request listed them.
type MsgBlockTxn struct {
	BlockHash    chainhash.Hash
	Transactions []*MsgTx
}

// AddTransaction adds a transaction to the message.
func (msg *MsgBlockTxn) AddTransaction(tx *MsgTx) error {
	msg.Transactions = append(msg.Transactions, tx)

	return nil
}

// Bsvdecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgBlockTxn) Bsvdecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	const op = "MsgBlockTxn.Bsvdecode"

	err := readElement(r, &msg.BlockHash)
	if err != nil {
		return err
	}

	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	if count > maxTxPerBlock() {
		str := fmt.Sprintf("too many transactions to fit into a block "+
			"[count %d, max %d]", count, maxTxPerBlock())

		return messageError(op, str)
	}

	msg.Transactions = make([]*MsgTx, 0, count)

	for i := uint64(0); i < count; i++ {
		tx := &MsgTx{}

		err = tx.Bsvdecode(r, pver, enc)
		if err != nil {
			return err
		}

		msg.Transactions = append(msg.Transactions, tx)
	}

	return nil
}

// BsvEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgBlockTxn) BsvEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	err := writeElement(w, &msg.BlockHash)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, uint64(len(msg.Transactions)))
	if err != nil {
		return err
	}

	for _, tx := range msg.Transactions {
		err = tx.BsvEncode(w, pver, enc)
		if err != nil {
			return err
		}
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgBlockTxn) Command() string {
	return CmdBlockTxn
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgBlockTxn) MaxPayloadLength(_ uint32) uint64 {
	// The transactions all come from one block, so the block payload limit is
	// the natural ceiling.
	return MaxBlockPayload()
}

// NewMsgBlockTxn returns a new bitcoin blocktxn message that conforms to the
// Message interface.  See MsgBlockTxn for details.
func NewMsgBlockTxn(blockHash *chainhash.Hash) *MsgBlockTxn {
	return &MsgBlockTxn{
		BlockHash: *blockHash,
	}
}
