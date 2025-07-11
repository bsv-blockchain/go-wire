// Copyright (c) 2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"io"

	"github.com/bsv-blockchain/go-bt/v2/chainhash"
)

// MsgGetCFHeaders is a message similar to MsgGetHeaders, but for committed
// filter headers. It allows setting the FilterType field to get headers in the
// chain of basic (0x00) or extended (0x01) headers.
type MsgGetCFHeaders struct {
	FilterType  FilterType
	StartHeight uint32
	StopHash    chainhash.Hash
}

// Bsvdecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgGetCFHeaders) Bsvdecode(r io.Reader, _ uint32, _ MessageEncoding) error {
	err := readElement(r, &msg.FilterType)
	if err != nil {
		return err
	}

	err = readElement(r, &msg.StartHeight)
	if err != nil {
		return err
	}

	return readElement(r, &msg.StopHash)
}

// BsvEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgGetCFHeaders) BsvEncode(w io.Writer, _ uint32, _ MessageEncoding) error {
	err := writeElement(w, msg.FilterType)
	if err != nil {
		return err
	}

	err = writeElement(w, &msg.StartHeight)
	if err != nil {
		return err
	}

	return writeElement(w, &msg.StopHash)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgGetCFHeaders) Command() string {
	return CmdGetCFHeaders
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgGetCFHeaders) MaxPayloadLength(_ uint32) uint64 {
	// Filter type + uint32 + block hash
	return 1 + 4 + chainhash.HashSize
}

// NewMsgGetCFHeaders returns a new bitcoin getcfheader message that conforms to
// the Message interface using the passed parameters and defaults for the
// remaining fields.
func NewMsgGetCFHeaders(filterType FilterType, startHeight uint32,
	stopHash *chainhash.Hash,
) *MsgGetCFHeaders {
	return &MsgGetCFHeaders{
		FilterType:  filterType,
		StartHeight: startHeight,
		StopHash:    *stopHash,
	}
}
