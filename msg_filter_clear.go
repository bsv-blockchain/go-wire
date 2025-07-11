// Copyright (c) 2014-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
)

// MsgFilterClear implements the Message interface and represents a bitcoin
// filterclear message which is used to reset a Bloom filter.
//
// This message was not added until protocol version BIP0037Version and has
// no payload.
type MsgFilterClear struct{}

// Bsvdecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgFilterClear) Bsvdecode(_ io.Reader, pver uint32, _ MessageEncoding) error {
	if pver < BIP0037Version {
		str := fmt.Sprintf("filterclear message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgFilterClear.Bsvdecode", str)
	}

	return nil
}

// BsvEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgFilterClear) BsvEncode(_ io.Writer, pver uint32, _ MessageEncoding) error {
	if pver < BIP0037Version {
		str := fmt.Sprintf("filterclear message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgFilterClear.BsvEncode", str)
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgFilterClear) Command() string {
	return CmdFilterClear
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgFilterClear) MaxPayloadLength(_ uint32) uint64 {
	return 0
}

// NewMsgFilterClear returns a new bitcoin filterclear message that conforms to the Message
// interface.  See MsgFilterClear for details.
func NewMsgFilterClear() *MsgFilterClear {
	return &MsgFilterClear{}
}
