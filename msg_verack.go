// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"io"
)

// MsgVerAck defines a bitcoin verack message which is used for a peer to
// acknowledge a version message (MsgVersion) after it has used the information
// to negotiate parameters.  It implements the Message interface.
//
// This message has no payload.
type MsgVerAck struct{}

// Bsvdecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgVerAck) Bsvdecode(_ io.Reader, _ uint32, _ MessageEncoding) error {
	return nil
}

// BsvEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgVerAck) BsvEncode(_ io.Writer, _ uint32, _ MessageEncoding) error {
	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgVerAck) Command() string {
	return CmdVerAck
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgVerAck) MaxPayloadLength(_ uint32) uint64 {
	return 0
}

// NewMsgVerAck returns a new bitcoin verack message that conforms to the
// Message interface.
func NewMsgVerAck() *MsgVerAck {
	return &MsgVerAck{}
}
