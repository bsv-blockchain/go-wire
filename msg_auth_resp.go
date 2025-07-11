// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"io"
)

var (
	SECP256K1_COMP_PUB_KEY_SIZE_IN_BYTES = 0x21 //nolint:revive // this is already being used in the code
	SECP256K1_DER_SIGN_MIN_SIZE_IN_BYTES = 0x46 //nolint:revive // this is already being used in the code
	SECP256K1_DER_SIGN_MAX_SIZE_IN_BYTES = 0x48 //nolint:revive // this is already being used in the code
)

// MsgAuthresp authentication response message
type MsgAuthresp struct {
	PublicKeyLength uint32
	PublicKey       []byte
	ClientNonce     uint64
	SignatureLength uint32
	Signature       []byte
}

// Bsvdecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgAuthresp) Bsvdecode(r io.Reader, pver uint32, _ MessageEncoding) error {
	var err error

	msg.PublicKey, err = ReadVarBytes(r, pver, msg.MaxPayloadLength(pver), "challenge")
	if err != nil {
		return err
	}

	msg.PublicKeyLength = uint32(len(msg.PublicKey)) //nolint:gosec // G115 Conversion

	// Read stop hash
	err = readElement(r, &msg.ClientNonce)
	if err != nil {
		return err
	}

	msg.Signature, err = ReadVarBytes(r, pver, msg.MaxPayloadLength(pver), "challenge")
	if err != nil {
		return err
	}

	msg.SignatureLength = uint32(len(msg.Signature)) //nolint:gosec // G115 Conversion

	return nil
}

// BsvEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgAuthresp) BsvEncode(w io.Writer, _ uint32, _ MessageEncoding) error {
	return writeElements(w, msg.PublicKeyLength, msg.PublicKey, msg.ClientNonce, msg.SignatureLength, msg.Signature)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgAuthresp) Command() string {
	return CmdAuthresp
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgAuthresp) MaxPayloadLength(_ uint32) uint64 {
	//nolint:gosec // G115 Conversion
	return uint64(4 + SECP256K1_COMP_PUB_KEY_SIZE_IN_BYTES + 8 + 4 + SECP256K1_DER_SIGN_MAX_SIZE_IN_BYTES)
}

// NewMsgAuthresp returns a new auth challenge message
func NewMsgAuthresp(publickKey, signature []byte) *MsgAuthresp {
	nonce, _ := RandomUint64()

	return &MsgAuthresp{
		PublicKeyLength: uint32(len(publickKey)), //nolint:gosec // G115 Conversion
		PublicKey:       publickKey,
		ClientNonce:     nonce,
		SignatureLength: uint32(len(signature)), //nolint:gosec // G115 Conversion
		Signature:       signature,
	}
}
