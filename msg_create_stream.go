package wire

import (
	"fmt"
	"io"
)

// MsgCreateStream implements the Message interface and represents a bitcoin
// createstream message. It is sent as the first message on a new TCP connection
// to associate it with an existing peer connection as an additional stream.
type MsgCreateStream struct {
	AssociationID    []byte
	StreamType       StreamType
	StreamPolicyName string
}

// Bsvdecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgCreateStream) Bsvdecode(r io.Reader, pver uint32, _ MessageEncoding) error {
	var err error

	msg.AssociationID, err = ReadVarBytes(r, pver, MaxAssociationIDLen, "AssociationID")
	if err != nil {
		return err
	}

	if len(msg.AssociationID) == 0 {
		return messageError("MsgCreateStream.Bsvdecode", "association ID must not be empty")
	}

	var streamType uint8
	if err = readElement(r, &streamType); err != nil {
		return err
	}

	msg.StreamType = StreamType(streamType)

	msg.StreamPolicyName, err = ReadVarString(r, pver)
	if err != nil {
		return err
	}

	return nil
}

// BsvEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgCreateStream) BsvEncode(w io.Writer, pver uint32, _ MessageEncoding) error {
	if len(msg.AssociationID) == 0 {
		return messageError("MsgCreateStream.BsvEncode", "association ID must not be empty")
	}

	if len(msg.AssociationID) > MaxAssociationIDLen {
		str := fmt.Sprintf("association ID too long [len %v, max %v]",
			len(msg.AssociationID), MaxAssociationIDLen)
		return messageError("MsgCreateStream.BsvEncode", str)
	}

	if err := WriteVarBytes(w, pver, msg.AssociationID); err != nil {
		return err
	}

	if err := writeElement(w, uint8(msg.StreamType)); err != nil {
		return err
	}

	if err := WriteVarString(w, pver, msg.StreamPolicyName); err != nil {
		return err
	}

	return nil
}

// Command returns the protocol command string for the message.
func (msg *MsgCreateStream) Command() string {
	return CmdCreateStream
}

// MaxPayloadLength returns the maximum length the payload can be for the receiver.
func (msg *MsgCreateStream) MaxPayloadLength(_ uint32) uint64 {
	// varint(association_id_len) + association_id + stream_type(1) + varint(policy_len) + policy_string
	return MaxVarIntPayload + MaxAssociationIDLen + 1 + MaxVarIntPayload + MaxUserAgentLen
}

// NewMsgCreateStream returns a new createstream message.
func NewMsgCreateStream(associationID []byte, streamType StreamType, policyName string) *MsgCreateStream {
	return &MsgCreateStream{
		AssociationID:    associationID,
		StreamType:       streamType,
		StreamPolicyName: policyName,
	}
}
