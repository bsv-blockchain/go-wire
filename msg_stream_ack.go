package wire

import (
	"io"
)

// MsgStreamAck implements the Message interface and represents a bitcoin
// streamack message. It is sent in response to a createstream message to
// confirm the new stream has been accepted and associated.
type MsgStreamAck struct {
	AssociationID []byte
	StreamType    StreamType
}

// Bsvdecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgStreamAck) Bsvdecode(r io.Reader, pver uint32, _ MessageEncoding) error {
	var err error

	msg.AssociationID, err = ReadVarBytes(r, pver, MaxAssociationIDLen, "AssociationID")
	if err != nil {
		return err
	}

	var streamType uint8
	if err = readElement(r, &streamType); err != nil {
		return err
	}

	msg.StreamType = StreamType(streamType)

	return nil
}

// BsvEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgStreamAck) BsvEncode(w io.Writer, pver uint32, _ MessageEncoding) error {
	if err := WriteVarBytes(w, pver, msg.AssociationID); err != nil {
		return err
	}

	if err := writeElement(w, uint8(msg.StreamType)); err != nil {
		return err
	}

	return nil
}

// Command returns the protocol command string for the message.
func (msg *MsgStreamAck) Command() string {
	return CmdStreamAck
}

// MaxPayloadLength returns the maximum length the payload can be for the receiver.
func (msg *MsgStreamAck) MaxPayloadLength(_ uint32) uint64 {
	// varint(association_id_len) + association_id + stream_type(1)
	return MaxVarIntPayload + MaxAssociationIDLen + 1
}

// NewMsgStreamAck returns a new streamack message.
func NewMsgStreamAck(associationID []byte, streamType StreamType) *MsgStreamAck {
	return &MsgStreamAck{
		AssociationID: associationID,
		StreamType:    streamType,
	}
}
