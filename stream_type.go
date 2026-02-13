package wire

// StreamType represents the type of stream within a multistream association.
type StreamType uint8

const (
	// StreamTypeUnknown is an unknown stream type.
	StreamTypeUnknown StreamType = 0
	// StreamTypeGeneral is a general stream type.
	StreamTypeGeneral StreamType = 1
	// StreamTypeData1 is a data stream type.
	StreamTypeData1 StreamType = 2
	// StreamTypeData2 is a data stream type.
	StreamTypeData2 StreamType = 3
	// StreamTypeData3 is a data stream type.
	StreamTypeData3 StreamType = 4
	// StreamTypeData4 is a data stream type.
	StreamTypeData4 StreamType = 5
)

// MaxAssociationIDLen is the maximum allowed length for an association ID
// in the version message. Format is [type byte][UUID bytes], with the most
// common format being 1 + 16 = 17 bytes, but we allow up to 129 bytes
// for future extensibility.
const MaxAssociationIDLen = 129
