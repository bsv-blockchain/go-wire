package wire

import (
	"bytes"
	"testing"
)

// allDecodeCommands lists every command makeEmptyMessage understands, so the
// fuzzer exercises each message type's Bsvdecode.
var allDecodeCommands = []string{
	CmdVersion, CmdVerAck, CmdGetAddr, CmdAddr, CmdGetBlocks, CmdInv,
	CmdGetData, CmdNotFound, CmdBlock, CmdTx, CmdExtendedTx, CmdGetHeaders,
	CmdHeaders, CmdPing, CmdPong, CmdMemPool, CmdFilterAdd, CmdFilterClear,
	CmdFilterLoad, CmdMerkleBlock, CmdReject, CmdSendHeaders, CmdFeeFilter,
	CmdGetCFilters, CmdGetCFHeaders, CmdGetCFCheckpt, CmdCFilter, CmdCFHeaders,
	CmdCFCheckpt, CmdProtoconf, CmdExtMsg, CmdSendcmpct, CmdAuthch, CmdAuthresp,
	CmdCreateStream, CmdStreamAck,
}

// FuzzMessageDecode feeds arbitrary bytes to every wire message decoder
// (Message.Bsvdecode) — the code path that runs on untrusted data received from
// a peer. A decoder must never panic or attempt an unbounded allocation from a
// length/count field in the payload (e.g. a 9-byte varint claiming 2^64 items).
// ReadMessageWithEncodingN bounds the *payload size* per message type before
// dispatch, but a count varint inside can still exceed the item data actually
// present, so the per-decoder count bounds are what this targets.
func FuzzMessageDecode(f *testing.F) {
	// A varint encoding 0xFFFFFFFFFFFFFFFF — a hostile "count" with no items
	// behind it. A decoder that does make([]T, count) without bounding it first
	// panics ("makeslice: len out of range") or OOMs here.
	hugeCount := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	for _, c := range allDecodeCommands {
		f.Add(c, []byte{})
		f.Add(c, make([]byte, 24))
		f.Add(c, hugeCount)
	}

	// Regression: a protoconf whose stream-policies length field is huge
	// previously panicked via an unbounded make([]byte, vi) in
	// MsgProtoconf.Bsvdecode. (testdata/ is gitignored here, so the crasher
	// lives as an explicit seed.)
	f.Add(CmdProtoconf, []byte("00000\xff00000000"))

	f.Fuzz(func(_ *testing.T, command string, data []byte) {
		msg, err := makeEmptyMessage(command)
		if err != nil {
			return // not a registered command
		}

		// Must not panic on arbitrary peer bytes; an error return is fine.
		_ = msg.Bsvdecode(bytes.NewReader(data), ProtocolVersion, LatestEncoding)
	})
}
