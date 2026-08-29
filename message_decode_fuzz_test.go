package wire

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// allDecodeCommands lists every command makeEmptyMessage understands, so both
// the deterministic regression matrix (TestMessageDecodeNoPanic) and the fuzzer
// (FuzzMessageDecode) exercise each message type's Bsvdecode.
var allDecodeCommands = []string{
	CmdVersion, CmdVerAck, CmdGetAddr, CmdAddr, CmdGetBlocks, CmdInv,
	CmdGetData, CmdNotFound, CmdBlock, CmdTx, CmdExtendedTx, CmdGetHeaders,
	CmdHeaders, CmdPing, CmdPong, CmdMemPool, CmdFilterAdd, CmdFilterClear,
	CmdFilterLoad, CmdMerkleBlock, CmdReject, CmdSendHeaders, CmdFeeFilter,
	CmdGetCFilters, CmdGetCFHeaders, CmdGetCFCheckpt, CmdCFilter, CmdCFHeaders,
	CmdCFCheckpt, CmdProtoconf, CmdExtMsg, CmdSendcmpct, CmdAuthch, CmdAuthresp,
	CmdCreateStream, CmdStreamAck, CmdCmpctBlock, CmdGetBlockTxn, CmdBlockTxn,
}

// hugeCount is a varint encoding 0xFFFFFFFFFFFFFFFF — a hostile "count" with no
// items behind it. A decoder that does make([]T, count) without bounding it
// first panics ("makeslice: len out of range") or OOMs on this input.
var hugeCount = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// protoconfCrasher is a regression input: a protoconf whose stream-policies
// length field is huge previously panicked via an unbounded make([]byte, vi) in
// MsgProtoconf.Bsvdecode. (testdata/ is gitignored here, so the crasher lives as
// an explicit input rather than a saved corpus file.)
var protoconfCrasher = []byte("00000\xff00000000")

// hostileDecodeInputs are payloads that must never make a decoder panic or
// attempt an unbounded allocation, regardless of which message type receives
// them: nothing at all, a short all-zero header, and a lone 2^64 count varint.
func hostileDecodeInputs() [][]byte {
	return [][]byte{
		nil,
		make([]byte, 24),
		hugeCount,
	}
}

// TestMessageDecodeNoPanic is the deterministic regression guard for
// Message.Bsvdecode — the code path that runs on untrusted data received from a
// peer. It feeds every registered decoder a set of hostile payloads and asserts
// Bsvdecode never panics or attempts an unbounded allocation from a length/count
// field in the payload; an error return is fine.
//
// This is where the exhaustive per-command coverage lives (and runs on every
// `go test`, independent of the fuzzer). Keeping it out of the fuzz seed corpus
// lets FuzzMessageDecode stay small enough that Go's baseline-coverage pass
// finishes within CI's short fuzz-time budget — a large seed corpus was making
// that pass exceed the deadline and fail flakily ("context deadline exceeded").
func TestMessageDecodeNoPanic(t *testing.T) {
	for _, command := range allDecodeCommands {
		for _, data := range hostileDecodeInputs() {
			assertDecodeNoPanic(t, command, data)
		}
	}

	assertDecodeNoPanic(t, CmdProtoconf, protoconfCrasher)
}

// assertDecodeNoPanic decodes data as command and fails the test if Bsvdecode
// panics. Each case runs as its own subtest so one panicking decoder does not
// mask the others.
func assertDecodeNoPanic(t *testing.T, command string, data []byte) {
	t.Helper()

	t.Run(command, func(t *testing.T) {
		msg, err := makeEmptyMessage(command)
		require.NoError(t, err)

		require.NotPanics(t, func() {
			_ = msg.Bsvdecode(bytes.NewReader(data), ProtocolVersion, LatestEncoding)
		})
	})
}

// FuzzMessageDecode feeds arbitrary bytes to every wire message decoder
// (Message.Bsvdecode) — the code path that runs on untrusted data received from
// a peer. A decoder must never panic or attempt an unbounded allocation from a
// length/count field in the payload (e.g. a 9-byte varint claiming 2^64 items).
// ReadMessageWithEncodingN bounds the *payload size* per message type before
// dispatch, but a count varint inside can still exceed the item data actually
// present, so the per-decoder count bounds are what this targets.
//
// The target decoder is chosen by index into allDecodeCommands rather than by a
// raw command string, so the fuzzer reaches every decoder just by mutating a
// single byte. That keeps the seed corpus — and therefore Go's baseline-coverage
// pass, which replays every seed before fuzzing begins — small enough to finish
// inside CI's short fuzz-time budget. A seed per command (100+ seeds) made that
// pass overrun the budget and fail flakily with "context deadline exceeded"
// before a single mutation ran. The exhaustive, deterministic hostile-input
// matrix lives in TestMessageDecodeNoPanic.
func FuzzMessageDecode(f *testing.F) {
	f.Add(uint8(0), []byte(nil))
	f.Add(uint8(0), hugeCount)
	for i, c := range allDecodeCommands {
		if c == CmdProtoconf {
			f.Add(uint8(i), protoconfCrasher) // known past crasher
			break
		}
	}

	f.Fuzz(func(_ *testing.T, cmdIndex uint8, data []byte) {
		command := allDecodeCommands[int(cmdIndex)%len(allDecodeCommands)]

		msg, err := makeEmptyMessage(command)
		if err != nil {
			return // command not built by makeEmptyMessage
		}

		// Must not panic on arbitrary peer bytes; an error return is fine.
		_ = msg.Bsvdecode(bytes.NewReader(data), ProtocolVersion, LatestEncoding)
	})
}
