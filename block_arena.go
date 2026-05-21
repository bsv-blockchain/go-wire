// Copyright (c) 2024 The go-wire developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

// blockArenaChunkSize is the maximum size in bytes of any standard chunk
// allocated by blockArena. 4 MiB matches a typical OS huge-page boundary and
// is large enough to hold dozens of standard scripts in a single allocation.
const blockArenaChunkSize = 4 * 1024 * 1024 // 4 MiB

// blockArenaMinFirstChunk is the lower bound for the first chunk size when a
// sized arena is requested with a very small hint. Keeps tiny-block decodes
// from paying a 4 MiB tax while still amortizing across a handful of allocs.
const blockArenaMinFirstChunk = 4 * 1024 // 4 KiB

// blockArena is a chunked bump-pointer allocator used during MsgBlock decoding
// to eliminate the per-transaction heap allocation that the old scratch-buffer
// approach caused.
//
// Design constraints:
//  1. Returned slices are stable forever — no reallocation or copy ever moves
//     previously returned memory.
//  2. cap == len on every returned slice so callers cannot accidentally write
//     past one script into the next script's bytes.
//  3. Alloc(0) returns nil to match make([]byte, 0) semantics.
//  4. Oversize requests (n > chunkSize) get a private chunk; subsequent small
//     allocs do not bleed into the oversize allocation.
//  5. The first chunk is allocated lazily on the first standard-sized Alloc
//     so decoding a coinbase-only block (or a block whose only allocations
//     are oversize) costs no standard-chunk memory.
//
// Ownership: the arena is created per-block-decode, lives for the duration of
// the block's lifetime, and is never explicitly freed. The GC reclaims chunks
// when the decoded MsgBlock (and all its script slices) become unreachable.
type blockArena struct {
	active   []byte   // the chunk currently being filled; nil when no chunk allocated yet
	offset   int      // write cursor within active
	others   [][]byte // previously-filled standard chunks + any oversize chunks
	sizeHint int      // first-chunk size hint; clamped on first standard Alloc
}

// newBlockArena returns a lazy blockArena. The first chunk is allocated on the
// first standard-sized Alloc, sized to fit the request (clamped to
// [blockArenaMinFirstChunk, blockArenaChunkSize]).
func newBlockArena() *blockArena {
	return &blockArena{}
}

// newBlockArenaSized returns a lazy blockArena that, on its first standard
// Alloc, will allocate a starter chunk sized to at least sizeHint (clamped to
// [blockArenaMinFirstChunk, blockArenaChunkSize]). A hint of 0 or less is
// equivalent to newBlockArena.
//
// Use this when the caller has cheap insight into how much script data the
// block will contain (e.g. txCount * average-script-bytes) so the first chunk
// is sized for the actual block rather than the worst case.
func newBlockArenaSized(sizeHint int) *blockArena {
	return &blockArena{sizeHint: sizeHint}
}

// Alloc returns a byte slice of exactly n bytes backed by the arena.
//
// The returned slice has cap == len == n. Calling Alloc again does not
// invalidate any previously returned slice. Alloc(0) returns nil.
func (a *blockArena) Alloc(n int) []byte {
	if n == 0 {
		return nil
	}

	// Oversize: request exceeds the standard chunk size. Give it a private
	// chunk parked in `others` so it never participates in the bump-pointer
	// fast path. The active standard chunk (if any) is untouched.
	if n > blockArenaChunkSize {
		chunk := make([]byte, n)
		a.others = append(a.others, chunk)
		return chunk[0:n:n]
	}

	// Lazy first standard chunk: nothing allocated yet. Size it to fit both
	// the current request and the caller's size hint, capped at the standard
	// chunk size and floored at the minimum first-chunk size.
	if a.active == nil {
		first := n
		if a.sizeHint > first {
			first = a.sizeHint
		}
		if first < blockArenaMinFirstChunk {
			first = blockArenaMinFirstChunk
		}
		if first > blockArenaChunkSize {
			first = blockArenaChunkSize
		}
		a.active = make([]byte, first)
		a.offset = 0
	}

	// Fast path: enough room in the active chunk.
	if a.offset+n <= len(a.active) {
		s := a.active[a.offset : a.offset+n : a.offset+n]
		a.offset += n
		return s
	}

	// Active chunk is full; retire it to `others` so its slices remain
	// reachable, then allocate a new standard-size chunk. Subsequent chunks
	// use the full standard size because by this point we know the block
	// exceeds the first chunk and amortizing big chunks is the win.
	a.others = append(a.others, a.active)
	a.active = make([]byte, blockArenaChunkSize)
	a.offset = n
	return a.active[0:n:n]
}
