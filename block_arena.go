// Copyright (c) 2024 The go-wire developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

// blockArenaChunkSize is the default size in bytes of each chunk allocated by
// blockArena. 4 MiB matches a typical OS huge-page boundary and is large enough
// to hold dozens of standard scripts in a single allocation.
const blockArenaChunkSize = 4 * 1024 * 1024 // 4 MiB

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
//     allocs do not bleed into it.
//
// Ownership: the arena is created per-block-decode, lives for the duration of
// the block's lifetime, and is never explicitly freed. The GC reclaims chunks
// when the decoded MsgBlock (and all its script slices) become unreachable.
type blockArena struct {
	chunks [][]byte // all allocated chunks; first element is the active one
	offset int      // write cursor within chunks[0]
}

// newBlockArena returns an initialized blockArena with one pre-allocated chunk.
func newBlockArena() *blockArena {
	return &blockArena{
		chunks: [][]byte{make([]byte, blockArenaChunkSize)},
		offset: 0,
	}
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
	// chunk so that the next small alloc continues from the existing active
	// standard chunk without bleeding into the oversize allocation.
	if n > blockArenaChunkSize {
		chunk := make([]byte, n)
		// Append so the private chunk is referenced (preventing GC) but
		// chunks[0] remains the active standard chunk with offset unchanged.
		a.chunks = append(a.chunks, chunk)
		return chunk[0:n:n]
	}

	// Fast path: enough room in the current chunk.
	if a.offset+n <= len(a.chunks[0]) {
		s := a.chunks[0][a.offset : a.offset+n : a.offset+n]
		a.offset += n
		return s
	}

	// Current chunk is full; allocate a new standard chunk.
	// The old chunk stays in chunks so that previously returned slices remain
	// valid (the GC won't collect it while blockArena is live).
	newChunk := make([]byte, blockArenaChunkSize)
	// Preserve the old chunks by prepending the new active chunk.
	a.chunks = append([][]byte{newChunk}, a.chunks...)
	a.offset = n
	return newChunk[0:n:n]
}
