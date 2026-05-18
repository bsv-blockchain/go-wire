// Copyright (c) 2024 The go-wire developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"testing"
)

// TestBlockArena_EmptyAlloc verifies that Alloc(0) returns nil.
func TestBlockArena_EmptyAlloc(t *testing.T) {
	a := newBlockArena()
	s := a.Alloc(0)
	if s != nil {
		t.Fatalf("Alloc(0): expected nil, got %v (len=%d)", s, len(s))
	}
}

// TestBlockArena_FitsInChunk verifies that three small allocations land in the
// same underlying chunk and are non-overlapping.
func TestBlockArena_FitsInChunk(t *testing.T) {
	a := newBlockArena()

	s1 := a.Alloc(16)
	s2 := a.Alloc(32)
	s3 := a.Alloc(8)

	for i := range s1 {
		s1[i] = 0x11
	}
	for i := range s2 {
		s2[i] = 0x22
	}
	for i := range s3 {
		s3[i] = 0x33
	}

	// All three slices should hold their own values independently.
	for i, b := range s1 {
		if b != 0x11 {
			t.Errorf("s1[%d] = 0x%02x, want 0x11", i, b)
		}
	}
	for i, b := range s2 {
		if b != 0x22 {
			t.Errorf("s2[%d] = 0x%02x, want 0x22", i, b)
		}
	}
	for i, b := range s3 {
		if b != 0x33 {
			t.Errorf("s3[%d] = 0x%02x, want 0x33", i, b)
		}
	}

	// Verify sizes.
	if len(s1) != 16 {
		t.Errorf("s1: len=%d, want 16", len(s1))
	}
	if len(s2) != 32 {
		t.Errorf("s2: len=%d, want 32", len(s2))
	}
	if len(s3) != 8 {
		t.Errorf("s3: len=%d, want 8", len(s3))
	}
}

// TestBlockArena_CrossChunkStability writes to the first slice, forces a new
// chunk to be allocated, writes to the new slice, then verifies the first
// slice is unchanged. This is the core no-aliasing guarantee.
func TestBlockArena_CrossChunkStability(t *testing.T) {
	a := newBlockArena()

	// Fill the first chunk almost completely so the next alloc overflows.
	filler := a.Alloc(blockArenaChunkSize - 10)
	_ = filler

	// Allocate the first "real" slice — this fits at the tail of chunk 0.
	s1 := a.Alloc(8)
	for i := range s1 {
		s1[i] = 0xAA
	}

	// This allocation (11 bytes) does NOT fit in the remaining 2 bytes of
	// chunk 0, so a new chunk must be created.
	s2 := a.Alloc(11)
	for i := range s2 {
		s2[i] = 0xBB
	}

	// s1 must still read 0xAA byte-for-byte.
	if !bytes.Equal(s1, bytes.Repeat([]byte{0xAA}, 8)) {
		t.Errorf("s1 was corrupted after cross-chunk alloc: %x", s1)
	}

	// s2 must read 0xBB byte-for-byte.
	if !bytes.Equal(s2, bytes.Repeat([]byte{0xBB}, 11)) {
		t.Errorf("s2 has wrong content: %x", s2)
	}
}

// TestBlockArena_OversizeAlloc verifies that a request larger than
// blockArenaChunkSize gets its own private chunk, and that subsequent small
// allocs do not overlap with the oversize slice.
func TestBlockArena_OversizeAlloc(t *testing.T) {
	a := newBlockArena()

	bigLen := blockArenaChunkSize + 1
	big := a.Alloc(bigLen)
	if len(big) != bigLen {
		t.Fatalf("oversize alloc: len=%d, want %d", len(big), bigLen)
	}

	// Write a sentinel into the oversize slice.
	for i := range big {
		big[i] = 0xDE
	}

	// Subsequent small allocs should not share memory with big.
	small1 := a.Alloc(16)
	small2 := a.Alloc(32)

	for i := range small1 {
		small1[i] = 0x01
	}
	for i := range small2 {
		small2[i] = 0x02
	}

	// The oversize slice must still contain 0xDE throughout.
	for i, b := range big {
		if b != 0xDE {
			t.Errorf("oversize slice corrupted at index %d: got 0x%02x, want 0xDE", i, b)
			break
		}
	}
}

// TestBlockArena_CapEqualsLen verifies that every slice returned by Alloc has
// cap == len, preventing callers from accidentally writing past the allocation.
func TestBlockArena_CapEqualsLen(t *testing.T) {
	a := newBlockArena()

	sizes := []int{1, 7, 512, 1024, blockArenaChunkSize - 1, blockArenaChunkSize, blockArenaChunkSize + 1}

	for _, n := range sizes {
		s := a.Alloc(n)
		if len(s) != n {
			t.Errorf("Alloc(%d): len=%d, want %d", n, len(s), n)
		}
		if cap(s) != n {
			t.Errorf("Alloc(%d): cap=%d, want %d (cap must equal len)", n, cap(s), n)
		}
	}
}
