// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package sequencer

import (
	"context"
	"slices"
	"sync"
)

type seqWriter struct {
	seqNbr uint64
	ready  chan<- struct{}
}

// Channel[T] is a multi-producer, single-consumer channel of items with monotonicaly-increasing sequence numbers.
// Items can be sent in any order, but they are always received in order of their sequence number.
// It is unsafe to call Next concurrently with itself, or to call Add/Reserve concurrently with another Add/Reserve
// call for the same sequence number.  Otherwise, methods are safe to call concurrently.
type Channel[T any] struct {
	mu          sync.Mutex
	next        uint64
	buf         []*T
	writers     []seqWriter
	readWaiting bool
	readReady   chan struct{}
}

func New[T any](initialSequenceNumber uint64, capacity uint64) *Channel[T] {
	return &Channel[T]{
		buf:       make([]*T, capacity),
		next:      initialSequenceNumber,
		readReady: make(chan struct{}, 1),
	}
}

func (seq *Channel[T]) parkWriter(seqNbr uint64) <-chan struct{} {
	ready := make(chan struct{})
	seq.writers = append(seq.writers, seqWriter{seqNbr: seqNbr, ready: ready})
	return ready
}

func (seq *Channel[T]) signalWriter(seqNbr uint64) {
	for i := range seq.writers {
		if seq.writers[i].seqNbr == seqNbr {
			close(seq.writers[i].ready)
			seq.writers = slices.Delete(seq.writers, i, i+1)
			return
		}
	}
}

func (seq *Channel[T]) forgetWriter(seqNbr uint64) {
	for i := range seq.writers {
		if seq.writers[i].seqNbr == seqNbr {
			seq.writers = slices.Delete(seq.writers, i, i+1)
			return
		}
	}
}

func (seq *Channel[T]) Cap() uint64 {
	return uint64(len(seq.buf))
}

func (seq *Channel[T]) index(seqNbr uint64) int {
	return int(seqNbr % seq.Cap())
}

// Wait until the channel has capacity for an item with the given sequence number.
// After this function returns nil, calling Add with the same sequence number will not block.
func (seq *Channel[T]) Reserve(ctx context.Context, sequenceNumber uint64) error {
	seq.mu.Lock()
	if sequenceNumber >= seq.next+seq.Cap() {
		ready := seq.parkWriter(sequenceNumber)
		seq.mu.Unlock()
		select {
		case <-ctx.Done():
			seq.mu.Lock()
			seq.forgetWriter(sequenceNumber)
			seq.mu.Unlock()
			return ctx.Err()
		case <-ready:
		}
	} else {
		seq.mu.Unlock()
	}
	return nil
}

// Send an item with the given sequence number.  Blocks if the channel does not have capacity for the item.
// It is undefined behavior to send a sequence number that has previously been sent.
func (seq *Channel[T]) Add(ctx context.Context, sequenceNumber uint64, item *T) error {
	seq.mu.Lock()
	if sequenceNumber >= seq.next+seq.Cap() {
		ready := seq.parkWriter(sequenceNumber)
		seq.mu.Unlock()
		select {
		case <-ctx.Done():
			seq.mu.Lock()
			seq.forgetWriter(sequenceNumber)
			seq.mu.Unlock()
			return ctx.Err()
		case <-ready:
		}
		seq.mu.Lock()
	}
	seq.buf[seq.index(sequenceNumber)] = item
	if sequenceNumber == seq.next && seq.readWaiting {
		seq.readReady <- struct{}{}
	}
	seq.mu.Unlock()
	return nil
}

// Return the item with the next sequence number, blocking if necessary.
// Not safe to call concurrently with other Next calls.
func (seq *Channel[T]) Next(ctx context.Context) (*T, error) {
	seq.mu.Lock()
	if seq.buf[seq.index(seq.next)] == nil {
		seq.readWaiting = true
		seq.mu.Unlock()
		select {
		case <-ctx.Done():
			seq.mu.Lock()
			select {
			case <-seq.readReady:
			default:
			}
			seq.readWaiting = false
			seq.mu.Unlock()
			return nil, ctx.Err()
		case <-seq.readReady:
		}
		seq.mu.Lock()
		seq.readWaiting = false
	}
	item := seq.buf[seq.index(seq.next)]
	seq.buf[seq.index(seq.next)] = nil
	seq.signalWriter(seq.next + seq.Cap())
	seq.next++
	seq.mu.Unlock()
	return item, nil
}
