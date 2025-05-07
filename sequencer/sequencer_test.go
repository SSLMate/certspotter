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
	"fmt"
	mathrand "math/rand/v2"
	"testing"
	"time"
)

func TestSequencerBasic(t *testing.T) {
	ctx := context.Background()
	seq := New[uint64](0, 100)
	go func() {
		for i := range uint64(10_000) {
			err := seq.Add(ctx, i, &i)
			if err != nil {
				panic(fmt.Sprintf("%d: seq.Add returned unexpected error %v", i, err))
			}
		}
	}()

	for i := range uint64(10_000) {
		next, err := seq.Next(ctx)
		if err != nil {
			t.Fatalf("%d: seq.Next returned unexpected error %v", i, err)
		}
		if *next != i {
			t.Fatalf("%d: got unexpected value %d", i, *next)
		}
	}
}

func TestSequencerNonZeroStart(t *testing.T) {
	ctx := context.Background()
	seq := New[uint64](10, 100)
	go func() {
		for i := range uint64(10_000) {
			err := seq.Add(ctx, i+10, &i)
			if err != nil {
				panic(fmt.Sprintf("%d: seq.Add returned unexpected error %v", i, err))
			}
		}
	}()

	for i := range uint64(10_000) {
		next, err := seq.Next(ctx)
		if err != nil {
			t.Fatalf("%d: seq.Next returned unexpected error %v", i, err)
		}
		if *next != i {
			t.Fatalf("%d: got unexpected value %d", i, *next)
		}
	}
}

func TestSequencerCapacity1(t *testing.T) {
	ctx := context.Background()
	seq := New[uint64](0, 1)
	go func() {
		for i := range uint64(10_000) {
			err := seq.Add(ctx, i, &i)
			if err != nil {
				panic(fmt.Sprintf("%d: seq.Add returned unexpected error %v", i, err))
			}
		}
	}()

	for i := range uint64(10_000) {
		next, err := seq.Next(ctx)
		if err != nil {
			t.Fatalf("%d: seq.Next returned unexpected error %v", i, err)
		}
		if *next != i {
			t.Fatalf("%d: got unexpected value %d", i, *next)
		}
	}
}

func TestSequencerTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	seq := New[uint64](0, 10_000)
	go func() {
		var i uint64
		for {
			newI := i
			err := seq.Add(ctx, i, &newI)
			if err != nil {
				break
			}
			i++
		}
	}()

	var i uint64
	for {
		next, err := seq.Next(ctx)
		if err != nil {
			break
		}
		if *next != i {
			t.Fatalf("%d: got unexpected value %d", i, *next)
		}
		i++
	}
}

func TestSequencerOutOfOrder(t *testing.T) {
	ctx := context.Background()
	seq := New[uint64](0, 100)
	ch := make(chan uint64)
	go func() {
		for i := range uint64(10_000) {
			ch <- i
		}
	}()
	for range 4 {
		go func() {
			for i := range ch {
				time.Sleep(mathrand.N(10 * time.Millisecond))
				//t.Logf("seq.Add %d", i)
				err := seq.Add(ctx, i, &i)
				if err != nil {
					panic(fmt.Sprintf("%d: seq.Add returned unexpected error %v", i, err))
				}
			}
		}()
	}
	for i := range uint64(10_000) {
		next, err := seq.Next(ctx)
		if err != nil {
			t.Fatalf("%d: seq.Next returned unexpected error %v", i, err)
		}
		if *next != i {
			t.Fatalf("%d: got unexpected value %d", i, *next)
		}
		//t.Logf("seq.Next %d", i)
	}
}
