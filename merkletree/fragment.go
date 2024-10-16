// Copyright (C) 2024 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package merkletree

import (
	"encoding/json"
	"fmt"
	"slices"
)

// FragmentedCollapsedTree represents a sequence of non-overlapping subtrees
type FragmentedCollapsedTree struct {
	subtrees []CollapsedTree // sorted by offset
}

func (tree *FragmentedCollapsedTree) AddHash(position uint64, hash Hash) error {
	return tree.Add(CollapsedTree{
		offset: position,
		nodes:  []Hash{hash},
		size:   1,
	})
}

func (tree *FragmentedCollapsedTree) Add(subtree CollapsedTree) error {
	if subtree.size == 0 {
		return nil
	}
	i := len(tree.subtrees)
	for i > 0 && tree.subtrees[i-1].offset > subtree.offset {
		i--
	}
	if i > 0 && tree.subtrees[i-1].offset+tree.subtrees[i-1].size > subtree.offset {
		return fmt.Errorf("overlaps with subtree ending at %d", tree.subtrees[i-1].offset+tree.subtrees[i-1].size)
	}
	if i < len(tree.subtrees) && subtree.offset+subtree.size > tree.subtrees[i].offset {
		return fmt.Errorf("overlaps with subtree starting at %d", tree.subtrees[i].offset)
	}
	if i == 0 || tree.subtrees[i-1].Append(subtree) != nil {
		tree.subtrees = slices.Insert(tree.subtrees, i, subtree)
		i++
	}
	for i < len(tree.subtrees) && tree.subtrees[i-1].Append(tree.subtrees[i]) == nil {
		tree.subtrees = slices.Delete(tree.subtrees, i, i+1)
	}
	return nil
}

func (tree *FragmentedCollapsedTree) Merge(other FragmentedCollapsedTree) error {
	for _, subtree := range other.subtrees {
		if err := tree.Add(subtree); err != nil {
			return err
		}
	}
	return nil
}

func (tree FragmentedCollapsedTree) Gaps(yield func(uint64, uint64) bool) {
	var prevEnd uint64
	for i := range tree.subtrees {
		if prevEnd != tree.subtrees[i].offset {
			if !yield(prevEnd, tree.subtrees[i].offset) {
				return
			}
		}
		prevEnd = tree.subtrees[i].offset + tree.subtrees[i].size
	}
	yield(prevEnd, 0)
}

func (tree FragmentedCollapsedTree) NumSubtrees() int {
	return len(tree.subtrees)
}

func (tree FragmentedCollapsedTree) Subtree(i int) CollapsedTree {
	return tree.subtrees[i]
}

func (tree FragmentedCollapsedTree) Subtrees() []CollapsedTree {
	if tree.subtrees == nil {
		return []CollapsedTree{}
	} else {
		return tree.subtrees
	}
}

// Return true iff the tree contains at least the first n nodes (without any gaps)
func (tree FragmentedCollapsedTree) ContainsFirstN(n uint64) bool {
	return len(tree.subtrees) >= 1 && tree.subtrees[0].offset == 0 && tree.subtrees[0].size >= n
}

func (tree *FragmentedCollapsedTree) Init(subtrees []CollapsedTree) error {
	for i := 1; i < len(subtrees); i++ {
		if subtrees[i-1].offset+subtrees[i-1].size > subtrees[i].offset {
			return fmt.Errorf("subtrees %d and %d overlap", i-1, i)
		}
	}
	tree.subtrees = subtrees
	return nil
}

func (tree FragmentedCollapsedTree) MarshalJSON() ([]byte, error) {
	return json.Marshal(tree.Subtrees())
}

func (tree *FragmentedCollapsedTree) UnmarshalJSON(b []byte) error {
	var subtrees []CollapsedTree
	if err := json.Unmarshal(b, &subtrees); err != nil {
		return fmt.Errorf("error unmarshaling Fragmented Collapsed Merkle Tree: %w", err)
	}
	if err := tree.Init(subtrees); err != nil {
		return fmt.Errorf("error unmarshaling Fragmented Collapsed Merkle Tree: %w", err)
	}
	return nil
}
