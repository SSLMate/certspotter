// Copyright (C) 2022 Opsmate, Inc.
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
	"math/bits"
	"slices"
)

// CollapsedTree is an efficient representation of a Merkle (sub)tree that permits appending
// nodes and calculating the root hash.
type CollapsedTree struct {
	offset uint64
	nodes  []Hash
	size   uint64
}

func calculateNumNodes(size uint64) int {
	return bits.OnesCount64(size)
}

// TODO: phase out this function
func EmptyCollapsedTree() *CollapsedTree {
	return &CollapsedTree{nodes: []Hash{}, size: 0}
}

// TODO: phase out this function
func NewCollapsedTree(nodes []Hash, size uint64) (*CollapsedTree, error) {
	tree := new(CollapsedTree)
	if err := tree.Init(nodes, size); err != nil {
		return nil, err
	}
	return tree, nil
}

func (tree CollapsedTree) Equal(other CollapsedTree) bool {
	return tree.offset == other.offset && tree.size == other.size && slices.Equal(tree.nodes, other.nodes)
}

func (tree CollapsedTree) Clone() CollapsedTree {
	return CollapsedTree{
		offset: tree.offset,
		nodes:  slices.Clone(tree.nodes),
		size:   tree.size,
	}
}

// Add a new leaf hash to the end of the tree.
// Returns an error if and only if the new tree would be too large for the subtree offset.
// Always returns a nil error if tree.Offset() == 0.
func (tree *CollapsedTree) Add(hash Hash) error {
	if tree.offset > 0 {
		maxSize := uint64(1) << bits.TrailingZeros64(tree.offset)
		if tree.size+1 > maxSize {
			return fmt.Errorf("subtree at offset %d is already at maximum size %d", tree.offset, maxSize)
		}
	}
	tree.nodes = append(tree.nodes, hash)
	tree.size++
	tree.collapse()
	return nil
}

func (tree *CollapsedTree) Append(other CollapsedTree) error {
	if tree.offset+tree.size != other.offset {
		return fmt.Errorf("subtree at offset %d cannot be appended to subtree ending at offset %d", other.offset, tree.offset+tree.size)
	}
	if tree.offset > 0 {
		newSize := tree.size + other.size
		maxSize := uint64(1) << bits.TrailingZeros64(tree.offset)
		if newSize > maxSize {
			return fmt.Errorf("size of new subtree (%d) would exceed maximum size %d for a subtree at offset %d", newSize, maxSize, tree.offset)
		}
	}
	if tree.size > 0 {
		maxSize := uint64(1) << bits.TrailingZeros64(tree.size)
		if other.size > maxSize {
			return fmt.Errorf("tree of size %d is too large to append to a tree of size %d (maximum size is %d)", other.size, tree.size, maxSize)
		}
	}

	tree.nodes = append(tree.nodes, other.nodes...)
	tree.size += other.size
	tree.collapse()
	return nil
}

func (tree *CollapsedTree) collapse() {
	numNodes := calculateNumNodes(tree.size)
	for len(tree.nodes) > numNodes {
		left, right := tree.nodes[len(tree.nodes)-2], tree.nodes[len(tree.nodes)-1]
		tree.nodes = tree.nodes[:len(tree.nodes)-2]
		tree.nodes = append(tree.nodes, HashChildren(left, right))
	}
}

func (tree CollapsedTree) CalculateRoot() Hash {
	if len(tree.nodes) == 0 {
		return HashNothing()
	}
	i := len(tree.nodes) - 1
	hash := tree.nodes[i]
	for i > 0 {
		i -= 1
		hash = HashChildren(tree.nodes[i], hash)
	}
	return hash
}

// Return the subtree offset (0 if this represents an entire tree)
func (tree CollapsedTree) Offset() uint64 {
	return tree.offset
}

// Return a non-nil slice containing the nodes.  The slice
// must not be modified.
func (tree CollapsedTree) Nodes() []Hash {
	if tree.nodes == nil {
		return []Hash{}
	} else {
		return tree.nodes
	}
}

// Return the number of leaf nodes in the tree.
func (tree CollapsedTree) Size() uint64 {
	return tree.size
}

type collapsedTreeMessage struct {
	Offset uint64 `json:"offset,omitempty"`
	Nodes  []Hash `json:"nodes"` // never nil
	Size   uint64 `json:"size"`
}

func (tree CollapsedTree) MarshalJSON() ([]byte, error) {
	return json.Marshal(collapsedTreeMessage{
		Offset: tree.offset,
		Nodes:  tree.Nodes(),
		Size:   tree.size,
	})
}

func (tree *CollapsedTree) UnmarshalJSON(b []byte) error {
	var rawTree collapsedTreeMessage
	if err := json.Unmarshal(b, &rawTree); err != nil {
		return fmt.Errorf("error unmarshalling Collapsed Merkle Tree: %w", err)
	}
	if err := tree.InitSubtree(rawTree.Offset, rawTree.Nodes, rawTree.Size); err != nil {
		return fmt.Errorf("error unmarshalling Collapsed Merkle Tree: %w", err)
	}
	return nil
}

func (tree *CollapsedTree) Init(nodes []Hash, size uint64) error {
	if len(nodes) != calculateNumNodes(size) {
		return fmt.Errorf("nodes has wrong length (should be %d, not %d)", calculateNumNodes(size), len(nodes))
	}
	tree.size = size
	tree.nodes = nodes
	return nil
}

func (tree *CollapsedTree) InitSubtree(offset uint64, nodes []Hash, size uint64) error {
	if offset > 0 {
		maxSize := uint64(1) << bits.TrailingZeros64(offset)
		if size > maxSize {
			return fmt.Errorf("subtree size (%d) is too large for offset %d (maximum size is %d)", size, offset, maxSize)
		}
	}
	tree.offset = offset
	return tree.Init(nodes, size)
}
