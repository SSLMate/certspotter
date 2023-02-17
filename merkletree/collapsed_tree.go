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
)

type CollapsedTree struct {
	nodes []Hash
	size  uint64
}

func calculateNumNodes(size uint64) int {
	return bits.OnesCount64(size)
}

func EmptyCollapsedTree() *CollapsedTree {
	return &CollapsedTree{nodes: []Hash{}, size: 0}
}

func NewCollapsedTree(nodes []Hash, size uint64) (*CollapsedTree, error) {
	if len(nodes) != calculateNumNodes(size) {
		return nil, fmt.Errorf("nodes has wrong length (should be %d, not %d)", calculateNumNodes(size), len(nodes))
	}
	return &CollapsedTree{nodes: nodes, size: size}, nil
}

func CloneCollapsedTree(source *CollapsedTree) *CollapsedTree {
	nodes := make([]Hash, len(source.nodes))
	copy(nodes, source.nodes)
	return &CollapsedTree{nodes: nodes, size: source.size}
}

func (tree *CollapsedTree) Add(hash Hash) {
	tree.nodes = append(tree.nodes, hash)
	tree.size++

	numNodes := calculateNumNodes(tree.size)
	for len(tree.nodes) > numNodes {
		left, right := tree.nodes[len(tree.nodes)-2], tree.nodes[len(tree.nodes)-1]
		tree.nodes = tree.nodes[:len(tree.nodes)-2]
		tree.nodes = append(tree.nodes, HashChildren(left, right))
	}
}

func (tree *CollapsedTree) CalculateRoot() Hash {
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

func (tree *CollapsedTree) Size() uint64 {
	return tree.size
}

func (tree *CollapsedTree) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"nodes": tree.nodes,
		"size":  tree.size,
	})
}

func (tree *CollapsedTree) UnmarshalJSON(b []byte) error {
	var rawTree struct {
		Nodes []Hash `json:"nodes"`
		Size  uint64 `json:"size"`
	}
	if err := json.Unmarshal(b, &rawTree); err != nil {
		return fmt.Errorf("error unmarshalling Collapsed Merkle Tree: %w", err)
	}
	if len(rawTree.Nodes) != calculateNumNodes(rawTree.Size) {
		return fmt.Errorf("error unmarshalling Collapsed Merkle Tree: nodes has wrong length (should be %d, not %d)", calculateNumNodes(rawTree.Size), len(rawTree.Nodes))
	}
	tree.size = rawTree.Size
	tree.nodes = rawTree.Nodes
	return nil
}
