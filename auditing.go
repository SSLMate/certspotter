// Copyright (C) 2016 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package certspotter

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"software.sslmate.com/src/certspotter/ct"
)

func reverseHashes(hashes []ct.MerkleTreeNode) {
	for i := 0; i < len(hashes)/2; i++ {
		j := len(hashes) - i - 1
		hashes[i], hashes[j] = hashes[j], hashes[i]
	}
}

func VerifyConsistencyProof(proof ct.ConsistencyProof, first *ct.SignedTreeHead, second *ct.SignedTreeHead) bool {
	// TODO: make sure every hash in proof is right length? otherwise input to hashChildren is ambiguous
	if second.TreeSize < first.TreeSize {
		// Can't be consistent if tree got smaller
		return false
	}
	if first.TreeSize == second.TreeSize {
		if !(bytes.Equal(first.SHA256RootHash[:], second.SHA256RootHash[:]) && len(proof) == 0) {
			return false
		}
		return true
	}
	if first.TreeSize == 0 {
		// The purpose of the consistency proof is to ensure the append-only
		// nature of the tree; i.e. that the first tree is a "prefix" of the
		// second tree.  If the first tree is empty, then it's trivially a prefix
		// of the second tree, so no proof is needed.
		if len(proof) != 0 {
			return false
		}
		return true
	}
	// Guaranteed that 0 < first.TreeSize < second.TreeSize

	node := first.TreeSize - 1
	lastNode := second.TreeSize - 1

	// While we're the right child, everything is in both trees, so move one level up.
	for node%2 == 1 {
		node /= 2
		lastNode /= 2
	}

	var newHash ct.MerkleTreeNode
	var oldHash ct.MerkleTreeNode
	if node > 0 {
		if len(proof) == 0 {
			return false
		}
		newHash = proof[0]
		proof = proof[1:]
	} else {
		// The old tree was balanced, so we already know the first hash to use
		newHash = first.SHA256RootHash[:]
	}
	oldHash = newHash

	for node > 0 {
		if node%2 == 1 {
			// node is a right child; left sibling exists in both trees
			if len(proof) == 0 {
				return false
			}
			newHash = hashChildren(proof[0], newHash)
			oldHash = hashChildren(proof[0], oldHash)
			proof = proof[1:]
		} else if node < lastNode {
			// node is a left child; rigth sibling only exists in the new tree
			if len(proof) == 0 {
				return false
			}
			newHash = hashChildren(newHash, proof[0])
			proof = proof[1:]
		} // else node == lastNode: node is a left child with no sibling in either tree
		node /= 2
		lastNode /= 2
	}

	if !bytes.Equal(oldHash, first.SHA256RootHash[:]) {
		return false
	}

	// If trees have different height, continue up the path to reach the new root
	for lastNode > 0 {
		if len(proof) == 0 {
			return false
		}
		newHash = hashChildren(newHash, proof[0])
		proof = proof[1:]
		lastNode /= 2
	}

	if !bytes.Equal(newHash, second.SHA256RootHash[:]) {
		return false
	}

	return true
}

func hashNothing() ct.MerkleTreeNode {
	return sha256.New().Sum(nil)
}

func hashLeaf(leafBytes []byte) ct.MerkleTreeNode {
	hasher := sha256.New()
	hasher.Write([]byte{0x00})
	hasher.Write(leafBytes)
	return hasher.Sum(nil)
}

func hashChildren(left ct.MerkleTreeNode, right ct.MerkleTreeNode) ct.MerkleTreeNode {
	hasher := sha256.New()
	hasher.Write([]byte{0x01})
	hasher.Write(left)
	hasher.Write(right)
	return hasher.Sum(nil)
}

type MerkleTreeBuilder struct {
	stack []ct.MerkleTreeNode
	numLeaves  uint64 // number of hashes added so far
}

func calculateStackSize (numLeaves uint64) int {
	stackSize := 0
	for numLeaves > 0 {
		stackSize += int(numLeaves & 1)
		numLeaves >>= 1
	}
	return stackSize
}
func EmptyMerkleTreeBuilder () *MerkleTreeBuilder {
	return &MerkleTreeBuilder{}
}
func NewMerkleTreeBuilder (stack []ct.MerkleTreeNode, numLeaves uint64) (*MerkleTreeBuilder, error) {
	if len(stack) != calculateStackSize(numLeaves) {
		return nil, errors.New("NewMerkleTreeBuilder: incorrect stack size")
	}
	return &MerkleTreeBuilder{stack: stack, numLeaves: numLeaves}, nil
}
func CloneMerkleTreeBuilder (source *MerkleTreeBuilder) *MerkleTreeBuilder {
	stack := make([]ct.MerkleTreeNode, len(source.stack))
	copy(stack, source.stack)
	return &MerkleTreeBuilder{stack: stack, numLeaves: source.numLeaves}
}

func (builder *MerkleTreeBuilder) Add(hash ct.MerkleTreeNode) {
	builder.stack = append(builder.stack, hash)
	builder.numLeaves++
	numLeaves := builder.numLeaves
	for numLeaves%2 == 0 {
		left, right := builder.stack[len(builder.stack)-2], builder.stack[len(builder.stack)-1]
		builder.stack = builder.stack[:len(builder.stack)-2]
		builder.stack = append(builder.stack, hashChildren(left, right))
		numLeaves /= 2
	}
}

func (builder *MerkleTreeBuilder) CalculateRoot() ct.MerkleTreeNode {
	if len(builder.stack) == 0 {
		return hashNothing()
	}
	i := len(builder.stack) - 1
	hash := builder.stack[i]
	for i > 0 {
		i -= 1
		hash = hashChildren(builder.stack[i], hash)
	}
	return hash
}

func (builder *MerkleTreeBuilder) GetNumLeaves() uint64 {
	return builder.numLeaves
}

func (builder *MerkleTreeBuilder) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"stack": builder.stack,
		"num_leaves": builder.numLeaves,
	})
}

func (builder *MerkleTreeBuilder) UnmarshalJSON(b []byte) error {
	var rawBuilder struct {
		Stack []ct.MerkleTreeNode `json:"stack"`
		NumLeaves uint64 `json:"num_leaves"`
	}
	if err := json.Unmarshal(b, &rawBuilder); err != nil {
		return errors.New("Failed to unmarshal MerkleTreeBuilder: " + err.Error())
	}
	if len(rawBuilder.Stack) != calculateStackSize(rawBuilder.NumLeaves) {
		return errors.New("Failed to unmarshal MerkleTreeBuilder: invalid stack size")
	}
	builder.numLeaves = rawBuilder.NumLeaves
	builder.stack = rawBuilder.Stack
	return nil
}
