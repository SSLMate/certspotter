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
	"software.sslmate.com/src/certspotter/ct"
)

func reverseHashes(hashes []ct.MerkleTreeNode) {
	for i := 0; i < len(hashes)/2; i++ {
		j := len(hashes) - i - 1
		hashes[i], hashes[j] = hashes[j], hashes[i]
	}
}

// TODO: drop the MerkleTreeBuilder return value
func VerifyConsistencyProof(proof ct.ConsistencyProof, first *ct.SignedTreeHead, second *ct.SignedTreeHead) (bool, *MerkleTreeBuilder) {
	if second.TreeSize < first.TreeSize {
		// Can't be consistent if tree got smaller
		return false, nil
	}
	if first.TreeSize == second.TreeSize {
		if !(bytes.Equal(first.SHA256RootHash[:], second.SHA256RootHash[:]) && len(proof) == 0) {
			return false, nil
		}
		return true, &MerkleTreeBuilder{stack: []ct.MerkleTreeNode{first.SHA256RootHash[:]}, size: 1}
	}
	if first.TreeSize == 0 {
		// The purpose of the consistency proof is to ensure the append-only
		// nature of the tree; i.e. that the first tree is a "prefix" of the
		// second tree.  If the first tree is empty, then it's trivially a prefix
		// of the second tree, so no proof is needed.
		if len(proof) != 0 {
			return false, nil
		}
		return true, &MerkleTreeBuilder{stack: []ct.MerkleTreeNode{}, size: 0}
	}
	// Guaranteed that 0 < first.TreeSize < second.TreeSize

	node := first.TreeSize - 1
	lastNode := second.TreeSize - 1

	// While we're the right child, everything is in both trees, so move one level up.
	for node%2 == 1 {
		node /= 2
		lastNode /= 2
	}

	var leftHashes []ct.MerkleTreeNode
	var newHash ct.MerkleTreeNode
	var oldHash ct.MerkleTreeNode
	if node > 0 {
		if len(proof) == 0 {
			return false, nil
		}
		newHash = proof[0]
		proof = proof[1:]
	} else {
		// The old tree was balanced, so we already know the first hash to use
		newHash = first.SHA256RootHash[:]
	}
	oldHash = newHash
	leftHashes = append(leftHashes, newHash)

	for node > 0 {
		if node%2 == 1 {
			// node is a right child; left sibling exists in both trees
			if len(proof) == 0 {
				return false, nil
			}
			newHash = hashChildren(proof[0], newHash)
			oldHash = hashChildren(proof[0], oldHash)
			leftHashes = append(leftHashes, proof[0])
			proof = proof[1:]
		} else if node < lastNode {
			// node is a left child; rigth sibling only exists in the new tree
			if len(proof) == 0 {
				return false, nil
			}
			newHash = hashChildren(newHash, proof[0])
			proof = proof[1:]
		} // else node == lastNode: node is a left child with no sibling in either tree
		node /= 2
		lastNode /= 2
	}

	if !bytes.Equal(oldHash, first.SHA256RootHash[:]) {
		return false, nil
	}

	// If trees have different height, continue up the path to reach the new root
	for lastNode > 0 {
		if len(proof) == 0 {
			return false, nil
		}
		newHash = hashChildren(newHash, proof[0])
		proof = proof[1:]
		lastNode /= 2
	}

	if !bytes.Equal(newHash, second.SHA256RootHash[:]) {
		return false, nil
	}

	reverseHashes(leftHashes)

	return true, &MerkleTreeBuilder{stack: leftHashes, size: first.TreeSize}
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
	size  uint64 // number of hashes added so far
}

func (builder *MerkleTreeBuilder) Add(hash ct.MerkleTreeNode) {
	builder.stack = append(builder.stack, hash)
	builder.size++
	size := builder.size
	for size%2 == 0 {
		left, right := builder.stack[len(builder.stack)-2], builder.stack[len(builder.stack)-1]
		builder.stack = builder.stack[:len(builder.stack)-2]
		builder.stack = append(builder.stack, hashChildren(left, right))
		size /= 2
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
