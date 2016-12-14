package main

import (
	"flag"
	"fmt"

	"github.com/golang/glog"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/crypto"
)

var treeSizeFlag = flag.Int("tree_size", 128, "Number of entries to add to the tree")
var inclusionIndexFlag = flag.Int("index", 0, "If set display inclusion proof for this index")
var snapshotSizeFlag = flag.Int("snapshot", 0, "Tree snapshot size to use for inclusion proof")
var inclusionRangeFlag = flag.Int("inclusion_range", 0, "If set explore proofs up to this size")
var inclusionMatrixSizeFlag = flag.Int("inc_matrix_size", 0, "If set creates a matrix of recomputations")

func showInclusionProof(mt *merkle.InMemoryMerkleTree, i, snapshot int) {
	showPathAndStats(mt.PathToRootAtSnapshot(i, snapshot))
}

func showProofInfoUpToSnapshot(mt *merkle.InMemoryMerkleTree, snapshot int) {
	trees := 0

	for s := 1; s <= snapshot; s++ {
		for i := 1; i < s; i++ {
			path, stats := mt.PathToRootAtSnapshot(i, s)
			trees++

			// Look for cases where more than one subtree is recomputed - the theory is that
			// this shouldn't ever happen
			if stats.SubtreesRecomputed > 1 {
				showPathAndStats(path, stats)
			}
		}
	}

	fmt.Printf("Examined %d trees\n", trees)
}

func showProofRecomputationMatrix(mt *merkle.InMemoryMerkleTree, snapshot int) {
	trees := 0

	matrix := make([][]int, snapshot)
	inner := make([]int, snapshot * snapshot)
	for i := range matrix {
		matrix[i], inner = inner[:snapshot], inner[snapshot:]
	}

	for s := 1; s <= snapshot; s++ {
		for i := 1; i <= s; i++ {
			_, stats := mt.PathToRootAtSnapshot(i, s)
			trees++
			matrix[i - 1][s - 1] = stats.SubtreesRecomputed
			if matrix[i - 1][s - 1] == 0 {
				// Mark it differently to a path that is never computed
				matrix[i - 1][s - 1] = -1
			}
		}
	}

	for i := 0; i < snapshot; i++ {
		for j := 0; j < snapshot; j++ {
			if matrix[i][j] == 0 {
				// This path didn't get examined - not valid
				fmt.Print(".")
			} else if matrix[i][j] > 0 {
				fmt.Print(matrix[i][j])
			} else {
				fmt.Printf("0")
			}
			fmt.Print(" ")
		}
		fmt.Print("\n")
	}

	fmt.Printf("Examined %d trees\n", trees)
}

func main() {
	flag.Parse()
	glog.CopyStandardLogTo("WARNING")

	// Build the tree and ensure all the lazy evaluations have been done before we get proofs
	mt := buildMerkleTree(*treeSizeFlag)
	mt.CurrentRoot()

	switch {
	case *inclusionIndexFlag > 0:
		// We're interested in an inclusion proof
		showInclusionProof(mt, *inclusionIndexFlag, *snapshotSizeFlag)

	case *inclusionRangeFlag > 0:
		// Display info on proofs up to this snapshot size
		showProofInfoUpToSnapshot(mt, *inclusionRangeFlag)

	case *inclusionMatrixSizeFlag > 0:
		// Show a matrix of recomputed subtrees
		showProofRecomputationMatrix(mt, *inclusionMatrixSizeFlag)
	}
}

func buildMerkleTree(treeSize int) *merkle.InMemoryMerkleTree {
	mt := merkle.NewInMemoryMerkleTree(merkle.NewRFC6962TreeHasher(crypto.NewSHA256()))

	for i := 0; i < treeSize; i++ {
		mt.AddLeaf([]byte(fmt.Sprintf("Leaf %d", i)))
	}

	return mt
}

func showPathAndStats(path []merkle.TreeEntryDescriptor, stats merkle.PathStats) {
	for i, pe := range path {
		fmt.Printf("%d: %v\n", i, pe)
	}

	fmt.Printf("\n")
	fmt.Printf("Stats: %v\n", stats)
}