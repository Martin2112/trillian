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

func showInclusionProof(mt *merkle.InMemoryMerkleTree, i, snapshot int) {
	showPathAndStats(mt.PathToRootAtSnapshot(i, snapshot))
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
	fmt.Printf("Stats: %v", stats)
}