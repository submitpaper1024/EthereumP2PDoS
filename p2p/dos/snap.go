package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// GetAccountRangeDOS floods the target with GetAccountRange snap requests
func GetAccountRangeDOS(node *enode.Node) error {
	fmt.Printf("Starting Snap GetAccountRange DoS attack on %s\n", node.URLv4())
	for {
		// Dummy request: random root, start, limit
		root := common.Hash{}
		start := make([]byte, 32)
		limit := big.NewInt(100)
		rand.Read(root[:])
		rand.Read(start)
		fmt.Printf("[Snap] Would send GetAccountRange: root=%x, start=%x, limit=%s\n", root[:4], start[:4], limit.String())
	}
	return nil
}

// GetStorageRangesDOS floods the target with GetStorageRanges snap requests
func GetStorageRangesDOS(node *enode.Node) error {
	fmt.Printf("Starting Snap GetStorageRanges DoS attack on %s\n", node.URLv4())
	for {
		// Dummy request: random root, account, start, limit
		root := common.Hash{}
		account := common.Address{}
		start := make([]byte, 32)
		limit := big.NewInt(100)
		rand.Read(root[:])
		rand.Read(account[:])
		rand.Read(start)
		fmt.Printf("[Snap] Would send GetStorageRanges: root=%x, account=%x, start=%x, limit=%s\n", root[:4], account[:4], start[:4], limit.String())
	}
	return nil
}

// GetByteCodesDOS floods the target with GetByteCodes snap requests
func GetByteCodesDOS(node *enode.Node) error {
	fmt.Printf("Starting Snap GetByteCodes DoS attack on %s\n", node.URLv4())
	for {
		// Dummy request: random hashes
		hashes := make([]common.Hash, 10)
		for j := range hashes {
			rand.Read(hashes[j][:])
		}
		fmt.Printf("[Snap] Would send GetByteCodes: hashes[0]=%x\n", hashes[0][:4])
	}
	return nil
}

// GetTrieNodesDOS floods the target with GetTrieNodes snap requests
func GetTrieNodesDOS(node *enode.Node) error {
	fmt.Printf("Starting Snap GetTrieNodes DoS attack on %s\n", node.URLv4())
	for {
		// Dummy request: random hashes
		hashes := make([]common.Hash, 10)
		for j := range hashes {
			rand.Read(hashes[j][:])
		}
		fmt.Printf("[Snap] Would send GetTrieNodes: hashes[0]=%x\n", hashes[0][:4])
	}
	return nil
}
