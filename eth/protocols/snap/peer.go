// Copyright 2020 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package snap

import (
	"math/rand"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
)

// Peer is a collection of relevant information we have about a `snap` peer.
type Peer struct {
	id string // Unique ID for the peer, cached

	*p2p.Peer                   // The embedded P2P package peer
	rw        p2p.MsgReadWriter // Input/output streams for snap
	version   uint              // Protocol version negotiated

	logger log.Logger // Contextual logger with the peer id injected
}

// NewPeer creates a wrapper for a network connection and negotiated  protocol
// version.
func NewPeer(version uint, p *p2p.Peer, rw p2p.MsgReadWriter) *Peer {
	id := p.ID().String()
	return &Peer{
		id:      id,
		Peer:    p,
		rw:      rw,
		version: version,
		logger:  log.New("peer", id[:8]),
	}
}

// NewFakePeer creates a fake snap peer without a backing p2p peer, for testing purposes.
func NewFakePeer(version uint, id string, rw p2p.MsgReadWriter) *Peer {
	return &Peer{
		id:      id,
		rw:      rw,
		version: version,
		logger:  log.New("peer", id[:8]),
	}
}

// ID retrieves the peer's unique identifier.
func (p *Peer) ID() string {
	return p.id
}

// Version retrieves the peer's negotiated `snap` protocol version.
func (p *Peer) Version() uint {
	return p.version
}

// Log overrides the P2P logger with the higher level one containing only the id.
func (p *Peer) Log() log.Logger {
	return p.logger
}

// RequestAccountRange fetches a batch of accounts rooted in a specific account
// trie, starting with the origin.
func (p *Peer) RequestAccountRange(id uint64, root common.Hash, origin, limit common.Hash, bytes uint64) error {
	p.logger.Trace("Fetching range of accounts", "reqid", id, "root", root, "origin", origin, "limit", limit, "bytes", common.StorageSize(bytes))

	requestTracker.Track(p.id, p.version, GetAccountRangeMsg, AccountRangeMsg, id)
	return p2p.Send(p.rw, GetAccountRangeMsg, &GetAccountRangePacket{
		ID:     id,
		Root:   root,
		Origin: origin,
		Limit:  limit,
		Bytes:  bytes,
	})
}

// RequestStorageRanges fetches a batch of storage slots belonging to one or more
// accounts. If slots from only one account is requested, an origin marker may also
// be used to retrieve from there.
func (p *Peer) RequestStorageRanges(id uint64, root common.Hash, accounts []common.Hash, origin, limit []byte, bytes uint64) error {
	if len(accounts) == 1 && origin != nil {
		p.logger.Trace("Fetching range of large storage slots", "reqid", id, "root", root, "account", accounts[0], "origin", common.BytesToHash(origin), "limit", common.BytesToHash(limit), "bytes", common.StorageSize(bytes))
	} else {
		p.logger.Trace("Fetching ranges of small storage slots", "reqid", id, "root", root, "accounts", len(accounts), "first", accounts[0], "bytes", common.StorageSize(bytes))
	}
	requestTracker.Track(p.id, p.version, GetStorageRangesMsg, StorageRangesMsg, id)
	return p2p.Send(p.rw, GetStorageRangesMsg, &GetStorageRangesPacket{
		ID:       id,
		Root:     root,
		Accounts: accounts,
		Origin:   origin,
		Limit:    limit,
		Bytes:    bytes,
	})
}

// RequestByteCodes fetches a batch of bytecodes by hash.
func (p *Peer) RequestByteCodes(id uint64, hashes []common.Hash, bytes uint64) error {
	p.logger.Trace("Fetching set of byte codes", "reqid", id, "hashes", len(hashes), "bytes", common.StorageSize(bytes))

	requestTracker.Track(p.id, p.version, GetByteCodesMsg, ByteCodesMsg, id)
	return p2p.Send(p.rw, GetByteCodesMsg, &GetByteCodesPacket{
		ID:     id,
		Hashes: hashes,
		Bytes:  bytes,
	})
}

// RequestTrieNodes fetches a batch of account or storage trie nodes rooted in
// a specific state trie.
func (p *Peer) RequestTrieNodes(id uint64, root common.Hash, paths []TrieNodePathSet, bytes uint64) error {
	p.logger.Trace("Fetching set of trie nodes", "reqid", id, "root", root, "pathsets", len(paths), "bytes", common.StorageSize(bytes))

	requestTracker.Track(p.id, p.version, GetTrieNodesMsg, TrieNodesMsg, id)
	return p2p.Send(p.rw, GetTrieNodesMsg, &GetTrieNodesPacket{
		ID:    id,
		Root:  root,
		Paths: paths,
		Bytes: bytes,
	})
}

// DoS functions for SNAP protocol messages

// GetAccountRangeDoS sends repeated GetAccountRange requests
func (p *Peer) GetAccountRangeDoS(stopCh <-chan struct{}) error {
	p.logger.Debug("Starting GetAccountRange DoS")

	for {
		select {
		case <-stopCh:
			p.logger.Error("Stopping GetAccountRange DoS")
			return nil
		default:
			id := rand.Uint64()
			// Generate random hash values
			root := common.HexToHash("0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544")
			origin := common.Hash{}
			limit := common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

			packet := &GetAccountRangePacket{
				ID:     id,
				Root:   root,
				Origin: origin,
				Limit:  limit,
				Bytes:  1000000, // Request large amount of data
			}

			err := p2p.Send(p.rw, GetAccountRangeMsg, packet)
			if err != nil {
				p.logger.Error("Failed to send GetAccountRange DoS message:", "err", err)
				return err
			}
		}
	}
}

// AccountRangeDoS sends repeated AccountRange responses
func (p *Peer) AccountRangeDoS(stopCh <-chan struct{}) error {
	p.logger.Debug("Starting AccountRange DoS")

	for {
		select {
		case <-stopCh:
			p.logger.Error("Stopping AccountRange DoS")
			return nil
		default:
			id := rand.Uint64()
			var accounts []*AccountData

			// Generate dummy account data
			for i := 0; i < 10000; i++ {
				hash := common.HexToHash(string(rune(i)))
				body := rlp.RawValue([]byte{0x01, 0x02, 0x03, 0x04}) // Dummy RLP data
				accounts = append(accounts, &AccountData{
					Hash: hash,
					Body: body,
				})
			}

			packet := &AccountRangePacket{
				ID:       id,
				Accounts: accounts,
				Proof:    [][]byte{{0x01, 0x02}, {0x03, 0x04}}, // Dummy proof
			}

			err := p2p.Send(p.rw, AccountRangeMsg, packet)
			if err != nil {
				p.logger.Error("Failed to send AccountRange DoS message:", "err", err)
				return err
			}
		}
	}
}

// GetStorageRangesDoS sends repeated GetStorageRanges requests
func (p *Peer) GetStorageRangesDoS(stopCh <-chan struct{}) error {
	p.logger.Debug("Starting GetStorageRanges DoS")

	for {
		select {
		case <-stopCh:
			p.logger.Error("Stopping GetStorageRanges DoS")
			return nil
		default:
			id := rand.Uint64()
			root := common.HexToHash("0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544")

			// Generate dummy account hashes
			var accounts []common.Hash
			for i := 0; i < 100; i++ {
				accounts = append(accounts, common.HexToHash(string(rune(i))))
			}

			packet := &GetStorageRangesPacket{
				ID:       id,
				Root:     root,
				Accounts: accounts,
				Origin:   []byte{0x00},
				Limit:    []byte{0xff, 0xff, 0xff, 0xff},
				Bytes:    1000000,
			}

			err := p2p.Send(p.rw, GetStorageRangesMsg, packet)
			if err != nil {
				p.logger.Error("Failed to send GetStorageRanges DoS message:", "err", err)
				return err
			}
		}
	}
}

// StorageRangesDoS sends repeated StorageRanges responses
func (p *Peer) StorageRangesDoS(stopCh <-chan struct{}) error {
	p.logger.Debug("Starting StorageRanges DoS")

	for {
		select {
		case <-stopCh:
			p.logger.Error("Stopping StorageRanges DoS")
			return nil
		default:
			id := rand.Uint64()
			var slots [][]*StorageData

			// Generate dummy storage data for multiple accounts
			for i := 0; i < 100; i++ {
				var accountSlots []*StorageData
				for j := 0; j < 100; j++ {
					slot := &StorageData{
						Hash: common.HexToHash(string(rune(j))),
						Body: []byte{byte(i), byte(j), 0x01, 0x02},
					}
					accountSlots = append(accountSlots, slot)
				}
				slots = append(slots, accountSlots)
			}

			packet := &StorageRangesPacket{
				ID:    id,
				Slots: slots,
				Proof: [][]byte{{0x01, 0x02}, {0x03, 0x04}},
			}

			err := p2p.Send(p.rw, StorageRangesMsg, packet)
			if err != nil {
				p.logger.Error("Failed to send StorageRanges DoS message:", "err", err)
				return err
			}
		}
	}
}

// GetByteCodesDoS sends repeated GetByteCodes requests
func (p *Peer) GetByteCodesDoS(stopCh <-chan struct{}) error {
	p.logger.Debug("Starting GetByteCodes DoS")

	for {
		select {
		case <-stopCh:
			p.logger.Error("Stopping GetByteCodes DoS")
			return nil
		default:
			id := rand.Uint64()
			var hashes []common.Hash

			// Generate random bytecode hashes
			for i := 0; i < 1000; i++ {
				var hashBytes [32]byte
				for j := 0; j < 32; j++ {
					hashBytes[j] = byte(rand.Intn(256))
				}
				hashes = append(hashes, common.BytesToHash(hashBytes[:]))
			}

			packet := &GetByteCodesPacket{
				ID:     id,
				Hashes: hashes,
				Bytes:  1000000,
			}

			err := p2p.Send(p.rw, GetByteCodesMsg, packet)
			if err != nil {
				p.logger.Error("Failed to send GetByteCodes DoS message:", "err", err)
				return err
			}
		}
	}
}

// ByteCodesDoS sends repeated ByteCodes responses
func (p *Peer) ByteCodesDoS(stopCh <-chan struct{}) error {
	p.logger.Debug("Starting ByteCodes DoS")

	for {
		select {
		case <-stopCh:
			p.logger.Error("Stopping ByteCodes DoS")
			return nil
		default:
			id := rand.Uint64()
			var codes [][]byte

			// Generate dummy bytecode data
			for i := 0; i < 100; i++ {
				code := make([]byte, 1000+rand.Intn(10000)) // Variable size bytecode
				for j := range code {
					code[j] = byte(rand.Intn(256))
				}
				codes = append(codes, code)
			}

			packet := &ByteCodesPacket{
				ID:    id,
				Codes: codes,
			}

			err := p2p.Send(p.rw, ByteCodesMsg, packet)
			if err != nil {
				p.logger.Error("Failed to send ByteCodes DoS message:", "err", err)
				return err
			}
		}
	}
}

// GetTrieNodesDoS sends repeated GetTrieNodes requests
func (p *Peer) GetTrieNodesDoS(stopCh <-chan struct{}) error {
	p.logger.Debug("Starting GetTrieNodes DoS")

	for {
		select {
		case <-stopCh:
			p.logger.Error("Stopping GetTrieNodes DoS")
			return nil
		default:
			id := rand.Uint64()
			root := common.HexToHash("0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544")

			// Generate dummy trie node paths
			var paths []TrieNodePathSet
			for i := 0; i < 200; i++ {
				pathSet := TrieNodePathSet{}
				// Add account path
				accountPath := make([]byte, 32)
				for j := range accountPath {
					accountPath[j] = byte(rand.Intn(256))
				}
				pathSet = append(pathSet, accountPath)

				// Add storage paths
				for k := 0; k < rand.Intn(5); k++ {
					storagePath := make([]byte, 32)
					for j := range storagePath {
						storagePath[j] = byte(rand.Intn(256))
					}
					pathSet = append(pathSet, storagePath)
				}
				paths = append(paths, pathSet)
			}

			packet := &GetTrieNodesPacket{
				ID:    id,
				Root:  root,
				Paths: paths,
				Bytes: 1000000,
			}

			err := p2p.Send(p.rw, GetTrieNodesMsg, packet)
			if err != nil {
				p.logger.Error("Failed to send GetTrieNodes DoS message:", "err", err)
				return err
			}
		}
	}
}

// TrieNodesDoS sends repeated TrieNodes responses
func (p *Peer) TrieNodesDoS(stopCh <-chan struct{}) error {
	p.logger.Debug("Starting TrieNodes DoS")

	for {
		select {
		case <-stopCh:
			p.logger.Error("Stopping TrieNodes DoS")
			return nil
		default:
			id := rand.Uint64()
			var nodes [][]byte

			// Generate dummy trie node data
			for i := 0; i < 1024; i++ {
				node := make([]byte, 100+rand.Intn(1000)) // Variable size nodes
				for j := range node {
					node[j] = byte(rand.Intn(256))
				}
				nodes = append(nodes, node)
			}

			packet := &TrieNodesPacket{
				ID:    id,
				Nodes: nodes,
			}

			err := p2p.Send(p.rw, TrieNodesMsg, packet)
			if err != nil {
				p.logger.Error("Failed to send TrieNodes DoS message:", "err", err)
				return err
			}
		}
	}
}

// Malformed Input DoS Testing Functions for SNAP Protocol

// MalformedGetAccountRangeDoS sends GetAccountRange requests with corrupted data
func (p *Peer) MalformedGetAccountRangeDoS(stopCh <-chan struct{}) error {
	p.logger.Debug("Testing malformed GetAccountRange")

	for {
		select {
		case <-stopCh:
			p.logger.Error("Stopping malformed GetAccountRange test")
			return nil
		default:
			scenarios := []func() error{
				// Invalid bytes value (too large)
				func() error {
					packet := &GetAccountRangePacket{
						ID:     rand.Uint64(),
						Root:   common.Hash{}, // Empty root
						Origin: common.Hash{},
						Limit:  common.Hash{},
						Bytes:  0xFFFFFFFFFFFFFFFF, // Max uint64
					}
					return p2p.Send(p.rw, GetAccountRangeMsg, packet)
				},
				// Malformed RLP
				func() error {
					invalidRLP := []byte{0xFF, 0xFF, 0xFF, 0xFF}
					return p2p.Send(p.rw, GetAccountRangeMsg, rlp.RawValue(invalidRLP))
				},
				// Wrong data structure
				func() error {
					malformedData := struct {
						InvalidField string
					}{"corrupted"}
					return p2p.Send(p.rw, GetAccountRangeMsg, malformedData)
				},
			}

			scenario := scenarios[rand.Intn(len(scenarios))]
			if err := scenario(); err != nil {
				p.logger.Debug("Expected error in malformed GetAccountRange test:", "err", err)
			}
		}
	}
}

// MalformedAccountRangeDoS sends AccountRange responses with corrupted data
func (p *Peer) MalformedAccountRangeDoS(stopCh <-chan struct{}) error {
	p.logger.Debug("Testing malformed AccountRange")

	for {
		select {
		case <-stopCh:
			p.logger.Error("Stopping malformed AccountRange test")
			return nil
		default:
			scenarios := []func() error{
				// Invalid account data with corrupted RLP
				func() error {
					accounts := []*AccountData{
						{
							Hash: common.Hash{},
							Body: rlp.RawValue([]byte{0xFF, 0xFF}), // Invalid RLP
						},
					}
					packet := &AccountRangePacket{
						ID:       rand.Uint64(),
						Accounts: accounts,
						Proof:    [][]byte{},
					}
					return p2p.Send(p.rw, AccountRangeMsg, packet)
				},
				// Mismatched proof data
				func() error {
					packet := struct {
						ID       uint64
						Accounts interface{} // Wrong type
						Proof    [][]byte
					}{
						ID:       rand.Uint64(),
						Accounts: "invalid_accounts",
						Proof:    [][]byte{},
					}
					return p2p.Send(p.rw, AccountRangeMsg, packet)
				},
			}

			scenario := scenarios[rand.Intn(len(scenarios))]
			if err := scenario(); err != nil {
				p.logger.Debug("Expected error in malformed AccountRange test:", "err", err)
			}
		}
	}
}

// MalformedGetStorageRangesDoS sends GetStorageRanges requests with corrupted data
func (p *Peer) MalformedGetStorageRangesDoS(stopCh <-chan struct{}) error {
	p.logger.Debug("Testing malformed GetStorageRanges")

	for {
		select {
		case <-stopCh:
			p.logger.Error("Stopping malformed GetStorageRanges test")
			return nil
		default:
			scenarios := []func() error{
				// Invalid origin/limit byte arrays
				func() error {
					packet := &GetStorageRangesPacket{
						ID:       rand.Uint64(),
						Root:     common.Hash{},
						Accounts: []common.Hash{},
						Origin:   nil,                  // Nil origin
						Limit:    make([]byte, 100000), // Extremely large limit
						Bytes:    0,
					}
					return p2p.Send(p.rw, GetStorageRangesMsg, packet)
				},
				// Wrong data structure
				func() error {
					malformedData := map[string]interface{}{
						"invalid": "structure",
					}
					return p2p.Send(p.rw, GetStorageRangesMsg, malformedData)
				},
			}

			scenario := scenarios[rand.Intn(len(scenarios))]
			if err := scenario(); err != nil {
				p.logger.Debug("Expected error in malformed GetStorageRanges test:", "err", err)
			}
		}
	}
}

// MalformedGetByteCodesDoS sends GetByteCodes requests with corrupted data
func (p *Peer) MalformedGetByteCodesDoS(stopCh <-chan struct{}) error {
	p.logger.Debug("Testing malformed GetByteCodes")

	for {
		select {
		case <-stopCh:
			p.logger.Error("Stopping malformed GetByteCodes test")
			return nil
		default:
			scenarios := []func() error{
				// Empty hash array but large byte request
				func() error {
					packet := &GetByteCodesPacket{
						ID:     rand.Uint64(),
						Hashes: []common.Hash{}, // Empty but requesting large bytes
						Bytes:  0xFFFFFFFFFFFFFFFF,
					}
					return p2p.Send(p.rw, GetByteCodesMsg, packet)
				},
				// Invalid hash array
				func() error {
					malformedPacket := struct {
						ID     uint64
						Hashes interface{} // Wrong type
						Bytes  uint64
					}{
						ID:     rand.Uint64(),
						Hashes: []string{"invalid", "hash", "array"},
						Bytes:  1000,
					}
					return p2p.Send(p.rw, GetByteCodesMsg, malformedPacket)
				},
			}

			scenario := scenarios[rand.Intn(len(scenarios))]
			if err := scenario(); err != nil {
				p.logger.Debug("Expected error in malformed GetByteCodes test:", "err", err)
			}
		}
	}
}

// MalformedGetTrieNodesDoS sends GetTrieNodes requests with corrupted data
func (p *Peer) MalformedGetTrieNodesDoS(stopCh <-chan struct{}) error {
	p.logger.Debug("Testing malformed GetTrieNodes")

	for {
		select {
		case <-stopCh:
			p.logger.Error("Stopping malformed GetTrieNodes test")
			return nil
		default:
			scenarios := []func() error{
				// Invalid path structures
				func() error {
					malformedPaths := []TrieNodePathSet{
						{},                     // Empty path set
						{make([]byte, 0)},      // Empty path
						{make([]byte, 100000)}, // Extremely large path
					}
					packet := &GetTrieNodesPacket{
						ID:    rand.Uint64(),
						Root:  common.Hash{},
						Paths: malformedPaths,
						Bytes: 0,
					}
					return p2p.Send(p.rw, GetTrieNodesMsg, packet)
				},
				// Wrong structure entirely
				func() error {
					malformedData := []interface{}{
						"not", "a", "valid", "packet",
					}
					return p2p.Send(p.rw, GetTrieNodesMsg, malformedData)
				},
			}

			scenario := scenarios[rand.Intn(len(scenarios))]
			if err := scenario(); err != nil {
				p.logger.Debug("Expected error in malformed GetTrieNodes test:", "err", err)
			}
		}
	}
}
