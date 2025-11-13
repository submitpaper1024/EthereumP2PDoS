// Copyright 2015 The go-ethereum Authors
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
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/eth/fetcher"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/eth/protocols/snap"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

const (
	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096

	// txMaxBroadcastSize is the max size of a transaction that will be broadcasted.
	// All transactions with a higher size will be announced and need to be fetched
	// by the peer.
	txMaxBroadcastSize = 4096
)

var syncChallengeTimeout = 15 * time.Second // Time allowance for a node to reply to the sync progress challenge

// txPool defines the methods needed from a transaction pool implementation to
// support all the operations needed by the Ethereum chain protocols.
type txPool interface {
	// Has returns an indicator whether txpool has a transaction
	// cached with the given hash.
	Has(hash common.Hash) bool

	// Get retrieves the transaction from local txpool with given
	// tx hash.
	Get(hash common.Hash) *types.Transaction

	// GetRLP retrieves the RLP-encoded transaction from local txpool
	// with given tx hash.
	GetRLP(hash common.Hash) []byte

	// GetMetadata returns the transaction type and transaction size with the
	// given transaction hash.
	GetMetadata(hash common.Hash) *txpool.TxMetadata

	// Add should add the given transactions to the pool.
	Add(txs []*types.Transaction, sync bool) []error

	// Pending should return pending transactions.
	// The slice should be modifiable by the caller.
	Pending(filter txpool.PendingFilter) map[common.Address][]*txpool.LazyTransaction

	// SubscribeTransactions subscribes to new transaction events. The subscriber
	// can decide whether to receive notifications only for newly seen transactions
	// or also for reorged out ones.
	SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription
}

// handlerConfig is the collection of initialization parameters to create a full
// node network handler.
type handlerConfig struct {
	NodeID         enode.ID               // P2P node ID used for tx propagation topology
	Database       ethdb.Database         // Database for direct sync insertions
	Chain          *core.BlockChain       // Blockchain to serve data from
	TxPool         txPool                 // Transaction pool to propagate from
	Network        uint64                 // Network identifier to advertise
	Sync           ethconfig.SyncMode     // Whether to snap or full sync
	BloomCache     uint64                 // Megabytes to alloc for snap sync bloom
	EventMux       *event.TypeMux         // Legacy event mux, deprecate for `feed`
	RequiredBlocks map[uint64]common.Hash // Hard coded map of required block hashes for sync challenges
}

type handler struct {
	nodeID     enode.ID
	networkID  uint64
	forkFilter forkid.Filter // Fork ID filter, constant across the lifetime of the node

	snapSync atomic.Bool // Flag whether snap sync is enabled (gets disabled if we already have blocks)
	synced   atomic.Bool // Flag whether we're considered synchronised (enables transaction processing)

	database ethdb.Database
	txpool   txPool
	chain    *core.BlockChain
	maxPeers int

	downloader *downloader.Downloader
	txFetcher  *fetcher.TxFetcher
	peers      *peerSet

	eventMux *event.TypeMux
	txsCh    chan core.NewTxsEvent
	txsSub   event.Subscription

	requiredBlocks map[uint64]common.Hash

	// channels for fetcher, syncer, txsyncLoop
	quitSync chan struct{}

	wg sync.WaitGroup

	handlerStartCh chan struct{}
	handlerDoneCh  chan struct{}
	StopRequest    chan struct{} // Dos Channel to stop Dos Request added by shixuan
}

// newHandler returns a handler for all Ethereum chain management protocol.
func newHandler(config *handlerConfig) (*handler, error) {
	// Create the protocol manager with the base fields
	if config.EventMux == nil {
		config.EventMux = new(event.TypeMux) // Nicety initialization for tests
	}
	h := &handler{
		nodeID:         config.NodeID,
		networkID:      config.Network,
		forkFilter:     forkid.NewFilter(config.Chain),
		eventMux:       config.EventMux,
		database:       config.Database,
		txpool:         config.TxPool,
		chain:          config.Chain,
		peers:          newPeerSet(),
		requiredBlocks: config.RequiredBlocks,
		quitSync:       make(chan struct{}),
		handlerDoneCh:  make(chan struct{}),
		handlerStartCh: make(chan struct{}),
	}
	if config.Sync == ethconfig.FullSync {
		// The database seems empty as the current block is the genesis. Yet the snap
		// block is ahead, so snap sync was enabled for this node at a certain point.
		// The scenarios where this can happen is
		// * if the user manually (or via a bad block) rolled back a snap sync node
		//   below the sync point.
		// * the last snap sync is not finished while user specifies a full sync this
		//   time. But we don't have any recent state for full sync.
		// In these cases however it's safe to reenable snap sync.
		fullBlock, snapBlock := h.chain.CurrentBlock(), h.chain.CurrentSnapBlock()
		if fullBlock.Number.Uint64() == 0 && snapBlock.Number.Uint64() > 0 {
			h.snapSync.Store(true)
			log.Warn("Switch sync mode from full sync to snap sync", "reason", "snap sync incomplete")
		} else if !h.chain.HasState(fullBlock.Root) {
			h.snapSync.Store(true)
			log.Warn("Switch sync mode from full sync to snap sync", "reason", "head state missing")
		}
	} else {
		head := h.chain.CurrentBlock()
		if head.Number.Uint64() > 0 && h.chain.HasState(head.Root) {
			// Print warning log if database is not empty to run snap sync.
			log.Warn("Switch sync mode from snap sync to full sync", "reason", "snap sync complete")
		} else {
			// If snap sync was requested and our database is empty, grant it
			h.snapSync.Store(true)
			log.Info("Enabled snap sync", "head", head.Number, "hash", head.Hash())
		}
	}
	// If snap sync is requested but snapshots are disabled, fail loudly
	if h.snapSync.Load() && config.Chain.Snapshots() == nil {
		return nil, errors.New("snap sync not supported with snapshots disabled")
	}
	// Construct the downloader (long sync)
	h.downloader = downloader.New(config.Database, h.eventMux, h.chain, h.removePeer, h.enableSyncedFeatures)

	fetchTx := func(peer string, hashes []common.Hash) error {
		p := h.peers.peer(peer)
		if p == nil {
			return errors.New("unknown peer")
		}
		return p.RequestTxs(hashes)
	}
	addTxs := func(txs []*types.Transaction) []error {
		return h.txpool.Add(txs, false)
	}
	h.txFetcher = fetcher.NewTxFetcher(h.txpool.Has, addTxs, fetchTx, h.removePeer)
	return h, nil
}

// protoTracker tracks the number of active protocol handlers.
func (h *handler) protoTracker() {
	defer h.wg.Done()
	var active int
	for {
		select {
		case <-h.handlerStartCh:
			active++
		case <-h.handlerDoneCh:
			active--
		case <-h.quitSync:
			// Wait for all active handlers to finish.
			for ; active > 0; active-- {
				<-h.handlerDoneCh
			}
			return
		}
	}
}

// incHandlers signals to increment the number of active handlers if not
// quitting.
func (h *handler) incHandlers() bool {
	select {
	case h.handlerStartCh <- struct{}{}:
		return true
	case <-h.quitSync:
		return false
	}
}

// decHandlers signals to decrement the number of active handlers.
func (h *handler) decHandlers() {
	h.handlerDoneCh <- struct{}{}
}

// runEthPeer registers an eth peer into the joint eth/snap peerset, adds it to
// various subsystems and starts handling messages.
func (h *handler) runEthPeer(peer *eth.Peer, handler eth.Handler) error {
	if !h.incHandlers() {
		return p2p.DiscQuitting
	}
	defer h.decHandlers()

	// If the peer has a `snap` extension, wait for it to connect so we can have
	// a uniform initialization/teardown mechanism
	snap, err := h.peers.waitSnapExtension(peer)
	if err != nil {
		peer.Log().Error("Snapshot extension barrier failed", "err", err)
		return err
	}

	// Execute the Ethereum handshake
	var (
		genesis = h.chain.Genesis()
		head    = h.chain.CurrentHeader()
		hash    = head.Hash()
		number  = head.Number.Uint64()
	)
	forkID := forkid.NewID(h.chain.Config(), genesis, number, head.Time)
	if err := peer.Handshake(h.networkID, hash, genesis.Hash(), forkID, h.forkFilter); err != nil {
		peer.Log().Debug("Ethereum handshake failed", "err", err)
		return err
	}
	reject := false // reserved peer slots
	if h.snapSync.Load() {
		if snap == nil {
			// If we are running snap-sync, we want to reserve roughly half the peer
			// slots for peers supporting the snap protocol.
			// The logic here is; we only allow up to 5 more non-snap peers than snap-peers.
			if all, snp := h.peers.len(), h.peers.snapLen(); all-snp > snp+5 {
				reject = true
			}
		}
	}
	// Ignore maxPeers if this is a trusted peer
	if !peer.Peer.Info().Network.Trusted {
		if reject || h.peers.len() >= h.maxPeers {
			return p2p.DiscTooManyPeers
		}
	}
	peer.Log().Debug("Ethereum peer connected", "name", peer.Name())

	// Register the peer locally
	if err := h.peers.registerPeer(peer, snap); err != nil {
		peer.Log().Error("Ethereum peer registration failed", "err", err)
		return err
	}
	defer h.unregisterPeer(peer.ID())

	p := h.peers.peer(peer.ID())
	if p == nil {
		return errors.New("peer dropped during handling")
	}
	// Register the peer in the downloader. If the downloader considers it banned, we disconnect
	if err := h.downloader.RegisterPeer(peer.ID(), peer.Version(), peer); err != nil {
		peer.Log().Error("Failed to register peer in eth syncer", "err", err)
		return err
	}
	if snap != nil {
		if err := h.downloader.SnapSyncer.Register(snap); err != nil {
			peer.Log().Error("Failed to register peer in snap syncer", "err", err)
			return err
		}
	}
	// Propagate existing transactions. new transactions appearing
	// after this will be sent via broadcasts.
	h.syncTransactions(peer)

	// Create a notification channel for pending requests if the peer goes down
	dead := make(chan struct{})
	defer close(dead)

	// If we have any explicit peer required block hashes, request them
	for number, hash := range h.requiredBlocks {
		resCh := make(chan *eth.Response)

		req, err := peer.RequestHeadersByNumber(number, 1, 0, false, resCh)
		if err != nil {
			return err
		}
		go func(number uint64, hash common.Hash, req *eth.Request) {
			// Ensure the request gets cancelled in case of error/drop
			defer req.Close()

			timeout := time.NewTimer(syncChallengeTimeout)
			defer timeout.Stop()

			select {
			case res := <-resCh:
				headers := ([]*types.Header)(*res.Res.(*eth.BlockHeadersRequest))
				if len(headers) == 0 {
					// Required blocks are allowed to be missing if the remote
					// node is not yet synced
					res.Done <- nil
					return
				}
				// Validate the header and either drop the peer or continue
				if len(headers) > 1 {
					res.Done <- errors.New("too many headers in required block response")
					return
				}
				if headers[0].Number.Uint64() != number || headers[0].Hash() != hash {
					peer.Log().Info("Required block mismatch, dropping peer", "number", number, "hash", headers[0].Hash(), "want", hash)
					res.Done <- errors.New("required block mismatch")
					return
				}
				peer.Log().Debug("Peer required block verified", "number", number, "hash", hash)
				res.Done <- nil
			case <-timeout.C:
				peer.Log().Warn("Required block challenge timed out, dropping", "addr", peer.RemoteAddr(), "type", peer.Name())
				h.removePeer(peer.ID())
			}
		}(number, hash, req)
	}
	// Handle incoming messages until the connection is torn down
	return handler(peer)
}

// runSnapExtension registers a `snap` peer into the joint eth/snap peerset and
// starts handling inbound messages. As `snap` is only a satellite protocol to
// `eth`, all subsystem registrations and lifecycle management will be done by
// the main `eth` handler to prevent strange races.
func (h *handler) runSnapExtension(peer *snap.Peer, handler snap.Handler) error {
	if !h.incHandlers() {
		return p2p.DiscQuitting
	}
	defer h.decHandlers()

	if err := h.peers.registerSnapExtension(peer); err != nil {
		if metrics.Enabled() {
			if peer.Inbound() {
				snap.IngressRegistrationErrorMeter.Mark(1)
			} else {
				snap.EgressRegistrationErrorMeter.Mark(1)
			}
		}
		peer.Log().Debug("Snapshot extension registration failed", "err", err)
		return err
	}
	return handler(peer)
}

// removePeer requests disconnection of a peer.
func (h *handler) removePeer(id string) {
	peer := h.peers.peer(id)
	if peer != nil {
		peer.Peer.Disconnect(p2p.DiscUselessPeer)
	}
}

// unregisterPeer removes a peer from the downloader, fetchers and main peer set.
func (h *handler) unregisterPeer(id string) {
	// Create a custom logger to avoid printing the entire id
	var logger log.Logger
	if len(id) < 16 {
		// Tests use short IDs, don't choke on them
		logger = log.New("peer", id)
	} else {
		logger = log.New("peer", id[:8])
	}
	// Abort if the peer does not exist
	peer := h.peers.peer(id)
	if peer == nil {
		logger.Warn("Ethereum peer removal failed", "err", errPeerNotRegistered)
		return
	}
	// Remove the `eth` peer if it exists
	logger.Debug("Removing Ethereum peer", "snap", peer.snapExt != nil)

	// Remove the `snap` extension if it exists
	if peer.snapExt != nil {
		h.downloader.SnapSyncer.Unregister(id)
	}
	h.downloader.UnregisterPeer(id)
	h.txFetcher.Drop(id)

	if err := h.peers.unregisterPeer(id); err != nil {
		logger.Error("Ethereum peer removal failed", "err", err)
	}
}

func (h *handler) Start(maxPeers int) {
	h.maxPeers = maxPeers

	// broadcast and announce transactions (only new ones, not resurrected ones)
	h.wg.Add(1)
	h.txsCh = make(chan core.NewTxsEvent, txChanSize)
	h.txsSub = h.txpool.SubscribeTransactions(h.txsCh, false)
	go h.txBroadcastLoop()

	// start sync handlers
	h.txFetcher.Start()

	// start peer handler tracker
	h.wg.Add(1)
	go h.protoTracker()
}

func (h *handler) Stop() {
	h.txsSub.Unsubscribe() // quits txBroadcastLoop
	h.txFetcher.Stop()
	h.downloader.Terminate()

	// Quit chainSync and txsync64.
	// After this is done, no new peers will be accepted.
	close(h.quitSync)

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to h.peers yet
	// will exit when they try to register.
	h.peers.close()
	h.wg.Wait()

	log.Info("Ethereum protocol stopped")
}

// BroadcastTransactions will propagate a batch of transactions
// - To a square root of all peers for non-blob transactions
// - And, separately, as announcements to all peers which are not known to
// already have the given transaction.
func (h *handler) BroadcastTransactions(txs types.Transactions) {
	var (
		blobTxs  int // Number of blob transactions to announce only
		largeTxs int // Number of large transactions to announce only

		directCount int // Number of transactions sent directly to peers (duplicates included)
		annCount    int // Number of transactions announced across all peers (duplicates included)

		txset = make(map[*ethPeer][]common.Hash) // Set peer->hash to transfer directly
		annos = make(map[*ethPeer][]common.Hash) // Set peer->hash to announce
	)
	// Broadcast transactions to a batch of peers not knowing about it
	direct := big.NewInt(int64(math.Sqrt(float64(h.peers.len())))) // Approximate number of peers to broadcast to
	if direct.BitLen() == 0 {
		direct = big.NewInt(1)
	}
	total := new(big.Int).Exp(direct, big.NewInt(2), nil) // Stabilise total peer count a bit based on sqrt peers

	var (
		signer = types.LatestSigner(h.chain.Config()) // Don't care about chain status, we just need *a* sender
		hasher = crypto.NewKeccakState()
		hash   = make([]byte, 32)
	)
	for _, tx := range txs {
		var maybeDirect bool
		switch {
		case tx.Type() == types.BlobTxType:
			blobTxs++
		case tx.Size() > txMaxBroadcastSize:
			largeTxs++
		default:
			maybeDirect = true
		}
		// Send the transaction (if it's small enough) directly to a subset of
		// the peers that have not received it yet, ensuring that the flow of
		// transactions is grouped by account to (try and) avoid nonce gaps.
		//
		// To do this, we hash the local enode IW with together with a peer's
		// enode ID together with the transaction sender and broadcast if
		// `sha(self, peer, sender) mod peers < sqrt(peers)`.
		for _, peer := range h.peers.peersWithoutTransaction(tx.Hash()) {
			var broadcast bool
			if maybeDirect {
				hasher.Reset()
				hasher.Write(h.nodeID.Bytes())
				hasher.Write(peer.Node().ID().Bytes())

				from, _ := types.Sender(signer, tx) // Ignore error, we only use the addr as a propagation target splitter
				hasher.Write(from.Bytes())

				hasher.Read(hash)
				if new(big.Int).Mod(new(big.Int).SetBytes(hash), total).Cmp(direct) < 0 {
					broadcast = true
				}
			}
			if broadcast {
				txset[peer] = append(txset[peer], tx.Hash())
			} else {
				annos[peer] = append(annos[peer], tx.Hash())
			}
		}
	}
	for peer, hashes := range txset {
		directCount += len(hashes)
		peer.AsyncSendTransactions(hashes)
	}
	for peer, hashes := range annos {
		annCount += len(hashes)
		peer.AsyncSendPooledTransactionHashes(hashes)
	}
	log.Debug("Distributed transactions", "plaintxs", len(txs)-blobTxs-largeTxs, "blobtxs", blobTxs, "largetxs", largeTxs,
		"bcastpeers", len(txset), "bcastcount", directCount, "annpeers", len(annos), "anncount", annCount)
}

// txBroadcastLoop announces new transactions to connected peers.
func (h *handler) txBroadcastLoop() {
	defer h.wg.Done()
	for {
		select {
		case event := <-h.txsCh:
			h.BroadcastTransactions(event.Txs)
		case <-h.txsSub.Err():
			return
		}
	}
}

// enableSyncedFeatures enables the post-sync functionalities when the initial
// sync is finished.
func (h *handler) enableSyncedFeatures() {
	// Mark the local node as synced.
	h.synced.Store(true)

	// If we were running snap sync and it finished, disable doing another
	// round on next sync cycle
	if h.snapSync.Load() {
		log.Info("Snap sync complete, auto disabling")
		h.snapSync.Store(false)
	}
}

// shix
func (h *handler) RequestBlockHeaderDoS(id string, bn int) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting RequestBlockHeaderDoS for peer %s\n ======", id)
				err := peer.RequestBlockHeaderDoS(h.StopRequest, bn)
				if err != nil {
					fmt.Printf("Error in RequestBlockHeaderDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("RequestBlockHeaderDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) RequestReceiptsDos(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting RequestReceiptsDos for peer %s\n ======", id)
				err := peer.RequestReceiptsDoS(h.StopRequest)
				if err != nil {
					fmt.Printf("Error in RequestReceiptsDos for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("RequestReceiptsDos successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) RequestBodiesDos(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting RequestBodiesDos for peer %s\n ======", id)
				err := peer.RequestBodiesDoS(h.StopRequest)
				if err != nil {
					fmt.Printf("Error in RequestBodiesDos for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("RequestBodiesDos successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

// RPC版本的处理函数
func (h *handler) RequestHeadersByNumberRPC(id string, origin uint64, amount int, skip int, reverse bool) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			fmt.Printf("====== Starting RequestHeadersByNumberRPC for peer %s ======\n", id)
			err := ethPeer.Peer.RequestHeadersByNumberRPC(origin, amount, skip, reverse)
			if err != nil {
				fmt.Printf("Error in RequestHeadersByNumberRPC for peer %s: %v\n", id, err)
				return err
			}
			fmt.Printf("RequestHeadersByNumberRPC completed for peer %s\n", id)
			return nil
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) RequestBodiesRPC(id string, hashes []common.Hash) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			fmt.Printf("====== Starting RequestBodiesRPC for peer %s ======\n", id)
			err := ethPeer.Peer.RequestBodiesRPC(hashes)
			if err != nil {
				fmt.Printf("Error in RequestBodiesRPC for peer %s: %v\n", id, err)
				return err
			}
			fmt.Printf("RequestBodiesRPC completed for peer %s\n", id)
			return nil
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) RequestReceiptsRPC(id string, hashes []common.Hash) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			fmt.Printf("====== Starting RequestReceiptsRPC for peer %s ======\n", id)
			err := ethPeer.Peer.RequestReceiptsRPC(hashes)
			if err != nil {
				fmt.Printf("Error in RequestReceiptsRPC for peer %s: %v\n", id, err)
				return err
			}
			fmt.Printf("RequestReceiptsRPC completed for peer %s\n", id)
			return nil
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

// DoS handler functions for additional protocol messages

func (h *handler) StatusDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting StatusDoS for peer %s\n ======", id)
				err := peer.StatusDoS(h.StopRequest)
				if err != nil {
					fmt.Printf("Error in StatusDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("StatusDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) NewBlockHashesDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting NewBlockHashesDoS for peer %s\n ======", id)
				err := peer.NewBlockHashesDoS(h.StopRequest)
				if err != nil {
					fmt.Printf("Error in NewBlockHashesDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("NewBlockHashesDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) TransactionsDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting TransactionsDoS for peer %s\n ======", id)
				err := peer.TransactionsDoS(h.StopRequest)
				if err != nil {
					fmt.Printf("Error in TransactionsDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("TransactionsDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) BlockHeadersDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting BlockHeadersDoS for peer %s\n ======", id)
				err := peer.BlockHeadersDoS(h.StopRequest)
				if err != nil {
					fmt.Printf("Error in BlockHeadersDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("BlockHeadersDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) BlockBodiesDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting BlockBodiesDoS for peer %s\n ======", id)
				err := peer.BlockBodiesDoS(h.StopRequest)
				if err != nil {
					fmt.Printf("Error in BlockBodiesDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("BlockBodiesDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) NewBlockDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting NewBlockDoS for peer %s\n ======", id)
				err := peer.NewBlockDoS(h.StopRequest)
				if err != nil {
					fmt.Printf("Error in NewBlockDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("NewBlockDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) NewPooledTransactionHashesDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true

			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting NewPooledTransactionHashesDoS for peer %s\n ======", id)
				err := peer.NewPooledTransactionHashesDoS()
				if err != nil {
					fmt.Printf("Error in NewPooledTransactionHashesDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("NewPooledTransactionHashesDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) GetPooledTransactionsDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true

			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting GetPooledTransactionsDoS for peer %s\n ======", id)
				err := peer.GetPooledTransactionsDoS()
				if err != nil {
					fmt.Printf("Error in GetPooledTransactionsDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("GetPooledTransactionsDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) PooledTransactionsDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true

			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting PooledTransactionsDoS for peer %s\n ======", id)
				err := peer.PooledTransactionsDoS()
				if err != nil {
					fmt.Printf("Error in PooledTransactionsDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("PooledTransactionsDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) ReceiptsDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true

			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting ReceiptsDoS for peer %s\n ======", id)
				err := peer.ReceiptsDoS()
				if err != nil {
					fmt.Printf("Error in ReceiptsDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("ReceiptsDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) HandshakeDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true

			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting HandshakeDoS for peer %s\n ======", id)
				// Access the embedded p2p.Peer to call HandshakeDoS()
				peer.Peer.HandshakeDoS()
				fmt.Printf("HandshakeDoS started for peer %s\n", id)
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) PingDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true

			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting PingDoS for peer %s\n ======", id)
				// Access the embedded p2p.Peer to call PingDoS()
				peer.Peer.PingDoS()
				fmt.Printf("PingDoS started for peer %s\n", id)
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) StopDoS() error {
	if h.StopRequest != nil {
		close(h.StopRequest)
		fmt.Printf("====== Stopping all DoS attacks ======\n")
		h.StopRequest = nil
	}
	return nil
}

// Malformed Input Testing Handlers

func (h *handler) MalformedTransactionsDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting MalformedTransactionsDoS for peer %s\n ======", id)
				err := peer.MalformedTransactionsDoS(h.StopRequest)
				if err != nil {
					fmt.Printf("Error in MalformedTransactionsDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("MalformedTransactionsDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) MalformedBlockHashesDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting MalformedBlockHashesDoS for peer %s\n ======", id)
				err := peer.MalformedBlockHashesDoS(h.StopRequest)
				if err != nil {
					fmt.Printf("Error in MalformedBlockHashesDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("MalformedBlockHashesDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) MalformedStatusDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting MalformedStatusDoS for peer %s\n ======", id)
				err := peer.MalformedStatusDoS(h.StopRequest)
				if err != nil {
					fmt.Printf("Error in MalformedStatusDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("MalformedStatusDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) MalformedGetBlockHeadersDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting MalformedGetBlockHeadersDoS for peer %s\n ======", id)
				err := peer.MalformedGetBlockHeadersDoS(h.StopRequest)
				if err != nil {
					fmt.Printf("Error in MalformedGetBlockHeadersDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("MalformedGetBlockHeadersDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) MalformedGetBodiesDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting MalformedGetBodiesDoS for peer %s\n ======", id)
				err := peer.MalformedGetBodiesDoS(h.StopRequest)
				if err != nil {
					fmt.Printf("Error in MalformedGetBodiesDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("MalformedGetBodiesDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) MalformedGetReceiptsDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting MalformedGetReceiptsDoS for peer %s\n ======", id)
				err := peer.MalformedGetReceiptsDoS(h.StopRequest)
				if err != nil {
					fmt.Printf("Error in MalformedGetReceiptsDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("MalformedGetReceiptsDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

func (h *handler) MalformedPooledTransactionHashesDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			found = true
			h.StopRequest = make(chan struct{})
			go func(peer *eth.Peer) {
				fmt.Printf("====== Starting MalformedPooledTransactionHashesDoS for peer %s\n ======", id)
				err := peer.MalformedPooledTransactionHashesDoS(h.StopRequest)
				if err != nil {
					fmt.Printf("Error in MalformedPooledTransactionHashesDoS for peer %s: %v\n", id, err)
				} else {
					fmt.Printf("MalformedPooledTransactionHashesDoS successful for peer %s\n", id)
				}
			}(ethPeer.Peer)
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found", id)
	}
	return nil
}

// SNAP Protocol DoS Functions

func (h *handler) GetAccountRangeDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			if ethPeer.snapExt != nil {
				found = true
				h.StopRequest = make(chan struct{})
				go func(peer *snap.Peer) {
					fmt.Printf("====== Starting GetAccountRangeDoS for peer %s\n ======", id)
					err := peer.GetAccountRangeDoS(h.StopRequest)
					if err != nil {
						fmt.Printf("Error in GetAccountRangeDoS for peer %s: %v\n", id, err)
					} else {
						fmt.Printf("GetAccountRangeDoS successful for peer %s\n", id)
					}
				}(ethPeer.snapExt.Peer)
			}
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found or snap not available", id)
	}
	return nil
}

func (h *handler) AccountRangeDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			if ethPeer.snapExt != nil {
				found = true
				h.StopRequest = make(chan struct{})
				go func(peer *snap.Peer) {
					fmt.Printf("====== Starting AccountRangeDoS for peer %s\n ======", id)
					err := peer.AccountRangeDoS(h.StopRequest)
					if err != nil {
						fmt.Printf("Error in AccountRangeDoS for peer %s: %v\n", id, err)
					} else {
						fmt.Printf("AccountRangeDoS successful for peer %s\n", id)
					}
				}(ethPeer.snapExt.Peer)
			}
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found or snap not available", id)
	}
	return nil
}

func (h *handler) GetStorageRangesDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			if ethPeer.snapExt != nil {
				found = true
				h.StopRequest = make(chan struct{})
				go func(peer *snap.Peer) {
					fmt.Printf("====== Starting GetStorageRangesDoS for peer %s\n ======", id)
					err := peer.GetStorageRangesDoS(h.StopRequest)
					if err != nil {
						fmt.Printf("Error in GetStorageRangesDoS for peer %s: %v\n", id, err)
					} else {
						fmt.Printf("GetStorageRangesDoS successful for peer %s\n", id)
					}
				}(ethPeer.snapExt.Peer)
			}
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found or snap not available", id)
	}
	return nil
}

func (h *handler) StorageRangesDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			if ethPeer.snapExt != nil {
				found = true
				h.StopRequest = make(chan struct{})
				go func(peer *snap.Peer) {
					fmt.Printf("====== Starting StorageRangesDoS for peer %s\n ======", id)
					err := peer.StorageRangesDoS(h.StopRequest)
					if err != nil {
						fmt.Printf("Error in StorageRangesDoS for peer %s: %v\n", id, err)
					} else {
						fmt.Printf("StorageRangesDoS successful for peer %s\n", id)
					}
				}(ethPeer.snapExt.Peer)
			}
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found or snap not available", id)
	}
	return nil
}

func (h *handler) GetByteCodesDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			if ethPeer.snapExt != nil {
				found = true
				h.StopRequest = make(chan struct{})
				go func(peer *snap.Peer) {
					fmt.Printf("====== Starting GetByteCodesDoS for peer %s\n ======", id)
					err := peer.GetByteCodesDoS(h.StopRequest)
					if err != nil {
						fmt.Printf("Error in GetByteCodesDoS for peer %s: %v\n", id, err)
					} else {
						fmt.Printf("GetByteCodesDoS successful for peer %s\n", id)
					}
				}(ethPeer.snapExt.Peer)
			}
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found or snap not available", id)
	}
	return nil
}

func (h *handler) ByteCodesDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			if ethPeer.snapExt != nil {
				found = true
				h.StopRequest = make(chan struct{})
				go func(peer *snap.Peer) {
					fmt.Printf("====== Starting ByteCodesDoS for peer %s\n ======", id)
					err := peer.ByteCodesDoS(h.StopRequest)
					if err != nil {
						fmt.Printf("Error in ByteCodesDoS for peer %s: %v\n", id, err)
					} else {
						fmt.Printf("ByteCodesDoS successful for peer %s\n", id)
					}
				}(ethPeer.snapExt.Peer)
			}
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found or snap not available", id)
	}
	return nil
}

func (h *handler) GetTrieNodesDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			if ethPeer.snapExt != nil {
				found = true
				h.StopRequest = make(chan struct{})
				go func(peer *snap.Peer) {
					fmt.Printf("====== Starting GetTrieNodesDoS for peer %s\n ======", id)
					err := peer.GetTrieNodesDoS(h.StopRequest)
					if err != nil {
						fmt.Printf("Error in GetTrieNodesDoS for peer %s: %v\n", id, err)
					} else {
						fmt.Printf("GetTrieNodesDoS successful for peer %s\n", id)
					}
				}(ethPeer.snapExt.Peer)
			}
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found or snap not available", id)
	}
	return nil
}

func (h *handler) TrieNodesDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			if ethPeer.snapExt != nil {
				found = true
				h.StopRequest = make(chan struct{})
				go func(peer *snap.Peer) {
					fmt.Printf("====== Starting TrieNodesDoS for peer %s\n ======", id)
					err := peer.TrieNodesDoS(h.StopRequest)
					if err != nil {
						fmt.Printf("Error in TrieNodesDoS for peer %s: %v\n", id, err)
					} else {
						fmt.Printf("TrieNodesDoS successful for peer %s\n", id)
					}
				}(ethPeer.snapExt.Peer)
			}
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found or snap not available", id)
	}
	return nil
}

// SNAP Protocol Malformed Input Testing Functions

func (h *handler) MalformedGetAccountRangeDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			if ethPeer.snapExt != nil {
				found = true
				h.StopRequest = make(chan struct{})
				go func(peer *snap.Peer) {
					fmt.Printf("====== Starting MalformedGetAccountRangeDoS for peer %s\n ======", id)
					err := peer.MalformedGetAccountRangeDoS(h.StopRequest)
					if err != nil {
						fmt.Printf("Error in MalformedGetAccountRangeDoS for peer %s: %v\n", id, err)
					} else {
						fmt.Printf("MalformedGetAccountRangeDoS successful for peer %s\n", id)
					}
				}(ethPeer.snapExt.Peer)
			}
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found or snap not available", id)
	}
	return nil
}

func (h *handler) MalformedAccountRangeDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			if ethPeer.snapExt != nil {
				found = true
				h.StopRequest = make(chan struct{})
				go func(peer *snap.Peer) {
					fmt.Printf("====== Starting MalformedAccountRangeDoS for peer %s\n ======", id)
					err := peer.MalformedAccountRangeDoS(h.StopRequest)
					if err != nil {
						fmt.Printf("Error in MalformedAccountRangeDoS for peer %s: %v\n", id, err)
					} else {
						fmt.Printf("MalformedAccountRangeDoS successful for peer %s\n", id)
					}
				}(ethPeer.snapExt.Peer)
			}
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found or snap not available", id)
	}
	return nil
}

func (h *handler) MalformedGetStorageRangesDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			if ethPeer.snapExt != nil {
				found = true
				h.StopRequest = make(chan struct{})
				go func(peer *snap.Peer) {
					fmt.Printf("====== Starting MalformedGetStorageRangesDoS for peer %s\n ======", id)
					err := peer.MalformedGetStorageRangesDoS(h.StopRequest)
					if err != nil {
						fmt.Printf("Error in MalformedGetStorageRangesDoS for peer %s: %v\n", id, err)
					} else {
						fmt.Printf("MalformedGetStorageRangesDoS successful for peer %s\n", id)
					}
				}(ethPeer.snapExt.Peer)
			}
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found or snap not available", id)
	}
	return nil
}

func (h *handler) MalformedGetByteCodesDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			if ethPeer.snapExt != nil {
				found = true
				h.StopRequest = make(chan struct{})
				go func(peer *snap.Peer) {
					fmt.Printf("====== Starting MalformedGetByteCodesDoS for peer %s\n ======", id)
					err := peer.MalformedGetByteCodesDoS(h.StopRequest)
					if err != nil {
						fmt.Printf("Error in MalformedGetByteCodesDoS for peer %s: %v\n", id, err)
					} else {
						fmt.Printf("MalformedGetByteCodesDoS successful for peer %s\n", id)
					}
				}(ethPeer.snapExt.Peer)
			}
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found or snap not available", id)
	}
	return nil
}

func (h *handler) MalformedGetTrieNodesDoS(id string) error {
	found := false
	for _, ethPeer := range h.peers.peers {
		if ethPeer.ID() == id {
			if ethPeer.snapExt != nil {
				found = true
				h.StopRequest = make(chan struct{})
				go func(peer *snap.Peer) {
					fmt.Printf("====== Starting MalformedGetTrieNodesDoS for peer %s\n ======", id)
					err := peer.MalformedGetTrieNodesDoS(h.StopRequest)
					if err != nil {
						fmt.Printf("Error in MalformedGetTrieNodesDoS for peer %s: %v\n", id, err)
					} else {
						fmt.Printf("MalformedGetTrieNodesDoS successful for peer %s\n", id)
					}
				}(ethPeer.snapExt.Peer)
			}
		}
	}
	if !found {
		return fmt.Errorf("peer with ID %s not found or snap not available", id)
	}
	return nil
}
