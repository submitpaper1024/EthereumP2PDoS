#!/bin/bash

# Configuration
# Read command and optional port
COMMAND="$1"
PORT="${2:-10545}"
RPC_URL="http://localhost:$PORT"
PEER_ID="cdcebd8e73eea89a8f0d3be5ec55574f3b65a95e15d5b05fafd087fd4745ea40"
#PEER_ID="6c4ae76fa8bcbb5ce1bbc2c70c34a96da367cbbd96698f9fac54abd68aa0ad4d"
PRIVATE_KEY=""


# Function to make RPC calls
make_rpc_call() {
    local method=$1
    local params=$2

    curl -X POST -H "Content-Type: application/json" --data "{
    \"jsonrpc\":\"2.0\",
    \"method\":\"eth_${method}\",
    \"params\":[${params}],
    \"id\":1
    }" $RPC_URL
}

# Function to show usage
show_usage() {
    echo "Usage: $0 <command>"
    echo "Available commands:"
    echo "  # ETH Protocol DoS Commands:"
    echo "  blockHeadersDoS"
    echo "  blockBodiesDoS"
    echo "  receiptsDoS"
    echo "  newBlockHashesDoS"
    echo "  newBlockDoS"
    echo "  statusDoS"
    echo "  pooledTransactionsDoS"
    echo "  newPooledTransactionHashesDoS"
    echo "  transactionsDoS"
    echo "  requestBlockHeaderDoS"
    echo "  requestReceiptsDoS"
    echo "  requestBodiesDoS"
    echo "  requestPooledTransactionsDoS"
    echo "  handshakeDoS"
    echo "  pingDoS"
    echo ""
    echo "  # SNAP Protocol DoS Commands:"
    echo "  getAccountRangeDoS"
    echo "  accountRangeDoS"
    echo "  getStorageRangesDoS"
    echo "  storageRangesDoS"
    echo "  getByteCodesDoS"
    echo "  byteCodesDoS"
    echo "  getTrieNodesDoS"
    echo "  trieNodesDoS"
    echo ""
    echo "  # ETH Protocol Malformed Input Testing Commands:"
    echo "  malformedTransactionsDoS"
    echo "  malformedBlockHashesDoS"
    echo "  malformedStatusDoS"
    echo "  malformedGetBlockHeadersDoS"
    echo "  malformedGetBodiesDoS"
    echo "  malformedGetReceiptsDoS"
    echo "  malformedPooledTransactionHashesDoS"
    echo ""
    echo "  # SNAP Protocol Malformed Input Testing Commands:"
    echo "  malformedGetAccountRangeDoS"
    echo "  malformedAccountRangeDoS"
    echo "  malformedGetStorageRangesDoS"
    echo "  malformedGetByteCodesDoS"
    echo "  malformedGetTrieNodesDoS"
    echo ""
    echo "  # Control Commands:"
    echo "  stopDoS"
    echo "  help"
}

# Main script
if [ -z "$COMMAND" ]; then
    show_usage
    exit 1
fi
case "$COMMAND" in
    # ETH Protocol DoS Commands
    "blockHeadersDoS")
        make_rpc_call "blockHeadersDoS" "\"$PEER_ID\""
        ;;
    "blockBodiesDoS")
        make_rpc_call "blockBodiesDoS" "\"$PEER_ID\""
        ;;
    "receiptsDoS")
        make_rpc_call "receiptsDoS" "\"$PEER_ID\""
        ;;
    "newBlockHashesDoS")
        make_rpc_call "newBlockHashesDoS" "\"$PEER_ID\""
        ;;
    "newBlockDoS")
        make_rpc_call "newBlockDoS" "\"$PEER_ID\""
        ;;
    "statusDoS")
        make_rpc_call "statusDoS" "\"$PEER_ID\""
        ;;
    "pooledTransactionsDoS")
        make_rpc_call "pooledTransactionsDoS" "\"$PEER_ID\""
        ;;
    "newPooledTransactionHashesDoS")
        make_rpc_call "newPooledTransactionHashesDoS" "\"$PEER_ID\""
        ;;
    "transactionsDoS")
        make_rpc_call "transactionsDoS" "\"$PEER_ID\""
        ;;
    "requestBlockHeaderDoS")
        # RequestBlockHeaderDoS takes an additional block number parameter
        make_rpc_call "requestBlockHeaderDoS" "\"$PEER_ID\", 1000000"
        ;;
    "requestReceiptsDoS")
        make_rpc_call "requestReceiptsDos" "\"$PEER_ID\""
        ;;
    "requestBodiesDoS")
        make_rpc_call "requestBodiesDos" "\"$PEER_ID\""
        ;;
    "requestPooledTransactionsDoS")
        make_rpc_call "getPooledTransactionsDoS" "\"$PEER_ID\""
        ;;
    "handshakeDoS")
        make_rpc_call "handshakeDoS" "\"$PEER_ID\""
        ;;
    "pingDoS")
        make_rpc_call "pingDoS" "\"$PEER_ID\""
        ;;

    # SNAP Protocol DoS Commands
    "getAccountRangeDoS")
        make_rpc_call "getAccountRangeDoS" "\"$PEER_ID\""
        ;;
    "accountRangeDoS")
        make_rpc_call "accountRangeDoS" "\"$PEER_ID\""
        ;;
    "getStorageRangesDoS")
        make_rpc_call "getStorageRangesDoS" "\"$PEER_ID\""
        ;;
    "storageRangesDoS")
        make_rpc_call "storageRangesDoS" "\"$PEER_ID\""
        ;;
    "getByteCodesDoS")
        make_rpc_call "getByteCodesDoS" "\"$PEER_ID\""
        ;;
    "byteCodesDoS")
        make_rpc_call "byteCodesDoS" "\"$PEER_ID\""
        ;;
    "getTrieNodesDoS")
        make_rpc_call "getTrieNodesDoS" "\"$PEER_ID\""
        ;;
    "trieNodesDoS")
        make_rpc_call "trieNodesDoS" "\"$PEER_ID\""
        ;;

    # ETH Protocol Malformed Input Testing Commands
    "malformedTransactionsDoS")
        make_rpc_call "malformedTransactionsDoS" "\"$PEER_ID\""
        ;;
    "malformedBlockHashesDoS")
        make_rpc_call "malformedBlockHashesDoS" "\"$PEER_ID\""
        ;;
    "malformedStatusDoS")
        make_rpc_call "malformedStatusDoS" "\"$PEER_ID\""
        ;;
    "malformedGetBlockHeadersDoS")
        make_rpc_call "malformedGetBlockHeadersDoS" "\"$PEER_ID\""
        ;;
    "malformedGetBodiesDoS")
        make_rpc_call "malformedGetBodiesDoS" "\"$PEER_ID\""
        ;;
    "malformedGetReceiptsDoS")
        make_rpc_call "malformedGetReceiptsDoS" "\"$PEER_ID\""
        ;;
    "malformedPooledTransactionHashesDoS")
        make_rpc_call "malformedPooledTransactionHashesDoS" "\"$PEER_ID\""
        ;;

    # SNAP Protocol Malformed Input Testing Commands
    "malformedGetAccountRangeDoS")
        make_rpc_call "malformedGetAccountRangeDoS" "\"$PEER_ID\""
        ;;
    "malformedAccountRangeDoS")
        make_rpc_call "malformedAccountRangeDoS" "\"$PEER_ID\""
        ;;
    "malformedGetStorageRangesDoS")
        make_rpc_call "malformedGetStorageRangesDoS" "\"$PEER_ID\""
        ;;
    "malformedGetByteCodesDoS")
        make_rpc_call "malformedGetByteCodesDoS" "\"$PEER_ID\""
        ;;
    "malformedGetTrieNodesDoS")
        make_rpc_call "malformedGetTrieNodesDoS" "\"$PEER_ID\""
        ;;

    # Control Commands
    "stopDoS")
        make_rpc_call "stopDoS" ""
        ;;
    "help")
        show_usage
        ;;
    *)
        echo "Unknown command: $1"
        show_usage
        exit 1
        ;;
esac
