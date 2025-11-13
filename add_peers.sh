#!/bin/bash

##############################################
# Usage:
#   ./eth_rpc.sh add <start> <end>     # Add peer to nodes <start> to <end> (inclusive)
#   ./eth_rpc.sh add <number>          # Add peer to node <number>
#
#   ./eth_rpc.sh check <start> <end>   # Check peers of nodes <start> to <end> (inclusive)
#   ./eth_rpc.sh check <number>        # Check peers of node <number>
##############################################
PEER_ENODE='enode://caa6ac82f7b8e27ec10542e7e9f08ab5a68eb81d8a3b1b57887f3152fdb1f071c8379f8e226d1cacf9e9a089b381ccf08b15e3c66e61af3f9b97bd93668a7ee4@155.246.103.91:30303'
#PEER_ENODE='enode://4479db0c3ac27d56d9fc5fca8cecc33857f4d68431d56d87520c604247a38a8d013f2cc510610dde14b2b2851e732dc104704122301a5e1c2f6cd421e05ba279@155.246.103.117:30303'
#PEER_ENODE='enode://f42b6020aac03557bc156e3d3eab940ea27d4c1c6fd11b06846cdfd7637fb1ea05f61b7fd20585a593c3481e759bac355c5586499adc4a037f6058ff421d0d02@155.246.103.55:30303'
BASE_HTTP_PORT=10500

add_peer() {
    i=$1
    HTTP_PORT=$((BASE_HTTP_PORT + i))
    curl -s -X POST http://localhost:$HTTP_PORT \
        -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"admin_addPeer\",\"params\":[\"$PEER_ENODE\"],\"id\":1}" \
        && echo " => Sent addPeer to node $i (port $HTTP_PORT)"
}

check_peers() {
    i=$1
    HTTP_PORT=$((BASE_HTTP_PORT + i))
    result=$(curl -s -X POST http://localhost:$HTTP_PORT \
        -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"admin_peers","params":[],"id":1}')

    count=$(echo "$result" | grep -o '"enode":' | wc -l)
    echo "Node $i (port $HTTP_PORT) has $count peer(s)"
}

if [[ "$1" != "add" && "$1" != "check" ]]; then
    echo "Usage:"
    echo "  ./eth_rpc.sh add <start> <end>     # Add peer to nodes"
    echo "  ./eth_rpc.sh check <start> <end>   # Check peers of nodes"
    echo "  ./eth_rpc.sh add <number>          # Add peer to one node"
    echo "  ./eth_rpc.sh check <number>        # Check peers of one node"
    exit 1
fi

COMMAND=$1
START=$2
END=$3

if [[ -n "$START" && -n "$END" ]]; then
    for ((i=START; i<=END; i++)); do
        if [[ "$COMMAND" == "add" ]]; then
            add_peer "$i"
        else
            check_peers "$i"
        fi
    done
elif [[ -n "$START" ]]; then
    if [[ "$COMMAND" == "add" ]]; then
        add_peer "$START"
    else
        check_peers "$START"
    fi
else
    echo "Invalid usage."
    exit 1
fi