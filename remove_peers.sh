#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${RPC_URL:-http://127.0.0.1:12545}"

echo "RPC = $RPC_URL"

# 1) Tools check
if ! command -v curl >/dev/null 2>&1; then
  echo "❌ curl not found. Please install curl first."
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "❌ jq not found. Please install jq (Ubuntu: sudo apt-get install -y jq)"
  exit 1
fi

# A small helper: send JSON-RPC and return the response
rpc() {
  local payload="$1"
  curl -sS -H 'Content-Type: application/json' -d "$payload" "$RPC_URL"
}

# 2) Quick connectivity / module check
echo "Checking JSON-RPC availability..."
VERS=$(rpc '{"jsonrpc":"2.0","id":1,"method":"web3_clientVersion","params":[]}' | jq -r '.result // empty')
if [ -z "$VERS" ]; then
  echo "❌ Cannot reach JSON-RPC (web3_clientVersion returned nothing). Check Nethermind's JsonRpc port / listening address / firewall."
  exit 1
else
  echo "✅ Connected: $VERS"
fi

echo "Checking enabled modules (should include Admin)..."
MODS=$(rpc '{"jsonrpc":"2.0","id":1,"method":"rpc_modules","params":[]}')
echo "rpc_modules raw => $MODS"
HAS_ADMIN=$(echo "$MODS" | jq -r '.result | has("admin")')
if [ "$HAS_ADMIN" != "true" ]; then
  echo "⚠️ The Admin module does not appear to be enabled. Please enable Admin in Nethermind config (JsonRpc.EnabledModules or EnabledModules include Admin) and restart."
fi

# 3) Check current peer count
echo "Checking net_peerCount..."
PHEX=$(rpc '{"jsonrpc":"2.0","id":1,"method":"net_peerCount","params":[]}' | jq -r '.result // empty')
if [ -z "$PHEX" ]; then
  echo "⚠️ net_peerCount returned nothing. Will try admin_peers next..."
else
  # hex -> decimal
  PDEC=$((16#${PHEX#0x}))
  echo "Current connected peers: $PDEC"
fi

# 4) Fetch peers (try two ways)
echo "Fetching peers (try with params)..."
RESP1=$(rpc '{"jsonrpc":"2.0","id":1,"method":"admin_peers","params":[false]}')
if [ "$(echo "$RESP1" | jq -r '.error // empty')" != "" ]; then
  echo "admin_peers with params returned error, trying without params..."
  RESP2=$(rpc '{"jsonrpc":"2.0","id":1,"method":"admin_peers","params":[]}')
  echo "admin_peers (no params) raw => $RESP2"
  PEERS_JSON="$RESP2"
else
  echo "admin_peers (with params) raw => $RESP1"
  PEERS_JSON="$RESP1"
fi

# 5) Extract enode(s)
PEERS=$(echo "$PEERS_JSON" | jq -r '.result[]?.enode // empty')
if [ -z "${PEERS:-}" ]; then
  echo "🟨 No enode entries extracted. Possible reasons:"
  echo "  - There are indeed no connected peers (net_peerCount=0);"
  echo "  - Admin module is not enabled or lacks permissions;"
  echo "  - Your Nethermind version returns admin_peers in a different structure (you can send me the raw output above and I can adapt the script);"
  echo "  - You're connected to the wrong JSON-RPC port."
  exit 0
fi

# 6) Remove peers one by one
COUNT=0
while IFS= read -r ENODE; do
  [ -z "$ENODE" ] && continue
  echo "Removing $ENODE ..."
  # Try both signatures: first try with removeFromStaticNodes = true, fallback to single-arg
  RES_RM=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"admin_removePeer\",\"params\":[\"$ENODE\", true]}")
  ERR=$(echo "$RES_RM" | jq -r '.error // empty')
  if [ -n "$ERR" ]; then
    echo "  ⚠️ Removal with parameter failed, trying single-arg..."
    RES_RM=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"admin_removePeer\",\"params\":[\"$ENODE\"]}")
    echo "  admin_removePeer raw => $RES_RM"
  else
    echo "  admin_removePeer raw => $RES_RM"
  fi
  COUNT=$((COUNT+1))
done <<< "$PEERS"

echo "✅ Done. Attempted to remove $COUNT peers."
