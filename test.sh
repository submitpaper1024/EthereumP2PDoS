#!/usr/bin/env bash
# DoS test harness for go-ethereum (generated)
# Purpose:
#  1) Whether compilation passes
#  2) Whether all required message types are covered (whether corresponding RPC exists)
#  3) Whether each test's RPC can be executed successfully
#
# Dependencies: bash, curl, jq (optional but highly recommended)
# Usage:
#   ./test.sh                              # run all checks
#   ./test.sh --only eth_status,discv4_ping  # run partial tests
#   ./test.sh --endpoint http://127.0.0.1:8545 --timeout 25
#   ./test.sh --help

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}"

ENDPOINT="http://127.0.0.1:8545"
TIMEOUT=20
ONLY=""
RETRIES=1
SLEEP_BETWEEN=1
OUTPUT_TXT="${ROOT_DIR}/feedback_report.txt"
OUTPUT_JSON="${ROOT_DIR}/feedback_report.json"
USE_STRICT_METHODS=0   # Set to 1 to use only dos_<id>, do not fallback to dos.<id>

JQ=$(command -v jq || true)

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --endpoint URL         RPC endpoint (default: ${ENDPOINT})
  --timeout SEC          curl max time per RPC (default: ${TIMEOUT})
  --retries N            retry count for failed RPCs (default ${RETRIES})
  --sleep SEC            sleep interval between retries (default ${SLEEP_BETWEEN})
  --only LIST            only run specified tests, comma-separated (see --list)
  --strict-methods       only try dos_<id> style, do not fallback to dos.<id>
  --list                 list all test IDs
  --help                 show this help

Output:
  - Human-readable: ${OUTPUT_TXT}
  - Machine-readable: ${OUTPUT_JSON}

Notes:
  - A local node must be running and exposing HTTP-RPC with your added DoS test RPC.
  - Each test corresponds to one RPC method, expected to be named: dos_<test_id> (script will also try dos.<test_id>).
  - Each call uses default params: [{ "mode": "max" }] to trigger "maximum packet size test".
EOF
}

ALL_TESTS=(
  # discv4
  discv4_ping
  discv4_findnode
  discv4_enr
  # discv5
  discv5_ping
  discv5_findnode
  discv5_talk
  # p2p
  p2p_handshake
  p2p_ping
  # eth
  eth_status
  eth_newBlockHashes
  eth_transactions
  eth_getBlockHeaders
  eth_blockHeaders
  eth_getBlockBodies
  eth_blockBodies
  eth_newBlock
  eth_newPooledTransactionHashes
  eth_getPooledTransactions
  eth_pooledTransactions
  eth_getReceipts
  eth_receipts
  # snap
  snap_getAccountRange
  snap_getStorageRanges
  snap_getByteCodes
  snap_getTrieNode
  snap_accountRange
  snap_storageRanges
  snap_byteCodes
  snap_trieNodes
)

# parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint) ENDPOINT="$2"; shift 2;;
    --timeout) TIMEOUT="$2"; shift 2;;
    --retries) RETRIES="$2"; shift 2;;
    --sleep) SLEEP_BETWEEN="$2"; shift 2;;
    --only) ONLY="$2"; shift 2;;
    --strict-methods) USE_STRICT_METHODS=1; shift 1;;
    --list)
      printf "%s\n" "${ALL_TESTS[@]}"
      exit 0
      ;;
    --help|-h) usage; exit 0;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2;;
  esac
done

# Filter tests if --only provided
SELECTED_TESTS=("${ALL_TESTS[@]}")
if [[ -n "$ONLY" ]]; then
  IFS=',' read -r -a ONLY_ARR <<< "$ONLY"
  SELECTED_TESTS=("${ONLY_ARR[@]}")
fi

log()   { echo -e "$*"; }
hr()    { printf '%*s\n' 60 '' | tr ' ' '='; }
warn()  { echo "WARN: $*" >&2; }
err()   { echo "ERROR: $*" >&2; }

# Results
compile_ok=0
missing_methods=()   # RPC not implemented ("method not found")
failed_calls=()      # RPC executed but failed
call_results=()      # JSON output snippets
declare -A per_test_status   # ok | missing | failed
declare -A per_test_detail   # short message

json_escape() {
  local s="$1"
  printf '%s' "$s" | python3 - <<'PY'
import json,sys
print(json.dumps(sys.stdin.read()))
PY
}

rpc_call_once() {
  local method="$1"
  local id="$2"
  local params='[{"mode":"max"}]'
  local payload
  payload=$(cat <<EOF
{"jsonrpc":"2.0","method":"${method}","params":${params},"id":${id}}
EOF
)
  curl --silent --show-error \
       --header 'Content-Type: application/json' \
       --data "${payload}" \
       --max-time "${TIMEOUT}" \
       "${ENDPOINT}"
}

rpc_try_both_names() {
  # Try dos_<id>, if fails then try dos.<id> (unless strict)
  local test_id="$1"
  local id="$2"
  local res method

  method="dos_${test_id}"
  res="$(rpc_call_once "${method}" "${id}")" || res=""
  if [[ -z "$res" ]] || grep -q '"method not found"' <<<"$res"; then
    if [[ "${USE_STRICT_METHODS}" -eq 0 ]]; then
      method="dos.${test_id}"
      res="$(rpc_call_once "${method}" "${id}")" || res=""
    fi
  fi
  echo -e "$method\n$res"
}

test_single_rpc() {
  local test_id="$1"
  local id="$2"
  local i=0
  local method res

  while :; do
    read -r method res < <(rpc_try_both_names "$test_id" "$id")
    if [[ -n "$res" ]]; then
      break
    fi
    i=$((i+1))
    if [[ $i -gt $RETRIES ]]; then
      break
    fi
    sleep "$SLEEP_BETWEEN"
  done

  if [[ -z "$res" ]]; then
    per_test_status["$test_id"]="failed"
    per_test_detail["$test_id"]="no response / timeout"
    failed_calls+=("$test_id: timeout")
    call_results+=("{\"test\":\"$test_id\",\"method\":\"$method\",\"ok\":false,\"error\":\"timeout\"}")
    return 1
  fi

  # method not found
  if grep -q '"code" *: *-32601' <<<"$res" || grep -q '"method not found"' <<<"$res"; then
    per_test_status["$test_id"]="missing"
    per_test_detail["$test_id"]="method not found (${method})"
    missing_methods+=("$test_id")
    call_results+=("{\"test\":\"$test_id\",\"method\":\"$method\",\"ok\":false,\"error\":\"method not found\"}")
    return 2
  fi

  # use jq if available
  if [[ -n "$JQ" ]]; then
    ok=$("$JQ" -r 'has("result")' <<<"$res" 2>/dev/null || echo "false")
    if [[ "$ok" == "true" ]]; then
      per_test_status["$test_id"]="ok"
      per_test_detail["$test_id"]="executed"
      mt=$("$JQ" -r '.result.msg_type // empty' <<<"$res" 2>/dev/null || true)
      ps=$("$JQ" -r '.result.packet_size // empty' <<<"$res" 2>/dev/null || true)
      call_results+=("{\"test\":\"$test_id\",\"method\":\"$method\",\"ok\":true,\"msg_type\":\"${mt}\",\"packet_size\":\"${ps}\",\"raw\":$(printf '%s' "$res" | ${JQ:-cat})}")
      return 0
    else
      per_test_status["$test_id"]="failed"
      errm=$("$JQ" -r '.error.message // empty' <<<"$res" 2>/dev/null || true)
      [[ -z "$errm" ]] && errm="rpc error"
      per_test_detail["$test_id"]="$errm"
      failed_calls+=("$test_id: $errm")
      call_results+=("{\"test\":\"$test_id\",\"method\":\"$method\",\"ok\":false,\"error\":$(json_escape "$errm"),\"raw\":$(json_escape "$res")}")
      return 3
    fi
  else
    # no jq — rough check
    if grep -q '"result"' <<<"$res"; then
      per_test_status["$test_id"]="ok"
      per_test_detail["$test_id"]="executed"
      call_results+=("{\"test\":\"$test_id\",\"method\":\"$method\",\"ok\":true}")
      return 0
    else
      per_test_status["$test_id"]="failed"
      per_test_detail["$test_id"]="rpc error (no jq)"
      failed_calls+=("$test_id: rpc error")
      call_results+=("{\"test\":\"$test_id\",\"method\":\"$method\",\"ok\":false,\"raw\":$(json_escape "$res")}")
      return 3
    fi
  fi
}

# ----------------------
# 1) Build stage
# ----------------------
hr
log "Step 1/3: build with make"
if make -C "$ROOT_DIR" -j"$(/usr/sbin/sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" ; then
  log " build success"
  compile_ok=1
else
  log "build failed"
  compile_ok=0
fi

# ----------------------
# 2) Coverage + 3) Executability
# ----------------------
hr
log "Step 2/3 & 3/3: coverage + executability via RPC"
log "Endpoint: ${ENDPOINT}   Timeout: ${TIMEOUT}s"
log "Selected tests: ${SELECTED_TESTS[*]}"

idx=1
for t in "${SELECTED_TESTS[@]}"; do
  log "→ [$idx/${#SELECTED_TESTS[@]}] ${t}"
  test_single_rpc "$t" "$idx" || true
  idx=$((idx+1))
done

# Summary
missing_count=${#missing_methods[@]}
failed_count=${#failed_calls[@]}
ok_count=0
for t in "${SELECTED_TESTS[@]}"; do
  [[ "${per_test_status[$t]:-missing}" == "ok" ]] && ok_count=$((ok_count+1))
done

hr
log "  Summary"
log "  Build:              $( [[ $compile_ok -eq 1 ]] && echo OK || echo FAILED )"
log "  Implemented+OK:     ${ok_count}"
log "  Missing methods:    ${missing_count}"
log "  Failed executions:  ${failed_count}"

# feedback text
hr
{
  echo "### DoS Test Feedback Report"
  echo ""
  echo "#### Build"
  echo "- status: $( [[ $compile_ok -eq 1 ]] && echo OK || echo FAILED )"
  echo ""
  echo "#### Coverage (missing methods)"
  if [[ $missing_count -eq 0 ]]; then
    echo "- all required RPC methods present"
  else
    for m in "${missing_methods[@]}"; do
      echo "- missing: ${m}"
    done
  fi
  echo ""
  echo "#### Executability (failed calls)"
  if [[ $failed_count -eq 0 ]]; then
    echo "- all RPC calls executed successfully"
  else
    for f in "${failed_calls[@]}"; do
      echo "- failed: ${f}"
    done
  fi
  echo ""
  echo "#### Notes for the agent"
  echo "- Ensure each RPC returns structured fields: { msg_type, packet_size, ok, details }"
  echo "- Each test should send a packet at exactly the protocol's max allowed size with valid payload."
  echo "- Provide robust error messages for boundary violations."
} > "${OUTPUT_TXT}"

# JSON
printf '{\n' > "${OUTPUT_JSON}"
printf '  "build_ok": %s,\n' "$( [[ $compile_ok -eq 1 ]] && echo true || echo false )" >> "${OUTPUT_JSON}"
printf '  "missing_methods": [' >> "${OUTPUT_JSON}"
for i in "${!missing_methods[@]}"; do
  printf '%s"%s"' $([[ $i -gt 0 ]] && echo ,) "${missing_methods[$i]}" >> "${OUTPUT_JSON}"
done
printf '],\n' >> "${OUTPUT_JSON}"
printf '  "failed_calls": [' >> "${OUTPUT_JSON}"
for i in "${!failed_calls[@]}"; do
  printf '%s"%s"' $([[ $i -gt 0 ]] && echo ,) "${failed_calls[$i]}" >> "${OUTPUT_JSON}"
done
printf '],\n' >> "${OUTPUT_JSON}"
printf '  "calls": [\n' >> "${OUTPUT_JSON}"
for i in "${!call_results[@]}"; do
  printf '    %s%s\n' "${call_results[$i]}" $([[ $i -lt $((${#call_results[@]}-1)) ]] && echo ,) >> "${OUTPUT_JSON}"
done
printf '  ]\n' >> "${OUTPUT_JSON}"
printf '}\n' >> "${OUTPUT_JSON}"

hr
log "  Feedback reports written:"
log "  - ${OUTPUT_TXT}"
log "  - ${OUTPUT_JSON}"

# Exit code: non-zero if any aspect failed
if [[ $compile_ok -eq 1 && $missing_count -eq 0 && $failed_count -eq 0 ]]; then
  exit 0
else
  exit 1
fi
