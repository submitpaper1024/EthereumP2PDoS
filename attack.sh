#!/usr/bin/env bash
# newshell.sh
# Usage:
#   ./newshell.sh <function> <start_offset> [end_offset]
# Example:
#   ./newshell.sh pingDoS 1 15   -> runs ./eth_dos.sh pingDoS 10501 ... 10515
#   ./newshell.sh newPooledTransactionHashesDoS 1 -> runs ./eth_dos.sh newPooledTransactionHashesDoS 10501

set -u

usage() {
  cat <<EOF
Usage: $0 <function> <start_offset> [end_offset]
  <function>      Function name to execute (e.g. pingDoS or newPooledTransactionHashesDoS)
  <start_offset>  Starting offset (number). 1 corresponds to port 10501
  [end_offset]    Optional ending offset (number). If omitted, only the port for start_offset will be executed
Example:
  $0 pingDoS 1 15
EOF
  exit 1
}

# Parameter check
if [ $# -lt 2 ] || [ $# -gt 3 ]; then
  usage
fi

FUNC="$1"
START="$2"
END="$3"

# If the third argument is not provided, set END to START
if [ $# -eq 2 ]; then
  END="$START"
fi

# Validate numbers
re='^[0-9]+$'
if ! [[ $START =~ $re ]] || ! [[ $END =~ $re ]]; then
  echo "Error: start_offset and end_offset must be positive integers."
  usage
fi

# Convert to integers and check ordering
START_N=$((START))
END_N=$((END))

if [ "$START_N" -gt "$END_N" ]; then
  echo "Error: start_offset ($START_N) cannot be greater than end_offset ($END_N)."
  exit 1
fi

# Check whether eth_dos script exists and is executable
ETH_SCRIPT="./eth_dos.sh"
if [ ! -f "$ETH_SCRIPT" ]; then
  echo "Warning: $ETH_SCRIPT not found. Please make sure it is present in the current directory."
fi
if [ ! -x "$ETH_SCRIPT" ]; then
  echo "Note: $ETH_SCRIPT is not executable (or lacks execute permission). If it exists, you can run: chmod +x $ETH_SCRIPT"
fi

BASE=10500

# Loop and execute
for (( i=START_N; i<=END_N; i++ )); do
  port=$((BASE + i))
  cmd="$ETH_SCRIPT $FUNC $port"
  echo "Executing: $cmd"
  if [ -x "$ETH_SCRIPT" ]; then
    # If eth_dos.sh is executable, run it and capture exit code; on error continue to next
    if ! $ETH_SCRIPT "$FUNC" "$port"; then
      rc=$?
      echo "⚠️ Command failed: $cmd (exit code $rc), continuing to next..."
    fi
  else
    # If eth_dos.sh is not executable / missing, only print the command (useful for debugging)
    echo "(Not executed — $ETH_SCRIPT is not executable or not found)"
  fi
done