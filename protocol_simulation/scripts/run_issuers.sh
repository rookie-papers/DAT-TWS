#!/bin/bash

# ================= 1. Parse Command-Line Arguments =================
# Check if at least one argument (NUM_ISSUERS) is provided
if [ -z "$1" ]; then
    echo "Error: Missing required argument."
    echo "Usage: $0 <NUM_ISSUERS> [BASE_PORT]"
    echo "Example 1: $0 5        (Starts 5 Issuers, defaulting to base port 8001)"
    echo "Example 2: $0 10 9000  (Starts 10 Issuers, starting from port 9000)"
    exit 1
fi

NUM_ISSUERS=$1
# Use the second argument as BASE_PORT if provided, otherwise default to 8001
BASE_PORT=${2:-8001}

# ================= 2. Startup Logic =================
echo "[*] Starting $NUM_ISSUERS Issuer nodes (Base Port: $BASE_PORT)..."

# Note: This script assumes it is executed from the build/protocol_simulation directory.
# Create a logs directory to store background process logs
mkdir -p logs

for ((i=0; i<NUM_ISSUERS; i++)); do
    PORT=$((BASE_PORT + i))
    echo " -> Starting Issuer $i on port $PORT ..."

    # Run the issuer in the background, redirecting stdout and stderr to a dedicated log file
    ./issuer $PORT > logs/issuer_$PORT.log 2>&1 &

    # Brief pause to prevent overwhelming the Regulator with concurrent connections
    sleep 0.1
done

echo ""
echo "[SUCCESS] All $NUM_ISSUERS Issuers started in the background."
echo "[INFO] You can check their status in the 'logs/' directory."