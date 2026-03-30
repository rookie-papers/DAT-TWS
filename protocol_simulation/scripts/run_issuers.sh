#!/bin/bash

# ================= 1. Load Configuration =================
# Get the script directory to ensure config.env can be found
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONFIG_FILE="$SCRIPT_DIR/config.env"

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
    echo "[Config] Loaded config file: $CONFIG_FILE"
else
    echo "Error: Config file not found: $CONFIG_FILE"
    exit 1
fi

# ================= 2. Check Configuration Items =================
# If NUM_ISSUERS is undefined or empty, exit with error immediately
if [[ -z "$NUM_ISSUERS" ]]; then
    echo "Error: 'NUM_ISSUERS' is undefined in the config file."
    exit 1
fi

# ================= 3. Startup Logic =================
BASE_PORT=8001
mkdir -p logs

echo "[*] Starting $NUM_ISSUERS Issuer nodes on Real Host (Base Port: $BASE_PORT)..."

for ((i=0; i<NUM_ISSUERS; i++)); do
    PORT=$((BASE_PORT + i))
    echo " -> Starting Issuer $i on port $PORT ..."

    # Run in background and redirect output to a specific log file
    # Assuming the executable 'issuer' is in the parent directory of 'scripts'
    ./issuer $PORT > logs/issuer_$PORT.log 2>&1 &

    # Slight delay to prevent connection flood to Regulator
    sleep 0.05
done

echo "================================================================"
echo "[SUCCESS] All $NUM_ISSUERS Issuers started in the background."
echo "[INFO] Check 'logs/' directory for individual node outputs."
echo "================================================================"