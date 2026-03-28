#!/bin/bash

# ================= 1. Load Configuration =================
# Locate the directory where the script resides
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONFIG_FILE="$SCRIPT_DIR/config.env"

# Source the configuration file
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
    echo "[Config] Loaded configuration from: $CONFIG_FILE"
else
    echo "Error: Configuration file not found at $CONFIG_FILE"
    exit 1
fi

# Validate mandatory parameters
if [[ -z "$NUM_ISSUERS" ]]; then
    echo "Error: 'NUM_ISSUERS' is undefined in the configuration file."
    exit 1
fi

# Set default base port if not provided in the configuration
BASE_PORT=${BASE_PORT:-8001}

# ================= 2. Startup Logic =================
echo "[*] Starting $NUM_ISSUERS Issuer nodes (Base Port: $BASE_PORT)..."

# Create a logs directory to store background process logs
mkdir -p logs

for ((i=1; i<=NUM_ISSUERS; i++)); do
    # Calculate the port for the current Issuer
    PORT=$BASE_PORT

    # Define the corresponding network namespace name
    NS_NAME="Issuer$i"

    echo " -> Starting $NS_NAME (IP: 10.0.0.$((100+i))) on port $PORT ..."

    # Execute the issuer node inside its dedicated network namespace
    # Redirect stdout and stderr to a dedicated log file
    sudo ip netns exec $NS_NAME ./issuer $PORT > logs/issuer_${i}.log 2>&1 &

    # Brief pause to prevent overwhelming the Regulator with concurrent connections
    sleep 0.1
done

echo ""
echo "[SUCCESS] All $NUM_ISSUERS Issuers started in the background."
echo "[INFO] You can check their status in the 'logs/' directory."