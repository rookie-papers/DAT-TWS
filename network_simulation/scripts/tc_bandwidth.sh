#!/bin/bash
set -e

# ================= 0. Permission & Configuration Check =================
if [[ $EUID -ne 0 ]]; then
    echo "Error: Network configuration requires root privileges. Please run with sudo."
    exit 1
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONFIG_FILE="$SCRIPT_DIR/config.env"

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "Error: Configuration file not found at $CONFIG_FILE"
    exit 1
fi

# ================= 1. Parameter Validation =================
if [[ -z "$NUM_ISSUERS" ]]; then echo "Error: NUM_ISSUERS is undefined."; exit 1; fi
if [[ -z "$NET_BANDWIDTH" ]]; then echo "Error: NET_BANDWIDTH is undefined."; exit 1; fi

# Fallback defaults if not set in config
NET_BURST=${NET_BURST:-"32kbit"}
NET_LATENCY=${NET_LATENCY:-"400ms"}

echo "[Config] Loaded config file: $CONFIG_FILE"
echo "[Config] Bandwidth Limit: $NET_BANDWIDTH (Burst: $NET_BURST, Latency: $NET_LATENCY)"

# ================= 2. Define Helper Function =================
function clean_tc() {
    ip netns exec $1 tc qdisc del dev $2 root 2>/dev/null || true
}

echo "[*] Configuring Scenario 2: Bandwidth Limitation..."
echo " -> Cleaning existing rules to prevent latency/loss rule collisions..."

# ================= 3. Configure Issuer Nodes =================
for i in $(seq 1 $NUM_ISSUERS); do
    NS_NAME="Issuer$i"
    DEV_NAME="veth-iss$i-ns"

    clean_tc $NS_NAME $DEV_NAME
    ip netns exec $NS_NAME tc qdisc add dev $DEV_NAME root tbf \
        rate "$NET_BANDWIDTH" \
        burst "$NET_BURST" \
        latency "$NET_LATENCY"
done
echo " -> Bandwidth limited for $NUM_ISSUERS Issuer nodes."

# ================= 4. Configure Verifier Node =================
clean_tc "Verifier" "veth-vf-ns"
echo " -> Setting Verifier bandwidth limit: $NET_BANDWIDTH"
ip netns exec Verifier tc qdisc add dev veth-vf-ns root tbf \
    rate "$NET_BANDWIDTH" \
    burst "$NET_BURST" \
    latency "$NET_LATENCY"

echo "[SUCCESS] Scenario 2 (Bandwidth Limit) Configuration Complete."