#!/bin/bash
set -e

# ================= 0. Permission & Configuration Check =================
if [[ $EUID -ne 0 ]]; then
    echo "Error: Network configuration requires root privileges. Please run with sudo."
    exit 1
fi

# Load configuration file
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
if [[ -z "$NET_DELAY" ]]; then echo "Error: NET_DELAY is undefined."; exit 1; fi

NET_JITTER=${NET_JITTER:-"0ms"}

echo "[Config] Loaded config file: $CONFIG_FILE"
echo "[Config] Target Nodes: $NUM_ISSUERS Issuers + 1 Verifier"
echo "[Config] Delay Settings: $NET_DELAY (Jitter: $NET_JITTER)"

# ================= 2. Define Helper Function =================
# Removes existing traffic control rules to prevent conflicts
function clean_tc() {
    ip netns exec $1 tc qdisc del dev $2 root 2>/dev/null || true
}

echo "[*] Configuring Scenario 1: High Latency [Delay: $NET_DELAY, Jitter: $NET_JITTER]..."

# ================= 3. Configure Issuer Nodes =================
for i in $(seq 1 $NUM_ISSUERS); do
    NS_NAME="Issuer$i"
    DEV_NAME="veth-iss$i-ns"

    clean_tc $NS_NAME $DEV_NAME
    ip netns exec $NS_NAME tc qdisc add dev $DEV_NAME root netem delay "$NET_DELAY" "$NET_JITTER"
done
echo " -> Completed delay setup for $NUM_ISSUERS Issuer nodes."

# ================= 4. Configure Verifier Node =================
clean_tc "Verifier" "veth-vf-ns"
echo " -> Setting Verifier delay ($NET_DELAY ± $NET_JITTER)"
ip netns exec Verifier tc qdisc add dev veth-vf-ns root netem delay "$NET_DELAY" "$NET_JITTER"

echo "[SUCCESS] Scenario 1 (High Latency) Configuration Complete."