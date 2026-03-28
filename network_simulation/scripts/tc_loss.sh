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
if [[ -z "$NET_LOSS" ]]; then echo "Error: NET_LOSS is undefined."; exit 1; fi

echo "[Config] Target Nodes: $NUM_ISSUERS Issuers + 1 Verifier"
echo "[Config] Packet Loss Settings: $NET_LOSS"

# ================= 2. Define Helper Function =================
function clean_tc() {
    ip netns exec $1 tc qdisc del dev $2 root 2>/dev/null || true
}

echo "[*] Configuring Scenario 3: Packet Loss Simulation [Loss: $NET_LOSS]..."

# ================= 3. Configure Issuer Nodes =================
for i in $(seq 1 $NUM_ISSUERS); do
    NS_NAME="Issuer$i"
    DEV_NAME="veth-iss$i-ns"

    clean_tc $NS_NAME $DEV_NAME
    ip netns exec $NS_NAME tc qdisc add dev $DEV_NAME root netem loss "$NET_LOSS"
done
echo " -> Packet loss rate set for $NUM_ISSUERS Issuer nodes."

# ================= 4. Configure Verifier Node =================
clean_tc "Verifier" "veth-vf-ns"
echo " -> Setting Verifier packet loss: $NET_LOSS"
ip netns exec Verifier tc qdisc add dev veth-vf-ns root netem loss "$NET_LOSS"

echo "[SUCCESS] Scenario 3 (Packet Loss) Configuration Complete."