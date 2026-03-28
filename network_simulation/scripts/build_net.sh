#!/bin/bash
set -e

# ==============================================================================
# 0. Permission & Configuration Check
# ==============================================================================
if [[ $EUID -ne 0 ]]; then
    echo "Error: Network construction requires root privileges. Please run with sudo."
    exit 1
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONFIG_FILE="$SCRIPT_DIR/config.env"

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
    echo "[Config] Loaded configuration from: $CONFIG_FILE"
else
    echo "Error: Configuration file not found at $CONFIG_FILE"
    exit 1
fi

if [[ -z "$NUM_ISSUERS" ]]; then
    echo "Error: NUM_ISSUERS is undefined in the config file."
    exit 1
fi

# ==============================================================================
# 1. Cleanup Old Environment
# ==============================================================================
echo "[*] Cleaning up old network environment..."
# Force cleanup: Delete namespaces, residual veths, and bridges. Ignore errors if they don't exist.
ip netns list | awk '{print $1}' | xargs -r -n1 ip netns delete >/dev/null 2>&1 || true
ip link show | grep veth | awk -F': ' '{print $2}' | cut -d'@' -f1 | xargs -r -n1 ip link delete >/dev/null 2>&1 || true
ip link delete br-dattws >/dev/null 2>&1 || true

echo "[*] Cleanup finished. Starting network construction..."

# ==============================================================================
# 2. Core Settings & Infrastructure (Linux Bridge)
# ==============================================================================
echo "[+] Enabling Kernel IP Forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# Define the central subnet for the DAT-TWS virtual network
SUBNET="10.0.0"

echo "[+] Building Central Virtual Bridge (br-dattws)..."
ip link add name br-dattws type bridge
ip addr add ${SUBNET}.1/24 dev br-dattws
ip link set br-dattws up

# ==============================================================================
# 3. Build Core Nodes (Regulator, Verifier, User)
# ==============================================================================
function create_node() {
    local NS_NAME=$1
    local VETH_HOST="veth-${2}"
    local VETH_NS="veth-${2}-ns"
    local IP_ADDR=$3

    echo " -> Attaching $NS_NAME (IP: $IP_ADDR)..."
    ip netns add $NS_NAME
    ip link add $VETH_HOST type veth peer name $VETH_NS

    # Attach host end to the bridge
    ip link set $VETH_HOST master br-dattws
    ip link set $VETH_HOST up

    # Move namespace end to the isolated namespace
    ip link set $VETH_NS netns $NS_NAME
    ip netns exec $NS_NAME ip addr add ${IP_ADDR}/24 dev $VETH_NS
    ip netns exec $NS_NAME ip link set $VETH_NS up
    ip netns exec $NS_NAME ip link set lo up

    # Set default route via the bridge
    ip netns exec $NS_NAME ip route add default via ${SUBNET}.1
}

echo "[+] Building Core Protocol Entities..."
create_node "Regulator" "reg" "${SUBNET}.10"
create_node "Verifier"  "vf"  "${SUBNET}.20"
create_node "User"      "usr" "${SUBNET}.30"

# ==============================================================================
# 4. Build Issuer Cluster
# ==============================================================================
echo "[+] Building Issuer Cluster ($NUM_ISSUERS nodes)..."

for ((i=1; i<=NUM_ISSUERS; i++)); do
    # IP assignments start from 10.0.0.101, 10.0.0.102, etc.
    IP_ADDR="${SUBNET}.$((100+i))"
    create_node "Issuer$i" "iss$i" "$IP_ADDR"
done

# ==============================================================================
# 5. Completion Report & Instructions
# ==============================================================================
echo ""
echo "============================================================"
echo "    DAT-TWS Network Simulation Build Complete"
echo "============================================================"
echo " [Topology IP Map]"
echo "  - Regulator : 10.0.0.10"
echo "  - Verifier  : 10.0.0.20"
echo "  - User      : 10.0.0.30"
echo "  - Issuers   : 10.0.0.101 to 10.0.0.$((100+NUM_ISSUERS))"
echo ""
echo " [Experiment Launch Steps]"
echo "  1. Apply Network Limits : sudo ./tc_latency.sh (or bandwidth/loss)"
echo "  2. Start Regulator    : sudo ip netns exec Regulator ./regulator"
echo "  3. Start Verifier     : sudo ip netns exec Verifier ./verifier"
echo "  4. Start Issuers      : sudo ./run_issuers.sh"
echo "  5. Start User         : sudo ip netns exec User ./user <num_issuers>"
echo "============================================================"