#!/bin/bash

echo "[*] 1. Terminating DAT-TWS simulation processes..."
# Kill any running instances of our protocol binaries
sudo pkill -9 -x regulator 2>/dev/null || true
sudo pkill -9 -x issuer 2>/dev/null || true
sudo pkill -9 -x verifier 2>/dev/null || true
sudo pkill -9 -x user 2>/dev/null || true
sleep 1

echo "[*] 2. Cleaning Network Namespaces..."
# Attempt to delete all network namespaces silently
sudo ip -all netns delete >/dev/null 2>&1 || true

# Fallback cleanup: parse list and delete one by one
sudo ip netns list | awk '{print $1}' | xargs -r -n1 sudo ip netns delete >/dev/null 2>&1 || true

echo "[*] 3. Cleaning virtual bridge and veth interfaces..."
# Assuming our bridge is named 'br-dattws' (to be created in build_net.sh)
sudo ip link delete br-dattws >/dev/null 2>&1 || true

# Find all veth interfaces on the host and delete them
ip link show | grep veth | awk -F': ' '{print $2}' | cut -d'@' -f1 | \
xargs -r -n1 sudo ip link delete >/dev/null 2>&1 || true

echo "[SUCCESS] Environment cleanup complete. The system is clean."