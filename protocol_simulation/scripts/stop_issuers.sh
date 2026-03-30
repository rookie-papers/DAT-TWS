#!/bin/bash

echo "[*] Terminating all DAT-TWS Issuer processes..."

# Use 'killall' to kill processes by name safely
# -q: Quiet mode (don't complain if no process is found)
# -9: Force kill
killall -9 -q issuer

# If you also run the Regulator on this machine and want to kill it too, uncomment below:
killall -9 -q regulator

echo " -> Waiting for ports to release..."
sleep 1

# Check if any processes remain
# grep -v grep: Excludes the grep search itself from results
COUNT=$(ps -ef | grep -E "issuer" | grep -v grep | wc -l)

if [ $COUNT -eq 0 ]; then
    echo "[SUCCESS] All Issuer processes cleaned up. Ports successfully released."
else
    echo "[WARNING] $COUNT processes remaining. Check manually using: ps -ef | grep issuer"
fi