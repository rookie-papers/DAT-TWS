#!/bin/bash

echo "[*] Stopping all Issuer processes..."

pkill -x issuer

if [ $? -eq 0 ]; then
    echo "[SUCCESS] All Issuer processes have been terminated."
else
    echo "[INFO] No running Issuer processes found."
fi