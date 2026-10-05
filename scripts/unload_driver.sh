#!/usr/bin/env bash
# ==============================================================================
# unload_driver.sh - Removes virt_firewall kernel module and verifies cleanup
# ==============================================================================

set -e

MODULE_NAME="virt_firewall"
DEV_NODE="/dev/$MODULE_NAME"

echo "========================================================"
echo "    Unloading Virtual Text Firewall Kernel Module       "
echo "========================================================"

if ! lsmod | grep -q "^$MODULE_NAME "; then
    echo "[*] Module '$MODULE_NAME' is not currently loaded."
    exit 0
fi

echo "[*] Removing kernel module: $MODULE_NAME"
sudo rmmod "$MODULE_NAME"

# Wait briefly for udev cleanup
sleep 0.5

# Verify device node removal
if [ ! -e "$DEV_NODE" ]; then
    echo "[+] SUCCESS: Device node $DEV_NODE successfully removed."
else
    echo "[-] WARNING: Device node $DEV_NODE still persists! Check module cleanup."
    ls -l "$DEV_NODE"
fi

echo ""
echo "[*] Kernel unload log messages:"
sudo dmesg | grep -i "$MODULE_NAME" | tail -n 8 || true

echo "========================================================"
echo "[+] Virtual Text Firewall unloaded cleanly."
echo "========================================================"
