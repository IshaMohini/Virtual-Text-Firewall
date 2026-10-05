#!/usr/bin/env bash
# ==============================================================================
# load_driver.sh - Builds (if needed) and inserts virt_firewall kernel module
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DRIVER_DIR="$PROJECT_ROOT/driver"
MODULE_NAME="virt_firewall"
KO_FILE="$DRIVER_DIR/$MODULE_NAME.ko"
DEV_NODE="/dev/$MODULE_NAME"

echo "========================================================"
echo "    Loading Virtual Text Firewall Kernel Module         "
echo "========================================================"

# Check if already loaded
if lsmod | grep -q "^$MODULE_NAME "; then
    echo "[!] Module '$MODULE_NAME' is already loaded in kernel."
    echo "[*] Current device node status:"
    ls -l "$DEV_NODE" || true
    exit 0
fi

# Ensure .ko exists; build if missing
if [ ! -f "$KO_FILE" ]; then
    echo "[*] Kernel object not found. Compiling in $DRIVER_DIR..."
    make -C "$DRIVER_DIR"
fi

if [ ! -f "$KO_FILE" ]; then
    echo "[-] Error: Failed to produce $KO_FILE"
    exit 1
fi

echo "[*] Inserting kernel module: $KO_FILE"
sudo insmod "$KO_FILE"

# Wait briefly for udev to create device node
sleep 0.5

# Verify device creation
if [ -e "$DEV_NODE" ]; then
    echo "[+] SUCCESS: Device created at $DEV_NODE"
    sudo chmod 666 "$DEV_NODE"
    echo "[+] Permissions set: rw-rw-rw- on $DEV_NODE"
    ls -l "$DEV_NODE"
else
    echo "[-] WARNING: Device node $DEV_NODE was not automatically created by udev."
    echo "    Check dmesg output below for errors."
fi

echo ""
echo "[*] Recent kernel logs related to $MODULE_NAME:"
sudo dmesg | grep -i "$MODULE_NAME" | tail -n 10 || true

echo "========================================================"
echo "[+] Virtual Text Firewall is ready for use!"
echo "========================================================"
