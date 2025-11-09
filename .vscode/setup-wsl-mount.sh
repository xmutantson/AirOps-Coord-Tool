#!/bin/bash
# This script configures WSL to access your X: drive

echo "=== WSL X: Drive Mount Setup ==="
echo ""
echo "Checking current mount status..."
mount | grep /mnt/x

echo ""
echo "This will mount your X: drive in WSL"
echo "We need to know the actual path of X:"
echo ""
echo "In Windows PowerShell, run: net use X:"
echo "This will show you the network path (like \\\\server\\share)"
echo ""
read -p "Enter the network path for X: (e.g., //server/share): " NET_PATH

if [ -z "$NET_PATH" ]; then
    echo "Error: No path provided"
    exit 1
fi

echo ""
echo "Creating mount point..."
sudo mkdir -p /mnt/x

echo "Mounting $NET_PATH to /mnt/x..."
sudo mount -t drvfs "$NET_PATH" /mnt/x

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Success! X: drive is now accessible at /mnt/x"
    echo ""
    echo "Testing access..."
    ls /mnt/x/Storage/Documents/air-ops-vscode/AirOps-Coord-Tool
    echo ""
    echo "To make this permanent, add this to /etc/fstab:"
    echo "$NET_PATH /mnt/x drvfs defaults 0 0"
else
    echo ""
    echo "✗ Mount failed. Your X: drive might be a physical drive."
    echo "If X: is a physical/internal drive, WSL should auto-mount it."
    echo "Check if /mnt/x exists and has your files."
fi
