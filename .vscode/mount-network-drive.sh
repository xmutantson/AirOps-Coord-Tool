#!/bin/bash
# Mount Windows network drive in WSL

echo "=== Mounting Network Drive in WSL ==="
echo ""

# Create mount point
sudo mkdir -p /mnt/x

# Mount the network share
# Windows format: \\192.168.69.1\HoneyPot
# WSL format: //192.168.69.1/HoneyPot
echo "Mounting //192.168.69.1/HoneyPot to /mnt/x..."
sudo mount -t drvfs '\\192.168.69.1\HoneyPot' /mnt/x

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Success! Network drive mounted"
    echo ""
    echo "Verifying access to project..."
    if [ -d "/mnt/x/Storage/Documents/air-ops-vscode/AirOps-Coord-Tool" ]; then
        echo "✓ Project directory accessible!"
        ls -la /mnt/x/Storage/Documents/air-ops-vscode/AirOps-Coord-Tool | head -10
    else
        echo "✗ Project directory not found at expected path"
        echo "Listing /mnt/x contents:"
        ls -la /mnt/x
    fi
else
    echo ""
    echo "✗ Mount failed"
    echo ""
    echo "Troubleshooting:"
    echo "1. Make sure you have network access to 192.168.69.1"
    echo "2. Try running: ping 192.168.69.1"
    echo "3. You may need to provide credentials"
fi

echo ""
echo "To make this mount permanent, add to /etc/fstab:"
echo "\\\\192.168.69.1\\HoneyPot /mnt/x drvfs defaults 0 0"