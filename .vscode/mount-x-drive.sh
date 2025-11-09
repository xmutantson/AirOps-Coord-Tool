#!/bin/bash
# Mount X: drive (\\192.168.69.1\HoneyPot) in WSL

echo "=== Mounting X: Network Drive in WSL ==="
echo ""

# Install cifs-utils if not present
if ! command -v mount.cifs &> /dev/null; then
    echo "Installing cifs-utils..."
    sudo apt-get update && sudo apt-get install -y cifs-utils
fi

# Create mount point
echo "Creating mount point /mnt/x..."
sudo mkdir -p /mnt/x

# Try mounting with guest access first
echo "Attempting to mount //192.168.69.1/HoneyPot..."
echo "(Using guest access - no password needed)"

sudo mount -t cifs //192.168.69.1/HoneyPot /mnt/x -o guest,uid=$(id -u),gid=$(id -g),file_mode=0777,dir_mode=0777

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Success! Network drive mounted at /mnt/x"
    echo ""
    echo "Verifying project access..."
    if [ -d "/mnt/x/Storage/Documents/air-ops-vscode/AirOps-Coord-Tool" ]; then
        echo "✓ Project directory is accessible!"
        echo ""
        echo "Project path: /mnt/x/Storage/Documents/air-ops-vscode/AirOps-Coord-Tool"
    else
        echo "Checking what's in /mnt/x..."
        ls -la /mnt/x | head -10
    fi
else
    echo ""
    echo "✗ Mount failed with guest access"
    echo ""
    echo "You may need to provide credentials:"
    read -p "Username (or press Enter to skip): " username
    if [ -n "$username" ]; then
        read -sp "Password: " password
        echo ""
        sudo mount -t cifs //192.168.69.1/HoneyPot /mnt/x -o username=$username,password=$password,uid=$(id -u),gid=$(id -g),file_mode=0777,dir_mode=0777
        if [ $? -eq 0 ]; then
            echo "✓ Mounted successfully with credentials"
        else
            echo "✗ Mount still failed. Check network connectivity:"
            echo "  ping 192.168.69.1"
        fi
    fi
fi

echo ""
echo "To make this permanent, add to /etc/fstab:"
echo "//192.168.69.1/HoneyPot /mnt/x cifs guest,uid=1000,gid=1000,file_mode=0777,dir_mode=0777 0 0"