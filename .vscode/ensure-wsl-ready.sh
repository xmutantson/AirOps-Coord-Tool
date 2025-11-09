#!/bin/bash
# Helper script to ensure WSL environment is ready

# Ensure /mnt/x is mounted
if ! mount | grep -q "/mnt/x"; then
  echo "Mounting X: drive to /mnt/x..."
  sudo mkdir -p /mnt/x
  sudo mount -t drvfs 'X:' /mnt/x
fi

# Ensure Docker daemon is running
if ! docker info >/dev/null 2>&1; then
  echo "Starting Docker daemon..."
  sudo service docker start
  sleep 2
fi
