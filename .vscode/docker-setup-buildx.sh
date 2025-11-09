#!/bin/bash

# Ensure WSL environment is ready (mount + Docker)
source "$(dirname "$0")/ensure-wsl-ready.sh"

echo "Setting up Docker Buildx..."
echo ""

# Remove existing builder if it exists
docker buildx rm multiplatform 2>/dev/null || true

# Create new builder
docker buildx create --use --name multiplatform --driver docker-container --bootstrap

if [ $? -eq 0 ]; then
  echo ""
  echo "Buildx configured!"
  echo ""
  echo "Available builders:"
  docker buildx ls
  echo ""
  echo "Ready for multi-platform builds!"
else
  echo ""
  echo "Setup failed!"
  exit 1
fi