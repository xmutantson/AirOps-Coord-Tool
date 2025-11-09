#!/bin/bash

# Ensure WSL environment is ready (mount + Docker)
source "$(dirname "$0")/ensure-wsl-ready.sh"

cd "$(dirname "$0")/.." || exit 1

export TAG="v$(date +%Y.%m.%d)"

echo "Building for local platform only..."
echo ""

docker build \
  -t aircraft_ops_tool:latest \
  -t aircraft_ops_tool:$TAG \
  .

if [ $? -eq 0 ]; then
  echo ""
  echo "Local build complete!"
  echo "  - aircraft_ops_tool:latest"
  echo "  - aircraft_ops_tool:$TAG"
else
  echo ""
  echo "Build failed!"
  exit 1
fi