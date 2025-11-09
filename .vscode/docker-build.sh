#!/bin/bash

# Ensure WSL environment is ready (mount + Docker)
source "$(dirname "$0")/ensure-wsl-ready.sh"

cd "$(dirname "$0")/.." || exit 1

export TAG="v$(date +%Y.%m.%d)"
export GHCR_USER="xmutantson"

echo "Building multi-platform image..."
echo "Tags: latest, $TAG"
echo ""

docker buildx build \
  --platform "linux/amd64,linux/386,linux/arm/v7,linux/arm64" \
  --cache-from=type=registry,ref=ghcr.io/$GHCR_USER/aircraft_ops_tool:buildcache \
  --cache-to=type=registry,ref=ghcr.io/$GHCR_USER/aircraft_ops_tool:buildcache,mode=max \
  -t ghcr.io/$GHCR_USER/aircraft_ops_tool:latest \
  -t ghcr.io/$GHCR_USER/aircraft_ops_tool:$TAG \
  --push \
  .

if [ $? -eq 0 ]; then
  echo ""
  echo "SUCCESS! Images pushed to GHCR:"
  echo "  - ghcr.io/$GHCR_USER/aircraft_ops_tool:latest"
  echo "  - ghcr.io/$GHCR_USER/aircraft_ops_tool:$TAG"
else
  echo ""
  echo "Build failed!"
  exit 1
fi