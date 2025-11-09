#!/bin/bash

# Ensure WSL environment is ready (mount + Docker)
source "$(dirname "$0")/ensure-wsl-ready.sh"

echo "=== Docker Version ==="
docker --version
echo ""
echo "=== Docker Buildx ==="
docker buildx version
echo ""
echo "=== Buildx Builders ==="
docker buildx ls
echo ""
echo "=== Local Images ==="
docker images | grep -E "REPOSITORY|aircraft_ops_tool|ghcr.io/xmutantson" | head -20
echo ""
echo "=== Disk Usage ==="
docker system df