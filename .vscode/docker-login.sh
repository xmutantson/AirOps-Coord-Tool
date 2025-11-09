#!/bin/bash

# Ensure WSL environment is ready (mount + Docker)
source "$(dirname "$0")/ensure-wsl-ready.sh"

echo "Logging in to GitHub Container Registry..."
echo "Username: xmutantson"
echo "Password: paste your GitHub Personal Access Token"
echo ""

docker login ghcr.io -u xmutantson

if [ $? -eq 0 ]; then
  echo ""
  echo "Login successful!"
else
  echo ""
  echo "Login failed!"
  exit 1
fi