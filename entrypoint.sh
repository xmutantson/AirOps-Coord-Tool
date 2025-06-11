#!/usr/bin/env bash
set -e

SECRET_PATH=/run/secrets/flask_secret

# If the volume is empty, generate a new secret
if [ ! -f "$SECRET_PATH" ]; then
  echo "Generating new Flask secret…"
  mkdir -p "$(dirname "$SECRET_PATH")"
  # 32 bytes → 64 hex chars
  openssl rand -hex 32 > "$SECRET_PATH"
  chmod 600 "$SECRET_PATH"
fi

# Finally exec the app
exec waitress-serve --port=5150 app:app
