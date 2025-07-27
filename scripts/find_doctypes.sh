#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-.}"

# File patterns to scan
INCLUDES=(
  --include='*.html' --include='*.htm'
  --include='*.jinja' --include='*.jinja2' --include='*.j2' --include='*.tpl'
)

# Dirs to skip
EXCLUDES=(
  --exclude-dir='.git' --exclude-dir='__pycache__'
  --exclude-dir='node_modules' --exclude-dir='dist' --exclude-dir='build'
  --exclude-dir='venv' --exclude-dir='.venv'
)

# -R recursive, -I skip binary, -n line numbers, -E extended regex
grep -RIn "${INCLUDES[@]}" "${EXCLUDES[@]}" -E '<!DOCTYPE[[:space:]]' "$ROOT" || true
