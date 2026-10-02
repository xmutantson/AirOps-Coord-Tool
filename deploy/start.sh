#!/bin/bash
set -euo pipefail

# Boot must work without an internet connection. Fetch a new image only when
# an operator explicitly requests an update (also required for first install).
if [ "$#" -gt 1 ]; then
  echo "Usage: $0 [--update]" >&2
  exit 2
fi
case "${1:-}" in
  "") update=0 ;;
  --update) update=1 ;;
  *) echo "Usage: $0 [--update]" >&2; exit 2 ;;
esac

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
OVR=docker-compose.override.yml
tmp=$(mktemp "${OVR}.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT

devices=()
for device in /dev/bus/usb /dev/snd /dev/digrig-ptt; do
  if [ -e "$device" ]; then
    devices+=("$device")
    echo "Found $device"
  else
    echo "Optional device unavailable: $device"
  fi
done
{
  printf 'services:\n  aircraft_ops_tool:\n'
  if [ "${#devices[@]}" -eq 0 ]; then
    printf '    devices: []\n'
  else
    printf '    devices:\n'
    for device in "${devices[@]}"; do
      printf '      - %s:%s\n' "$device" "$device"
    done
  fi
} > "$tmp"
mv -- "$tmp" "$OVR"

compose=(docker compose -f docker-compose.yml -f "$OVR")
"${compose[@]}" config --quiet
if [ "$update" -eq 1 ]; then
  echo "Fetching configured image; a failed pull leaves the running service unchanged."
  "${compose[@]}" pull
fi
echo "Starting the locally cached image (no pull or build)."
"${compose[@]}" up -d --pull never --no-build
"${compose[@]}" images aircraft_ops_tool
echo "Check the flight board and integrations before operational use."
