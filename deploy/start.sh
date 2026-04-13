#!/bin/bash
cd /home/pi/docker/aoct
OVR=docker-compose.override.yml
printf "services:\n  aircraft_ops_tool:\n    devices:\n      - /dev/bus/usb:/dev/bus/usb\n" > "$OVR"
if [ -e /dev/snd ]; then
  echo "      - /dev/snd" >> "$OVR"
  echo "Found /dev/snd"
else
  echo "WARNING: /dev/snd not found"
fi
if [ -e /dev/digrig-ptt ]; then
  echo "      - /dev/digrig-ptt:/dev/digrig-ptt" >> "$OVR"
  echo "Found /dev/digrig-ptt"
else
  echo "WARNING: /dev/digrig-ptt not found"
fi
docker compose pull
docker compose up -d
