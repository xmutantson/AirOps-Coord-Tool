#!/usr/bin/env bash
# prepare_digirig_host.sh
# Prepare a Linux host (Debian/Raspbian/Ubuntu) for DigiRig Lite:
# - Installs minimal tools
# - Creates udev rule for stable PTT symlink /dev/digrig-ptt (CM108 HID)
# - Ensures user is in 'audio' group
# - Prints stable ALSA device names to use in Docker/containers

set -euo pipefail

readonly UDEV_RULE="/etc/udev/rules.d/99-digirig-ptt.rules"
readonly HID_VENDOR="0d8c"
readonly HID_PRODUCT="0012"
readonly PTT_SYMLINK="/dev/digrig-ptt"
readonly USERNAME="${SUDO_USER:-${USER:-$(id -un)}}"

echo "[*] Installing minimal tools (udev rules rely on them existing anyway)…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -qq
apt-get install -y -qq --no-install-recommends \
  usbutils alsa-utils udev >/dev/null

echo "[*] Writing udev rule to ${UDEV_RULE}"
cat <<'RULE' >/tmp/99-digirig-ptt.rules
# DigiRig Lite (CM108/CM108B) HID-based PTT -> stable symlink
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="0d8c", ATTRS{idProduct}=="0012", \
  SYMLINK+="digrig-ptt", MODE="0660", GROUP="audio"
RULE
# Only update if changed (keeps mtime/logs cleaner)
if ! cmp -s /tmp/99-digirig-ptt.rules "${UDEV_RULE}" 2>/dev/null; then
  install -m 0644 -o root -g root /tmp/99-digirig-ptt.rules "${UDEV_RULE}"
else
  echo "    (rule unchanged)"
fi
rm -f /tmp/99-digirig-ptt.rules

echo "[*] Reloading udev rules…"
udevadm control --reload-rules

echo "[*] Triggering udev for CM108 devices…"
# Trigger only matching devices; then wait for processing to complete.
udevadm trigger --attr-match=idVendor="${HID_VENDOR}" --attr-match=idProduct="${HID_PRODUCT}" || true
udevadm settle || true

# Give the kernel/udev a moment to publish links (handles slower Pis/USB hubs)
sleep 2

echo "[*] Ensuring user '${USERNAME}' is in 'audio' group…"
if id -nG "${USERNAME}" | tr ' ' '\n' | grep -qx "audio"; then
  echo "    User '${USERNAME}' already in 'audio' group."
else
  usermod -aG audio "${USERNAME}"
  echo "    Added '${USERNAME}' to 'audio'. Log out/in (or reboot) to pick up membership."
fi

echo
echo "[*] USB snapshot (looking for C-Media ${HID_VENDOR}:${HID_PRODUCT}):"
lsusb | grep -i "${HID_VENDOR}:${HID_PRODUCT}" || echo "    (not present right now)"

echo
echo "[*] ALSA cards:"
if [ -r /proc/asound/cards ]; then
  cat /proc/asound/cards
else
  echo "    /proc/asound/cards not available."
fi

echo
echo "[*] ALSA playback/capture lists:"
aplay -l || true
arecord -l || true

echo
echo "[*] Stable ALSA names to use (look for CARD=Device):"
# These names are stable across reboots for the USB audio dongle.
# We'll print both playback and capture lists with the long names.
aplay -L 2>/dev/null | nl -ba | sed -n '1,200p' || true
arecord -L 2>/dev/null | nl -ba | sed -n '1,80p' || true

echo
echo "[*] PTT symlink (should exist if device is plugged):"
if [ -e "${PTT_SYMLINK}" ]; then
  ls -l "${PTT_SYMLINK}"
  echo "    ✅ ${PTT_SYMLINK} is present."
else
  echo "    ❌ ${PTT_SYMLINK} not found."
  echo "       Trying a focused re-trigger and settle…"
  udevadm trigger --attr-match=idVendor="${HID_VENDOR}" --attr-match=idProduct="${HID_PRODUCT}" || true
  udevadm settle || true
  sleep 2
  if [ -e "${PTT_SYMLINK}" ]; then
    ls -l "${PTT_SYMLINK}"
    echo "    ✅ ${PTT_SYMLINK} is present after re-trigger."
  else
    echo "    ⚠ Still missing. If the DigiRig is plugged in, try unplug/replug:"
    echo "       sudo udevadm control --reload-rules && sudo udevadm trigger"
  fi
fi

echo
echo "[*] /dev/snd nodes:"
ls -l /dev/snd || true

echo
echo "✔ Host is prepared."

cat <<'NEXT'

Use these in Docker (compose example):

  services:
    your_app:
      # … image/build/etc …
      devices:
        - /dev/snd
        - /dev/digrig-ptt:/dev/digrig-ptt
      group_add:
        - audio
      environment:
        AX25_RX_DEVICE=plughw:CARD=Device,DEV=0
        AX25_TX_DEVICE=plughw:CARD=Device,DEV=0
        DIGIRIG_PTT=/dev/digrig-ptt
        DIGIRIG_ENABLE=1

Notes:
- /dev/digrig-ptt symlink is created by the udev rule and is stable for CM108 PTT.
- The ALSA device names printed above (e.g., plughw:CARD=Device,DEV=0) are stable across reboots.
- If you were just added to the 'audio' group, log out and back in (or reboot)
  before starting Docker so your shell picks up the new membership.

NEXT
