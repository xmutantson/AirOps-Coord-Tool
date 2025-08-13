#!/usr/bin/env bash
set -e

SECRET_PATH=/run/secrets/flask_secret
DW_CFG=/etc/direwolf.conf
DW_LOG=/var/log/direwolf.log

# 1) generate flask_secret if missing
if [ ! -f "$SECRET_PATH" ]; then
  echo "Generating new Flask secret…"
  mkdir -p "$(dirname "$SECRET_PATH")"
  openssl rand -hex 32 > "$SECRET_PATH"
  chmod 600 "$SECRET_PATH"
fi

# 2) auto‐detect the “real” LAN IP if not overridden
if [ -z "$HOST_LAN_IP" ] && [ -z "$HOST_LAN_IFACE" ]; then
  route_line=$(ip route show default | grep -vE 'dev (docker|br-|tun)' | head -n1 || true)
  iface=$(awk '/dev/ {for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}' <<<"$route_line")
  if [ -n "$iface" ]; then
    HOST_LAN_IP=$(ip -4 addr show dev "$iface" \
                  | grep -oP '(?<=inet\s)\d+(\.\d+){3}' \
                  | head -n1 || true)
    if [ -n "$HOST_LAN_IP" ]; then
      export HOST_LAN_IP
      echo "Auto‐detected LAN IP: $HOST_LAN_IP on interface $iface"
    fi
  fi
fi

# 2.5) Optional: start Direwolf with DigiRig CM108 PTT if enabled
# Requires env: DIGIRIG_ENABLE=1, AX25_CALLSIGN, AX25_RX_DEVICE, AX25_TX_DEVICE, DIGIRIG_PTT
start_direwolf() {
  echo "Configuring Direwolf…"
  : "${AX25_CALLSIGN:?AX25_CALLSIGN not set (e.g. KG7VSN-10)}"
  : "${AX25_RX_DEVICE:?AX25_RX_DEVICE not set (e.g. plughw:CARD=Device,DEV=0)}"
  : "${AX25_TX_DEVICE:?AX25_TX_DEVICE not set (e.g. plughw:CARD=Device,DEV=0)}"
  : "${DIGIRIG_PTT:?DIGIRIG_PTT not set (e.g. /dev/digrig-ptt)}"

  # Generate a minimal, solid Direwolf config tuned for 1200 AFSK VHF
  cat > "$DW_CFG" <<EOF
ADEVICE ${AX25_RX_DEVICE} ${AX25_TX_DEVICE}
ARATE   48000
ACHANNELS 1
CHANNEL 0
MODEM 1200
MYCALL ${AX25_CALLSIGN}
PTT CM108 ${DIGIRIG_PTT}
AGWPORT 8000
KISSPORT 8001
EOF

  mkdir -p "$(dirname "$DW_LOG")"
  echo "Starting Direwolf (AGW:8000, KISS:8001)…"
  # Run Direwolf in background; no chrt/nice (requires CAP_SYS_NICE).
  ( set -m; exec direwolf -t 0 -c "$DW_CFG" >"$DW_LOG" 2>&1 & )
  # Give Direwolf a moment to bind sockets.
  sleep 2
}

# Optionally bring up Direwolf if enabled
if [ "${DIGIRIG_ENABLE:-0}" = "1" ]; then
  # Validate devices exist from host mapping
  if [ ! -e /dev/snd ] || [ ! -e "${DIGIRIG_PTT:-/dev/digrig-ptt}" ]; then
    echo "WARNING: DIGIRIG_ENABLE=1 but /dev/snd or ${DIGIRIG_PTT:-/dev/digrig-ptt} is missing."
    echo "         Check docker compose 'devices:' and your udev rule."
  else
    start_direwolf
  fi
fi

# 3) waitress settings (env‑configurable; sensible defaults)
LISTEN_ADDR="${WAITRESS_LISTEN:-0.0.0.0:5150}"
THREADS="${WAITRESS_THREADS:-32}"
CONNLIM="${WAITRESS_CONNECTION_LIMIT:-200}"
CHTIME="${WAITRESS_CHANNEL_TIMEOUT:-120}"
BACKLOG_OPT=""
if [ -n "${WAITRESS_BACKLOG:-}" ]; then
  BACKLOG_OPT="--backlog=${WAITRESS_BACKLOG}"
fi

echo "Starting waitress: listen=${LISTEN_ADDR} threads=${THREADS} conn_limit=${CONNLIM} channel_timeout=${CHTIME}"

# 4) finally exec the app via waitress
#    also forward any extra args passed to this entrypoint
exec waitress-serve \
  --listen="${LISTEN_ADDR}" \
  --threads="${THREADS}" \
  --connection-limit="${CONNLIM}" \
  --channel-timeout="${CHTIME}" \
  ${BACKLOG_OPT} \
  "$@" \
  app:app
