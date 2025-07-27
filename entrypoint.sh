#!/usr/bin/env bash
set -e

SECRET_PATH=/run/secrets/flask_secret

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
