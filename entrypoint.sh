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
  # grab the default‐route line but ignore docker*/br*/tun* interfaces
  route_line=$(ip route show default | grep -vE 'dev (docker|br-|tun)' | head -n1)
  iface=$(awk '/dev/ {for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}' <<<"$route_line")
  # then grab the IPv4 address assigned to that iface
  HOST_LAN_IP=$(ip -4 addr show dev "$iface" \
                | grep -oP '(?<=inet\s)\d+(\.\d+){3}' \
                | head -n1)
  export HOST_LAN_IP
  echo "Auto‐detected LAN IP: $HOST_LAN_IP on interface $iface"
fi

# 3) finally exec the app via waitress
exec waitress-serve --port=5150 app:app
