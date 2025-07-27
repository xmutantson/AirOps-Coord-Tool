# ✈️ Aircraft Ops Coordination Tool

A lightweight Flask-based web application for tracking inbound and outbound aircraft operations during emergency events or deployments.

Optimized for DART usage (see [https://clallamdart.com/](https://clallamdart.com/) for background). Originally designed to run on a Raspberry Pi or minimal server, it’s now fully dockerized and portable.

## 🛠 Features

* **Ramp Boss Mode**: Fast entry of outbound/inbound flight details
* **Dashboard**: Real-time operational summary of aircraft movement
* **Radio Operator Tools**: Winlink message parser + message builder
* **Preferences**: Browser-local settings for unit and code display
* **Persistent History**: Tracks changes via flight history log
* **CSV Import/Export**: Syncs with external flight manifests or logs
* **ICAO/IATA Lookup**: Integrated database of US airfields
* **Security Hardened**: CSRF, XSS protection, rate limiting, upload limits, secret management
* **Production WSGI**: Uses Waitress for robust serving
* **mDNS Auto-Discovery**: Uses mDNS to advertise as RampOps.local

## 🐳 Run via Docker

### 🚀 Quick Start with `docker-compose`

Create a directory and save this `docker-compose.yml`:

```yaml
services:
  aircraft_ops_tool:
    image: ghcr.io/xmutantson/aircraft_ops_tool:latest
    network_mode: host
    volumes:
      - ./data:/app/data
      - flask_secret:/run/secrets
    restart: unless-stopped

    # Waitress sizing (safe defaults for a Pi 4; tune by env without rebuilds)
    environment:
      WAITRESS_LISTEN: "0.0.0.0:5150"
      WAITRESS_THREADS: "32"            # 24–40 are fine on a Pi 4 for I/O-bound loads
      WAITRESS_CONNECTION_LIMIT: "200"  # cap concurrent sockets per process
      WAITRESS_CHANNEL_TIMEOUT: "120"   # > 30s SSE keep-alive
      # WAITRESS_BACKLOG: "100"         # optional; leave unset unless needed

    # A modest FD limit helps if many tabs open SSE
    ulimits:
      nofile:
        soft: 4096
        hard: 8192

volumes:
  flask_secret:
```

Then run:

```bash
docker compose up -d
```

### 🔄 Or with `docker run`

```bash
docker run -d \
  --name aircraft_ops_tool \
  --network host \
  -v $(pwd)/data:/app/data \
  --mount type=volume,source=flask_secret,target=/run/secrets \
  ghcr.io/xmutantson/aircraft_ops_tool:latest
```

## 📂 Persistent Storage

The app writes its database to `/app/data/aircraft_ops.db`. Both examples above mount a host directory (`./data`) so that data is retained across container restarts. The `flask_secret` volume auto-generates a stable secret on first run and persists it across `docker compose down && docker compose up`.

## 🧪 Development

To run it manually outside Docker:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
./entrypoint.sh
```

Then visit: `http://localhost:5150`

## 📝 License

MIT License

## 👤 Maintainer

Built and maintained by [@xmutantson](https://github.com/xmutantson)
---

## 👤 Maintainer

Built and maintained by [@xmutantson](https://github.com/xmutantson)

