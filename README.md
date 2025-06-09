# ✈️ Aircraft Ops Coordination Tool

A lightweight Flask-based web application for tracking inbound and outbound aircraft operations during emergency events or deployments. 

This was optimized for DART usage. https://clallamdart.com/ is one team, this page contains a good explaantion of what DART is.

Originally designed to run on a Raspberry Pi or minimal server, now fully dockerized and portable.

---

## 🛠 Features

* **Ramp Boss Mode**: Fast entry of outbound/inbound flight details
* **Dashboard**: Real-time operational summary of aircraft movement
* **Radio Operator Tools**: Winlink message parser + message builder
* **Preferences**: Browser-local settings for unit and code display
* **Persistent History**: Tracks changes via flight history log
* **CSV Import/Export**: Syncs with external flight manifests or logs
* **ICAO/IATA Lookup**: Integrated database of US airfields

---

## 🐳 Run via Docker

### 🚀 Quick Start (`docker-compose`)

Create a directory and save this `docker-compose.yml`:

```yaml
version: '3.8'

services:
  aircraft_ops_tool:
    image: ghcr.io/xmutantson/aircraft_ops_tool:latest
    ports:
      - "8080:5150"  # Visit http://localhost:8080
    volumes:
      - ./data:/app/data  # Stores aircraft_ops.db here
    restart: unless-stopped
```

Then run:

```bash
docker compose up -d
```

### 🔄 Or with `docker run`

```bash
docker run -d \
  --name aircraft_ops_tool \
  -p 8080:5150 \
  -v $(pwd)/data:/app/data \
  ghcr.io/xmutantson/aircraft_ops_tool:latest
```

---

## 📂 Persistent Storage

The app writes its database to `/app/data/aircraft_ops.db`. Both examples above mount a host directory (`./data`) so that data is **retained across container restarts**.

---

## 🧪 Development

To run it manually (outside Docker):

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Default port: `http://localhost:5150`

---

## 📝 License

MIT License

---

## 👤 Maintainer

Built and maintained by [@xmutantson](https://github.com/xmutantson)
