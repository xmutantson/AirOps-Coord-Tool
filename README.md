# ✈️ Aircraft Ops Coordination Tool

A lightweight Flask app for tracking inbound/outbound aircraft ops during emergencies. Runs great on a Raspberry Pi or small server and is fully dockerized.

Now includes a radio feature: it **broadcasts the dashboard over AX.25 UI frames via Direwolf (KISS-TCP)**, and a **Windows client** that listens on KISS-TCP (UZ7HO/Direwolf/etc.), reassembles packets, applies diffs, and shows a live dashboard.

## 🛠 Features

- **Ramp Boss Mode**: fast entry of flight details  
- **Dashboard**: real-time operational summary  
- **Radio Uplink (NEW)**:
  - Server transmits dashboard snapshots as **AX.25 UI frames** over **KISS-TCP** (Direwolf).
  - Payloads are **chunked** and **compressed** by default (zlib + Base91; Base64 fallback).
  - **Full table** every 15 min; **diffs** (only when there’s change) ~ every 30 s.
- **Windows Receive Client (NEW)**:
  - Self-contained EXE (`dist/aot_client.exe`) that connects to KISS-TCP and:
    - Logs frames (packet log),
    - Reassembles the JSON, applies diffs,
    - Renders a dashboard table (toggle the 3 panes on/off).
- **Radio Operator Tools**: Winlink message parser & builder  
- **Security**: CSRF/XSS protections, rate limiting, secret management  
- **Production WSGI**: Waitress  
- **mDNS**: advertises as `RampOps.local`  
- **CSV Import/Export**, **ICAO/IATA lookup**, **Persistent history**

---

## 🐳 Run via Docker

### Quick Start (`docker-compose`)

Create `docker-compose.yml`:


```
services:
  aircraft_ops_tool:
    image: ghcr.io/xmutantson/aircraft_ops_tool:latest
    network_mode: host
    volumes:
      - ./data:/app/data
      - flask_secret:/run/secrets
    restart: unless-stopped
    devices:
      - /dev/snd
      - /dev/digrig-ptt:/dev/digrig-ptt
    group_add:
      - audio
    environment:
      WAITRESS_LISTEN: "0.0.0.0:5150"
      WAITRESS_THREADS: "32"
      WAITRESS_CONNECTION_LIMIT: "200"
      WAITRESS_CHANNEL_TIMEOUT: "120"
      DIGIRIG_ENABLE: "1"
      DIGIRIG_PTT: "/dev/digrig-ptt"
      AX25_CALLSIGN: "KG7VSN-10"
      AX25_RX_DEVICE: "plughw:CARD=Device,DEV=0"
      AX25_TX_DEVICE: "plughw:CARD=Device,DEV=0"
      AX25_DEST: "AOCTDB"
      AX25_PATH: ""
      MYCALL: "KG7VSN-10"
      KISS_HOST: "127.0.0.1"
      KISS_PORT: "8001"
      KISS_VERBOSE: "0"
      CHUNK_BYTES: "200"
      PACE_MS: "350"
      BURST_SIZE: "6"
      BURST_PAUSE_MS: "750"
      KISS_WARMUP_MS: "250"
      FULL_INTERVAL_SEC: "900"
      DIFF_INTERVAL_SEC: "30"
      COMPRESS: "1"
      ENCODING: "B91"
    ulimits:
      nofile:
        soft: 4096
        hard: 8192

volumes:
  flask_secret:

```

Then:

```
docker compose up -d

```

> The container can optionally **start Direwolf** itself (using your DigiRig CM108 PTT). If you already run Direwolf externally, set `DIGIRIG_ENABLE=0` and just keep KISS-TCP reachable at `KISS_HOST:KISS_PORT`.

---

## 📡 About the Radio Uplink

- Frames look like:  
  `AOT <seq>/<total>|<F|D>|<sid>|<Z|B|J>|<chunk>`  
  - `F` = full snapshot; `D` = diff  
  - `sid` = session id (diffs reuse the last full’s sid)  
  - Encoding: `Z` (zlib+Base91), `B` (zlib+Base64), or `J` (plain JSON)  
- The sender **chunks** the encoded payload to `CHUNK_BYTES` and paces frames.
- The receiver buffers all parts for a `sid`, reassembles, decodes, and:
  - Replaces the current state on `F`,
  - Applies `df.u`/`df.rm` on `D`.

---

## 🪟 Windows Receive Client

For most users, just **download the EXE** from the repo: `dist/aot_client.exe`.

1. Run `aot_client.exe`.  
2. Set **Host** (often `127.0.0.1`) and **KISS Port**:
   - **UZ7HO**: default **8100**
   - **Direwolf**: default **8001**
3. Click **Connect**.  
4. Use the checkboxes to toggle:
   - Packet Log, JSON, Dashboard (defaults: all on).  
   - If you turn everything off, the app auto-re-enables the dashboard.
5. Your settings are saved to `settings.json` **next to the EXE**.

> The client is KISS-TCP only (simple and robust). It does not speak AGWPE.

---

## 📂 Data & Persistence

- SQLite DB: `/app/data/aircraft_ops.db` (mounted from `./data`).
- The `flask_secret` named volume persists a stable secret for sessions/CSRF.

---

## 🔧 Development

Run locally (no Docker):

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
./entrypoint.sh
# open http://localhost:5150

```

### Build the Windows Client (from Linux via Wine)

If you want to reproduce the EXE yourself:

```
pip install pyinstaller
pyinstaller --noconfirm --windowed --onefile aot_client.pyw
# output: dist/aot_client.exe
```

> We now **commit `dist/`** so Windows users can download prebuilt artifacts directly from the repo.

---

## 🔍 Troubleshooting

- **Client shows “Connected to KISS” but no packets:**  
  Make sure your TNC/modem is actually decoding and forwarding UI frames to KISS-TCP, and the **port** matches your modem:
  - UZ7HO: 8100, Direwolf: 8001.
- **Diff arrives but does nothing:**  
  The receiver requires at least one prior **Full** for that `sid`. Fulls are sent every 15 min (or on first start).
- **Throughput issues:**  
  Try tweaking `CHUNK_BYTES` (e.g., 180–220) and pacing (e.g., `PACE_MS=300–500`).  
  You can also switch encoding to Base64 (`ENCODING=B64`) if your path tolerates slightly larger payloads but you want simpler alphabet/decoding.

---

## 📝 License

MIT License

## 👤 Maintainer

Built and maintained by [@xmutantson](https://github.com/xmutantson)
