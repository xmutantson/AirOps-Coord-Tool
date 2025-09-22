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
    restart: always
    devices:
      - /dev/snd
      - /dev/digrig-ptt:/dev/digrig-ptt
    group_add:
      - audio

    cap_add:
      - SYS_TIME                       # required to change host clock from inside container

    environment:
      # ---- System Time Autoset ----
      AOCT_SET_HOST_TIME: "1"           # OFF by default; enable to allow host time set
      AOCT_TIME_DRIFT_MS: "900000"      # only adjust when drift >= 15m (900s)
      AOCT_TIME_MAX_ADJUST_SEC: "0"     # refuse adjustments bigger than value (in seconds). set to 0 to disable limits

      # ---- Waitress (web app) ----
      WAITRESS_LISTEN: "0.0.0.0:5150"
      WAITRESS_THREADS: "32"
      WAITRESS_CONNECTION_LIMIT: "200"
      WAITRESS_CHANNEL_TIMEOUT: "120"

      # ---- Direwolf / radio I/O ----
      DIGIRIG_ENABLE: "1"
      DIGIRIG_PTT: "/dev/digrig-ptt"
      AX25_CALLSIGN: "KG7VSN-10"
      AX25_RX_DEVICE: "plughw:CARD=Device,DEV=0"
      AX25_TX_DEVICE: "plughw:CARD=Device,DEV=0"

      # ---- AX.25 UI broadcaster (radio_tx.py) ----
      AX25_DEST: "AOCTDB"        # 6-char destination
      AX25_PATH: ""              # optional digipeater path (blank = direct)
      MYCALL: "KG7VSN-10"        # overrides AX25_CALLSIGN if set

      # KISS TCP the broadcaster talks to (Direwolf default 8001)
      KISS_HOST: "127.0.0.1"
      KISS_PORT: "8001"
      # KISS verbosity (0/1). Turn on temporarily if you need troubleshooting.
      KISS_VERBOSE: "0"

      # Payload chunking/pacing
      CHUNK_BYTES: "200"         # bytes per frame after encoding
      PACE_MS: "350"             # ms between frames inside a burst
      BURST_SIZE: "6"            # frames per kissutil session
      BURST_PAUSE_MS: "750"      # ms between bursts
      KISS_WARMUP_MS: "250"      # ms after kissutil starts before first frame

      # New timing model (full snapshot + diffs)
      FULL_INTERVAL_SEC: "900"   # 15 minutes
      DIFF_INTERVAL_SEC: "30"    # 30 seconds (skips empty diffs)

      # Compression (payload-only)
      COMPRESS: "1"              # 1=enable compression (zlib), 0=plain JSON
      ENCODING: "B91"            # Encoding alphabet for compressed bytes: B91 (Base91) or B64 (Base64)

      # ---- SQL slow-query logging ----
      AOCT_SQL_SLOW_MS: "50"     # log ≥50ms
      AOCT_SQL_EXPLAIN: "1"      # also log EXPLAIN for slow SELECTs
      AOCT_SQL_LOG: "0"          # set "1" to log ALL dict_rows() queries
      AOCT_SQL_TRACE: "1"        # set "1" to enable sqlite trace hook
      AOCT_SQL_TRACE_EXPANDED: "0"
      PYTHONUNBUFFERED: "1"      # flush logs promptly

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

```
# ------------------------------------------------------------
# Build the Windows client (from Linux) using Wine + PyInstaller
# ------------------------------------------------------------

# 0) Choose an isolated Wine prefix for Windows-Python tools (recommended)
export WINEARCH=win64
export WINEPREFIX="${HOME}/.wine-py311"
wineboot -u

# 1) Download and install Windows Python in the Wine prefix
#    (Pick a specific 3.11.x you like; 3.11 works well with PyInstaller.)
PY_VER="3.11.6"
PY_EXE="python-${PY_VER}-amd64.exe"

# Download if missing
[ -f "${PY_EXE}" ] || wget "https://www.python.org/ftp/python/${PY_VER}/${PY_EXE}"

# Silent install, add pip and PATH for the Wine user
# Flags reference: https://docs.python.org/3/using/windows.html#installing-without-ui
wine "${PY_EXE}" /quiet InstallAllUsers=0 PrependPath=1 Include_launcher=1 Include_pip=1 Include_tcltk=1

# 2) Path to the Windows Python inside Wine (your original path kept, now guaranteed to exist)
#    If your Wine user is different, adjust the "kameron" part.
WIN_PY_WINPATH='C:\users\kameron\AppData\Local\Programs\Python\Python311\python.exe'

# Sanity check
wine "$WIN_PY_WINPATH" --version || {
  echo "ERROR: Could not run Windows Python via Wine at $WIN_PY_WINPATH"
  echo "If needed, locate it with: find \"$WINEPREFIX/drive_c/users\" -iname python.exe"
  exit 1
}

# 3) Make sure pip works; upgrade toolchain and install PyInstaller
wine "$WIN_PY_WINPATH" -m pip install --upgrade pip setuptools wheel
wine "$WIN_PY_WINPATH" -m pip install pyinstaller

# (If pip was somehow not present, you can bootstrap it:)
# wine "$WIN_PY_WINPATH" -m ensurepip --upgrade

# 4) From the folder containing aot_client.pyw, build a GUI EXE (no console window)
#    (Your original build line preserved, just with --windowed for GUI)
wine "$WIN_PY_WINPATH" -m PyInstaller --noconfirm --windowed --onefile --name aot_client aot_client.pyw

# 5) Find your EXE in ./dist/
echo "Build complete. EXE is at: $(pwd)/dist/aot_client.exe"

# ------------------------------------------------------------
# Optional: use a Wine venv (keeps packages isolated per project)
# (Uncomment to use.)
# wine "$WIN_PY_WINPATH" -m venv venv-win
# wine "venv-win\Scripts\python.exe" -m pip install --upgrade pip setuptools wheel pyinstaller
# wine "venv-win\Scripts\python.exe" -m PyInstaller --noconfirm --windowed --onefile --name aot_client aot_client.pyw
# ------------------------------------------------------------
```

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
