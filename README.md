# Aircraft Ops Coordination Tool

A Flask web app for tracking aircraft operations during emergencies. Runs on a Raspberry Pi or small server, fully Dockerized. Life-safety adjacent: operators depend on this during real incidents.

## Features

- **Ramp Boss**: fast flight entry, cargo manifest builder, queue management
- **Inventory / Material Handling**: barcode scanning (USB + camera), auto-generated barcodes, stock tracking with origin/source
- **Direct Label Printing**: sends labels to a Brother QL-820NWB over the network via `brother_ql` (no driver install needed on workstations)
  - Shipping labels: full flight info with barcode, one per unit, auto-cut
  - Inventory tags: compact barcode sticker for tagging items
- **Winlink Radio**: message parsing, composition, multi-account send-as, auto-reply
- **Radio Uplink**: broadcasts dashboard over AX.25 UI frames via Direwolf (KISS-TCP)
- **SAME Weather Alerts**: 7-channel rtl_airband monitoring with alert decode
- **Flight Locate**: ADS-B integration, offline map tiles
- **Wargame Mode**: isolated training environment
- **Windows Receive Client**: standalone EXE for radio dashboard (`dist/aot_client.exe`)
- mDNS (`RampOps.local`), CSV import/export, CSRF/XSS protections, Waitress WSGI

## Deployment

### Prerequisites

- Raspberry Pi (or any Linux host) with Docker installed
- Optional: DigiRig for packet radio, RTL-SDR for weather alerts, Brother QL-820NWB for label printing

### Install

```bash
# Create the working directory
mkdir -p /home/pi/docker/aoct/data
cd /home/pi/docker/aoct

# Copy deploy files from the repo's deploy/ directory
cp deploy/docker-compose.yml .
cp deploy/start.sh .
cp deploy/aoct.service /etc/systemd/system/
chmod +x start.sh

# Enable the systemd service (starts on boot)
sudo systemctl daemon-reload
sudo systemctl enable aoct.service

# Start now
sudo systemctl start aoct
```

The `start.sh` script handles hardware detection:
- Checks for DigiRig USB devices (`/dev/snd`, `/dev/digrig-ptt`)
- Writes a `docker-compose.override.yml` with only the devices that exist
- Container starts even if the DigiRig is unplugged (radio features degrade gracefully)
- Brother QL label printer is auto-discovered via mDNS on the LAN

### Update

```bash
cd /home/pi/docker/aoct
bash start.sh
```

This pulls the latest image and restarts the container.

### Manage

```bash
sudo systemctl start aoct     # start
sudo systemctl stop aoct      # stop
sudo systemctl restart aoct   # restart
sudo systemctl status aoct    # check status
docker logs aoct-aircraft_ops_tool-1 --tail 50   # view logs
```

### Configuration

All runtime configuration is in `docker-compose.yml` via environment variables. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `WAITRESS_LISTEN` | `0.0.0.0:5150` | Web server bind address |
| `DIGIRIG_ENABLE` | `1` | Enable DigiRig/Direwolf for packet radio |
| `AX25_CALLSIGN` | `KG7VSN-10` | Your AX.25 callsign |
| `AOCT_SAME_ENABLE` | `1` | Enable SAME weather alert monitoring |
| `AOCT_SAME_MODE` | `airband` | SAME decode mode (airband/rtl_fm/udp) |

See `deploy/docker-compose.yml` for the full list.

### Firewall

If the Pi runs iptables, port 9100 (label printer) needs to be open outbound. See `iptables-lockdown-config.txt` on the Pi for the full rule set. Key additions for label printing:

```bash
sudo iptables -A OUTPUT -p tcp --dport 9100 -j ACCEPT
sudo iptables -I FORWARD 1 -p tcp --dport 9100 -j ACCEPT
sudo netfilter-persistent save
```

## Label Printer

The tool prints directly to a Brother QL-820NWB on DK-2205 62mm continuous tape. No driver install needed on any workstation.

**Setup:**
1. Put the QL-820NWB on the same Wi-Fi network (infrastructure mode)
2. Set Command Mode to **Raster** via the printer's web interface (`http://<printer-ip>`)
3. Enable **Raw Port** (9100) under Network > Protocol
4. The tool auto-discovers the printer via mDNS on container start

**How it works:**
- Labels are rendered as PNG images via Pillow at 300 DPI (696px = 62mm)
- Sent directly to the printer over TCP port 9100 via `brother_ql`
- Auto-cuts at exact content length (no wasted tape)
- Falls back to browser print dialog if direct printing is disabled or printer is unreachable

## Building

### Docker image (multi-platform)

```bash
# From WSL (mount drive first if needed)
sudo mount -t drvfs X: /mnt/x
cd /mnt/x/Storage/Documents/air-ops-vscode/AirOps-Coord-Tool

docker buildx build --builder multiplatform \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t ghcr.io/xmutantson/aircraft_ops_tool:latest --push .
```

### Local development

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
# open http://localhost:5150
```

## Tech Stack

- **Backend:** Python 3.10, Flask, SQLite, Waitress, APScheduler
- **Frontend:** Vanilla JS (ES6), no framework
- **Radio:** Direwolf (AX.25/KISS-TCP), PAT (Winlink), rtl_airband (SAME)
- **Printing:** brother_ql, python-barcode, Pillow
- **Deploy:** Docker multi-platform (amd64, arm64, arm/v7) via `ghcr.io/xmutantson/aircraft_ops_tool`

## Data & Persistence

- SQLite DB: `/app/data/aircraft_ops.db` (mounted from `./data`)
- `flask_secret` named volume persists session/CSRF secret

## License

MIT License

## Maintainer

Built and maintained by [@xmutantson](https://github.com/xmutantson)
