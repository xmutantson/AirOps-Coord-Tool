"""
Offline tile serving + one-time seeding.

• Storage path: preference('map_tiles_path')
    - If path ends with '.mbtiles' → store in MBTiles file (TMS y-flip).
    - Otherwise, treat path as a directory tree: <root>/<z>/<x>/<y>.png
• Endpoint: GET /tiles/<int:z>/<int:x>/<int:y>.png
• Seeding (first boot only when preference 'map_offline_seed' == 'yes'):
    - Best-effort background task that seeds a tiny low-zoom footprint (z0–7)
      around CONUS center so the map renders offline. Creates directories/MBTiles
      even if network is unavailable.

This module is self-contained:
    - Exposes a blueprint `bp` with /tiles route.
    - Exposes `bootstrap_offline_tiles(app)` to install a background seeder once.
    - CLI prefetcher:  python -m modules.services.tiles prefetch --bbox minLon,minLat,maxLon,maxLat --zmin 5 --zmax 7 [--threads 8]
      (Writes tiles to the same storage path as above; skips existing files.)
"""

from __future__ import annotations
import base64
import io
import math
import os
import sqlite3
import threading
import time
from typing import Optional, Tuple
from urllib.request import Request, urlopen
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import sys

from flask import Blueprint, Response, current_app, jsonify

from modules.utils.common import get_preference, get_db_file

bp = Blueprint(__name__.rsplit(".", 1)[-1], __name__)

# ──────────────────────────────────────────────────────────────────────────────
# Helpers: path/MBTiles detection and y-flip math

def _tiles_path() -> str:
    # common.get_preference already supplies sensible default near the DB
    path = (get_preference('map_tiles_path') or '').strip()
    if not path:
        # Double fallback if prefs table isn't ready yet
        path = os.path.join(os.path.dirname(get_db_file()), 'tiles')
    return path

def _is_mbtiles(path: str) -> bool:
    return path.lower().endswith('.mbtiles')

def _ensure_fs_tree(root: str) -> None:
    os.makedirs(root, exist_ok=True)

def _mb_open(path: str) -> sqlite3.Connection:
    # Single-process Flask: use check_same_thread=False for request threads
    conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    # Tables (idempotent)
    conn.execute("""
      CREATE TABLE IF NOT EXISTS tiles(
        zoom_level INTEGER,
        tile_column INTEGER,
        tile_row INTEGER,
        tile_data BLOB
      );
    """)
    conn.execute("""
      CREATE TABLE IF NOT EXISTS metadata(
        name TEXT, value TEXT
      );
    """)
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_tiles_zxy ON tiles(zoom_level, tile_column, tile_row);")
    return conn

def _y_to_tms(z: int, y: int) -> int:
    # Leaflet XYZ → MBTiles TMS row
    return (2 ** z - 1) - y

# ──────────────────────────────────────────────────────────────────────────────
# Serving: /tiles/z/x/y.png

# 1×1 transparent PNG for holes/misses (kept tiny)
_BLANK_PNG = base64.b64decode(
    b"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Yb6zDkAAAAASUVORK5CYII="
)

def _resp_png(data: bytes) -> Response:
    # Aggressive: 5 years, immutable
    expires = (datetime.utcnow() + timedelta(days=365*5)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    return Response(
        data,
        mimetype="image/png",
        headers={
            "Cache-Control": "public, max-age=157680000, immutable",
            "Expires": expires,
        },
    )

@bp.get("/tiles/<int:z>/<int:x>/<int:y>.png")
def serve_tile(z: int, x: int, y: int):
    """
    Serve from MBTiles or folder cache. Returns 1×1 transparent PNG on miss.
    """
    path = _tiles_path()
    try:
        if _is_mbtiles(path) and os.path.isfile(path):
            conn = _mb_open(path)
            with conn:
                row = conn.execute(
                    "SELECT tile_data FROM tiles WHERE zoom_level=? AND tile_column=? AND tile_row=? LIMIT 1",
                    (z, x, _y_to_tms(z, y))
                ).fetchone()
            if row and row[0]:
                return _resp_png(row[0])

        # Folder layout: <root>/<z>/<x>/<y>.png
        root = path if not _is_mbtiles(path) else os.path.dirname(path)
        f = os.path.join(root, str(z), str(x), f"{y}.png")
        if os.path.isfile(f):
            with open(f, "rb") as fh:
                return _resp_png(fh.read())

        # If not cached and policy allows, try to fetch once, persist, and serve.
        if (os.getenv("AOCT_TILES_ALLOW_FETCH", "1") == "1"):
            data = _download_tile(z, x, y)
            if data:
                try:
                    if _is_mbtiles(path):
                        # store into MBTiles
                        conn = _mb_open(path)
                        with conn:
                            _store_tile_mb(conn, z, x, y, data)
                            conn.commit()
                    else:
                        # store into FS tree
                        root = path
                        _store_tile_fs(root, z, x, y, data)
                    return _resp_png(data)
                except Exception:
                    pass

    except Exception as e:
        try:
            current_app.logger.debug("Tile serve error z=%s x=%s y=%s: %s", z, x, y, e)
        except Exception:
            pass

    return _resp_png(_BLANK_PNG)

# ──────────────────────────────────────────────────────────────────────────────
# Seeding (best-effort, background)

def _latlon_to_tile(lat: float, lon: float, z: int) -> Tuple[int, int]:
    lat = max(-85.05112878, min(85.05112878, lat))
    n = 2 ** z
    xtile = int((lon + 180.0) / 360.0 * n)
    ytile = int((1.0 - math.log(math.tan(math.radians(lat)) + 1 / math.cos(math.radians(lat))) / math.pi) / 2.0 * n)
    xtile = max(0, min(n - 1, xtile))
    ytile = max(0, min(n - 1, ytile))
    return xtile, ytile

def _seed_targets(center_lat: float, center_lon: float, zmin=0, zmax=7):
    """
    Yield (z, x, y) tiles for a tiny footprint around (lat,lon).
    Footprint radius grows mildly with zoom to stay well under 1 GB.
    """
    for z in range(zmin, zmax + 1):
        cx, cy = _latlon_to_tile(center_lat, center_lon, z)
        # radius: 0 at z0..1, then roughly doubles every couple of zooms (capped)
        r = max(0, min(8, int(max(0, z - 2))))
        for dx in range(-r, r + 1):
            for dy in range(-r, r + 1):
                yield z, cx + dx, cy + dy

def _download_tile(z: int, x: int, y: int) -> Optional[bytes]:
    """
    Fetch from OSM default endpoint (respectful UA). Network failures return None.
    """
    try:
        url = f"https://tile.openstreetmap.org/{z}/{x}/{y}.png"
        req = Request(url, headers={"User-Agent": "AOCT/1.0 offline-seed"})
        with urlopen(req, timeout=10) as r:
            if r.status == 200:
                return r.read()
    except Exception:
        return None
    return None

def _store_tile_fs(root: str, z: int, x: int, y: int, data: bytes) -> None:
    d = os.path.join(root, str(z), str(x))
    os.makedirs(d, exist_ok=True)
    f = os.path.join(d, f"{y}.png")
    if not os.path.exists(f):
        with open(f, "wb") as fh:
            fh.write(data)

def _store_tile_mb(conn: sqlite3.Connection, z: int, x: int, y: int, data: bytes) -> None:
    yt = _y_to_tms(z, y)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO tiles(zoom_level,tile_column,tile_row,tile_data) VALUES (?,?,?,?)",
            (z, x, yt, data)
        )
    except Exception:
        # Fallback to upsert
        conn.execute(
            "REPLACE INTO tiles(zoom_level,tile_column,tile_row,tile_data) VALUES (?,?,?,?)",
            (z, x, yt, data)
        )

def _seed_worker(path: str, sentinel: str) -> None:
    """
    Background seeder (tiny). Creates structure when offline, fills when online.
    """
    try:
        # Seed center near CONUS; if you prefer a different area, set AOCT_SEED_LAT/LON envs
        lat = float(os.getenv("AOCT_SEED_LAT", "39.5"))
        lon = float(os.getenv("AOCT_SEED_LON", "-98.35"))

        if _is_mbtiles(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            conn = _mb_open(path)
            with conn:
                # Minimal metadata
                conn.execute("INSERT OR IGNORE INTO metadata(name,value) VALUES('name','AOCT base');")
                conn.execute("INSERT OR IGNORE INTO metadata(name,value) VALUES('format','png');")
                conn.commit()
        else:
            _ensure_fs_tree(path)
            conn = None

        # Iterate small set and best-effort fetch
        count = 0
        for (z, x, y) in _seed_targets(lat, lon, 0, 7):
            if x < 0 or y < 0 or x >= 2**z or y >= 2**z:
                continue
            data = _download_tile(z, x, y)
            if not data:
                # Create holes lazily; serve-time will return a 1×1 PNG fallback.
                continue
            if conn is not None:
                _store_tile_mb(conn, z, x, y, data)
            else:
                _store_tile_fs(path, z, x, y, data)
            count += 1
            # Light throttle to be polite
            if count % 50 == 0:
                time.sleep(0.2)

        # Mark as seeded (idempotent)
        try:
            with open(sentinel, "w") as f:
                f.write(str(int(time.time())))
        except Exception:
            pass

    except Exception as e:
        try:
            current_app.logger.warning("Tile seeding error: %s", e)
        except Exception:
            pass
    finally:
        try:
            if 'conn' in locals() and conn:
                conn.commit()
                conn.close()
        except Exception:
            pass

def bootstrap_offline_tiles(app) -> None:
    """
    Kick off a one-time background seed if:
      • preference 'map_offline_seed' == 'yes'
      • sentinel doesn't exist yet
    Always ensures base directory/mbtiles file parent exists.
    """
    try:
        path = _tiles_path()
        want = (get_preference('map_offline_seed') or 'yes').strip().lower() == 'yes'

        # Sentinel file lives next to the directory or MBTiles file
        sentinel_dir = path if not _is_mbtiles(path) else os.path.dirname(path)
        os.makedirs(sentinel_dir, exist_ok=True)
        sentinel = os.path.join(sentinel_dir, ".seeded.offline.tiles")

        if not want:
            app.logger.info("Offline tiles seeding disabled by preference.")
            return
        if os.path.exists(sentinel):
            app.logger.info("Offline tiles seeding already done (sentinel present).")
            return

        # Ensure container volume path exists even if offline
        if _is_mbtiles(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
        else:
            _ensure_fs_tree(path)

        t = threading.Thread(target=_seed_worker, args=(path, sentinel), daemon=True)
        t.start()
        app.logger.info("Started offline tiles seeding thread (path=%s).", path)

    except Exception as e:
        try:
            app.logger.warning("Could not bootstrap offline tiles: %s", e)
        except Exception:
            pass

# ──────────────────────────────────────────────────────────────────────────────
# CLI prefetcher (Option A): warm cache for a bbox & zoom range, skip existing
# Usage example:
#   python -m modules.services.tiles prefetch \
#     --bbox -130,24,-60,55 --zmin 5 --zmax 7 --threads 8
# ──────────────────────────────────────────────────────────────────────────────

def _tile_exists(path: str, z: int, x: int, y: int) -> bool:
    if _is_mbtiles(path) and os.path.isfile(path):
        try:
            conn = _mb_open(path)
            with conn:
                row = conn.execute(
                    "SELECT 1 FROM tiles WHERE zoom_level=? AND tile_column=? AND tile_row=? LIMIT 1",
                    (z, x, _y_to_tms(z, y)),
                ).fetchone()
            return bool(row)
        except Exception:
            return False
    else:
        f = os.path.join(path, str(z), str(x), f"{y}.png")
        return os.path.isfile(f)

def _lonlat_to_tile(lon: float, lat: float, z: int) -> Tuple[int, int]:
    # XYZ conversion (lon,lat) → (x,y)
    lat = max(-85.05112878, min(85.05112878, lat))
    n = 2 ** z
    xtile = int((lon + 180.0) / 360.0 * n)
    ytile = int((1.0 - math.log(math.tan(math.radians(lat)) + 1 / math.cos(math.radians(lat))) / math.pi) / 2.0 * n)
    xtile = max(0, min(n - 1, xtile))
    ytile = max(0, min(n - 1, ytile))
    return xtile, ytile

def _bbox_ranges(bbox: Tuple[float, float, float, float], z: int):
    minLon, minLat, maxLon, maxLat = bbox
    x0, y1 = _lonlat_to_tile(minLon, minLat, z)
    x1, y0 = _lonlat_to_tile(maxLon, maxLat, z)
    if x0 > x1: x0, x1 = x1, x0
    if y0 > y1: y0, y1 = y1, y0
    return range(x0, x1 + 1), range(y0, y1 + 1)

def _ensure_fetch_and_store(path: str, z: int, x: int, y: int) -> bool:
    if _tile_exists(path, z, x, y):
        return True
    data = _download_tile(z, x, y)
    if not data:
        return False
    try:
        if _is_mbtiles(path):
            conn = _mb_open(path)
            with conn:
                _store_tile_mb(conn, z, x, y, data)
                conn.commit()
        else:
            _store_tile_fs(path, z, x, y, data)
        return True
    except Exception:
        return False

def _prefetch_bbox(path: str, bbox: Tuple[float, float, float, float], zmin: int, zmax: int, threads: int = 8) -> int:
    targets = []
    for z in range(zmin, zmax + 1):
        xr, yr = _bbox_ranges(bbox, z)
        for x in xr:
            for y in yr:
                targets.append((z, x, y))
    if not targets:
        return 0
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futs = {ex.submit(_ensure_fetch_and_store, path, z, x, y): (z, x, y) for (z, x, y) in targets}
        for f in as_completed(futs):
            try:
                if f.result():
                    done += 1
            except Exception:
                pass
    return done

def _main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("prefetch", help="Warm tile cache for bbox & zooms (skips existing).")
    # Accept --bbox OR AOCT_PREFETCH_BBOX env as a fallback
    sp.add_argument("--bbox", required=False, default=os.getenv("AOCT_PREFETCH_BBOX"),
                    help="minLon,minLat,maxLon,maxLat (or set AOCT_PREFETCH_BBOX env)")
    sp.add_argument("--zmin", type=int, default=5)
    sp.add_argument("--zmax", type=int, default=7)
    sp.add_argument("--threads", type=int, default=8)
    args = ap.parse_args()
    if args.cmd == "prefetch":
        if not args.bbox:
            print("Missing --bbox and AOCT_PREFETCH_BBOX is not set.", file=sys.stderr)
            sys.exit(2)
        bbox = tuple(map(float, args.bbox.split(",")))
        p = _tiles_path()
        # Ensure tree/parent exists so we can write immediately even if offline later
        if _is_mbtiles(p):
            os.makedirs(os.path.dirname(p), exist_ok=True)
        else:
            os.makedirs(p, exist_ok=True)
        n = _prefetch_bbox(p, bbox, args.zmin, args.zmax, threads=args.threads)
        print(f"Prefetched {n} tiles into {p}")

if __name__ == "__main__":
    _main()
