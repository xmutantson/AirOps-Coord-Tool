from __future__ import annotations

from modules.services import same_ingest
from flask import Blueprint, render_template, jsonify, request, abort, make_response, Response
from flask import stream_with_context
import subprocess
import socket, array, select, math
import time
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
from jinja2 import TemplateNotFound
from threading import Thread
from typing import List, Dict
import os  # for stem handling (canonicalization)
import hashlib
import json
import re
import urllib.parse, urllib.request
from app import scheduler

from modules.utils.common import (
    dict_rows,
    upsert_weather_product,
    get_wx_keys,
    get_wx_display_name,
    infer_mime_for_upload,
)
from modules.services.winlink.core import (
    send_winlink_message,
    pat_config_exists,
)

# Two blueprints so URLs are clean:
#   • /weather/ (page)
#   • /api/weather/... (catalog, blob/text, upload)
bp_page = Blueprint("weather_page", __name__, url_prefix="/weather")
bp_api  = Blueprint("weather_api",  __name__, url_prefix="/api/weather")

# Start the SAME monitor (idempotent; honors AOCT_SAME_ENABLE/… env)
try:
    same_ingest.maybe_start_same_monitor()
except Exception:
    pass

# ----------------------------- Helpers --------------------------------
def _stem(s: str) -> str:
    """
    Uppercased basename without extension. Examples:
      'WCVS.JPG' -> 'WCVS', 'wa_for_wa' -> 'WA_FOR_WA'
    """
    return os.path.splitext((s or "").strip())[0].upper()

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _extract_metar_taf_blocks(raw: str) -> tuple[list[str], str]:
    """
    Parse arbitrary email/text and pull out:
      • METAR/SPECI lines (single-line products)
      • TAF blocks (may span multiple lines; include AMD/COR; keep all lines)
    Returns (ordered_unique_station_ids, extracted_text).
    Robust to Saildocs headers/footers like the example you sent.
    """
    if not raw:
        return ([], "")
    lines = (raw.replace("\r\n", "\n").replace("\r", "\n")).split("\n")
    metars: list[str] = []
    taf_blocks: list[list[str]] = []
    ids_ordered: list[str] = []
    seen_ids: set[str] = set()

    def _add_id(sta: str):
        s = (sta or "").strip().upper()
        if re.fullmatch(r"[A-Z0-9]{3,4}", s) and s not in seen_ids:
            seen_ids.add(s); ids_ordered.append(s)

    i = 0
    N = len(lines)
    while i < N:
        ln = lines[i]
        s = ln.strip()
        if not s:
            i += 1; continue
        # METAR / SPECI — take whole line
        m = re.match(r"^(METAR|SPECI)\s+([A-Z0-9]{3,4})\b.*", s, re.IGNORECASE)
        if m:
            metars.append(s if ln == s else ln.rstrip())
            _add_id(m.group(2))
            i += 1; continue
        # TAF (with optional AMD/COR) — capture continuation lines too
        t = re.match(r"^TAF(?:\s+(?:AMD|COR))?\s+([A-Z0-9]{3,4})\b.*", s, re.IGNORECASE)
        if t:
            block: list[str] = [ln.rstrip()]
            _add_id(t.group(1))
            j = i + 1
            while j < N:
                nxt = lines[j]
                nxts = nxt.strip()
                # stop when another product starts or a hard separator appears
                if not nxts:
                    break
                if re.match(r"^(METAR|SPECI)\s+[A-Z0-9]{3,4}\b", nxts, re.IGNORECASE):
                    break
                if re.match(r"^TAF(?:\s+(?:AMD|COR))?\s+[A-Z0-9]{3,4}\b", nxts, re.IGNORECASE):
                    break
                # accept common TAF continuation starters, or any indented line
                if (nxt.startswith((" ", "\t")) or
                    re.match(r"^(FM\d{6}|TEMPO|PROB\d{2}|BECMG|NSW|TX\d{4}/\d{4}|TN\d{4}/\d{4}|RMK)\b", nxts, re.IGNORECASE)):
                    block.append(nxt.rstrip()); j += 1; continue
                # If the next line looks unrelated (headers/footers), stop.
                if re.match(r"^(Message ID:|Date:|From:|To:|Subject:|URL:|=====)", nxts):
                    break
                # Conservative: include one more neutral line then stop
                block.append(nxt.rstrip()); j += 1
                if j < N and not lines[j].strip():
                    break
            taf_blocks.append(block)
            i = j; continue
        i += 1

    # Prefer to keep exactly the aviation lines; if none found, fall back to raw
    extracted = []
    if metars:
        extracted.extend(metars)
    if taf_blocks:
        if extracted: extracted.append("")  # spacer between METAR and TAF
        for b in taf_blocks:
            extracted.extend(b)
            extracted.append("")            # blank line between TAFs
        if extracted and extracted[-1] == "":
            extracted.pop()
    if not extracted:
        return (_sanitize_ids(re.findall(r"\b[A-Z0-9]{3,4}\b", raw.upper())), raw.strip())
    return (ids_ordered, "\n".join(extracted).strip())

# ----------------------- METAR/TAF request log ------------------------
def _ensure_metar_table() -> None:
    """
    Create a tiny history table for METAR/TAF requests (idempotent).
    NOTE: hides are per-client via localStorage, per product spec.
    """
    dict_rows("""
      CREATE TABLE IF NOT EXISTS wx_metar_taf_log (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        ids              TEXT NOT NULL,           -- comma-separated ICAO list
        method           TEXT NOT NULL,           -- 'internet' | 'manual'
        raw_text         TEXT NOT NULL,           -- raw payload
        source_url       TEXT,                    -- if fetched
        fetched_at_utc   TEXT NOT NULL,           -- ISO8601
        created_at_utc   TEXT NOT NULL            -- ISO8601
      )
    """)
_ensure_metar_table()

def _extract_icao_from_line(ln: str) -> str:
    """Extract ICAO code from a METAR/SPECI/TAF line."""
    # METAR KATL 262052Z ... or TAF KATL 2620/2724 ...
    m = re.match(r"^(?:METAR|SPECI|TAF(?:\s+(?:AMD|COR))?)\s+([A-Z0-9]{3,4})\b", ln.strip(), re.IGNORECASE)
    return m.group(1).upper() if m else ""

def _try_decode_metar_taf(raw_text: str) -> str:
    """
    Best-effort plain-English summary, separated by airport.
      • For each airport: header "=== KXXX ===" followed by METAR and TAF translations
      • METAR: "Valid DD HH:MMZ — METAR: <summary>"
      • TAF:   one bullet per forecast line using AVWX's per-line summaries, each
               prefixed by the correct time label (Valid / From / TEMPO / BECMG / PROBxx).
    Falls back to concise, hand-built summaries if the library is missing.
    """
    if not raw_text:
        return ""

    # Pull out just the aviation lines/blocks first
    _ids, extracted = _extract_metar_taf_blocks(raw_text)
    text = extracted or raw_text
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")

    # Collect METAR lines and TAF blocks with their ICAO codes
    metar_by_icao: dict[str, list[str]] = {}
    taf_by_icao: dict[str, list[str]] = {}
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if not s:
            i += 1
            continue
        if s.startswith(("METAR", "SPECI")):
            icao = _extract_icao_from_line(s) or "UNKNOWN"
            metar_by_icao.setdefault(icao, []).append(s)
            i += 1
            continue
        if s.startswith("TAF"):
            j = i + 1
            cur = [lines[i].rstrip()]
            while j < len(lines) and lines[j].strip():
                cur.append(lines[j].rstrip())
                j += 1
            block = "\n".join(cur)
            icao = _extract_icao_from_line(s) or "UNKNOWN"
            taf_by_icao.setdefault(icao, []).append(block)
            i = j
            continue
        i += 1

    # Get all unique ICAO codes in order of first appearance
    all_icaos: list[str] = []
    seen_icaos: set[str] = set()
    for icao in list(metar_by_icao.keys()) + list(taf_by_icao.keys()):
        if icao not in seen_icaos:
            seen_icaos.add(icao)
            all_icaos.append(icao)

    def _fmt_dt(dt) -> str | None:
        try:
            d, h = int(getattr(dt, "day")), int(getattr(dt, "hour"))
            m = getattr(dt, "minute", None)
            if m is None:
                return f"{d:02d} {h:02d}Z"
            return f"{d:02d} {h:02d}:{int(m):02d}Z"
        except Exception:
            return None

    def _fmt_range(st, en, tag: str | None = None) -> str:
        a = _fmt_dt(st)
        b = _fmt_dt(en)
        if tag and tag.upper() == "FROM":
            return f"From {a or ''}".strip()
        if tag and tag.upper() in ("TEMPO", "BECMG") and a and b:
            return f"{tag.upper()} {a}–{b}"
        if tag and tag.upper().startswith("PROB") and a and b:
            return f"{tag.upper()} {a}–{b}"
        if a and b:
            return f"{a}–{b}"
        if a:
            return f"From {a}"
        return ""

    def _metar_valid_prefix(ln: str) -> str:
        # METAR KATL 262052Z ...
        m = re.search(r"\b(\d{2})(\d{2})(\d{2})Z\b", ln)
        if not m:
            return ""
        dd, hh, mm = map(int, m.groups())
        return f"Valid {dd:02d} {hh:02d}:{mm:02d}Z — "

    out: list[str] = []
    multiple_airports = len(all_icaos) > 1

    # ---------- Try AVWX for full decode ----------
    try:
        from avwx import Metar, Taf  # type: ignore

        for icao in all_icaos:
            airport_out: list[str] = []

            # Add airport header if multiple airports
            if multiple_airports:
                airport_out.append(f"=== {icao} ===")

            # METAR lines for this airport
            for ln in metar_by_icao.get(icao, []):
                try:
                    m = Metar.from_report(ln)  # type: ignore[attr-defined]
                    summ = (
                        getattr(m, "summary", None)
                        or getattr(m, "speech", None)
                        or ""
                    )
                    prefix = _metar_valid_prefix(ln)
                    if summ:
                        airport_out.append(f"{prefix}METAR: {summ}")
                except Exception:
                    # ignore and fall back later if needed
                    pass

            # TAF blocks for this airport
            for block in taf_by_icao.get(icao, []):
                try:
                    # Parse with AVWX; rely on its per-line `summary` list which aligns
                    # with `data.forecast` (times + type).
                    t = Taf.from_report(block)  # type: ignore[attr-defined]
                    summaries = t.summary or []
                    data = getattr(t, "data", None)
                    forecasts = list(getattr(data, "forecast", []) or [])
                    lines_out: list[str] = ["TAF:"]

                    # Pair each forecast line with its summary (if any)
                    n = max(len(forecasts), len(summaries))
                    for idx in range(n):
                        f = forecasts[idx] if idx < len(forecasts) else None
                        seg_summ = summaries[idx].strip() if idx < len(summaries) else ""

                        # Forecast window & type/tag (BASE/FM/TEMPO/BECMG/PROBxx)
                        st = getattr(f, "start_time", None)
                        en = getattr(f, "end_time", None)
                        tag = (getattr(f, "type", None) or "").upper() if f else ""
                        # Convert AVWX Timestamp -> datetime for formatter
                        st_dt = getattr(st, "dt", None) or getattr(st, "datetime", None)
                        en_dt = getattr(en, "dt", None) or getattr(en, "datetime", None)

                        # Label logic
                        label = _fmt_range(st_dt, en_dt, tag or None)
                        base_like = not tag or tag in ("", "BASE", "MAIN")
                        # The first line is the header validity window → prefix with "Valid"
                        if idx == 0 and base_like and label and "–" in label:
                            label = f"Valid {label}"
                        elif not label and seg_summ:
                            # Fallback if no times came through for some reason
                            label = "Segment"

                        bullet = ("  • " + label) if label else "  •"
                        if seg_summ:
                            bullet += f" — {seg_summ}"
                        lines_out.append(bullet.rstrip())

                    airport_out.append("\n".join(lines_out).rstrip())

                except Exception:
                    # As a last resort, keep at least the header validity window if present
                    txt = (block or "").replace("\r\n", "\n").replace("\r", "\n")
                    m = re.search(r"\b(\d{2})(\d{2})/(\d{2})(\d{2})\b", txt)
                    lines_out = ["TAF:"]
                    if m:
                        d1,h1,d2,h2 = map(int, m.groups())
                        lines_out.append(f"  • Valid {d1:02d} {h1:02d}Z–{d2:02d} {h2:02d}Z")
                    airport_out.append("\n".join(lines_out))

            if airport_out:
                out.append("\n".join(airport_out))

    except Exception:
        # Library unavailable → METAR fallback (python-metar) + bare timing for TAF
        for icao in all_icaos:
            airport_out: list[str] = []

            # Add airport header if multiple airports
            if multiple_airports:
                airport_out.append(f"=== {icao} ===")

            try:
                from metar import Metar as _Metar  # type: ignore
                for ln in metar_by_icao.get(icao, []):
                    try:
                        obs = _Metar.Metar(ln)
                        prefix = _metar_valid_prefix(ln)
                        airport_out.append(prefix + "METAR: " + obs.string())
                    except Exception:
                        pass
            except Exception:
                pass

            for block in taf_by_icao.get(icao, []):
                txt = (block or "").replace("\r\n", "\n").replace("\r", "\n")
                lines_out = ["TAF:"]
                m = re.search(r"\b(\d{2})(\d{2})/(\d{2})(\d{2})\b", txt)
                if m:
                    d1,h1,d2,h2 = map(int, m.groups())
                    lines_out.append(f"  • Valid {d1:02d} {h1:02d}Z–{d2:02d} {h2:02d}Z")
                for fm in re.findall(r"\bFM(\d{2})(\d{2})(\d{2})\b", txt):
                    d,h,mi = map(int, fm)
                    lines_out.append(f"  • From {d:02d} {h:02d}:{mi:02d}Z")
                airport_out.append("\n".join(lines_out))

            if airport_out:
                out.append("\n".join(airport_out))

    return "\n\n".join([s for s in out if s]).strip()

def _sanitize_ids(raw: List[str] | str) -> List[str]:
    """Normalize ICAO list; accept 3–4 alnum; de-dupe, preserve order."""
    if isinstance(raw, str):
        toks = re.split(r"[^A-Za-z0-9]+", raw.upper())
    else:
        toks = [str(x or "").upper() for x in raw]
    out, seen = [], set()
    for t in toks:
        t = t.strip()
        if not t: continue
        if not re.fullmatch(r"[A-Z0-9]{3,4}", t): continue
        if t in seen: continue
        seen.add(t)
        out.append(t)
    return out

def _insert_metar_record(ids: List[str], method: str, raw_text: str, source_url: str | None = None) -> int:
    ids_csv = ",".join(ids)
    now_iso = _utc_now_iso()
    dict_rows("""
      INSERT INTO wx_metar_taf_log (ids, method, raw_text, source_url, fetched_at_utc, created_at_utc)
      VALUES (?, ?, ?, ?, ?, ?)
    """, (ids_csv, method, raw_text, source_url or "", now_iso, now_iso))
    row = dict_rows("SELECT last_insert_rowid() AS id")
    return int(row[0]["id"]) if row else 0

def _maybe_decode_text(raw_text: str) -> str:
    """
    Best-effort decode to plain English:
      - Try avwx-engine if installed (METAR/TAF).
      - Else try python-metar (METAR only).
      - Else return empty string.
    """
    text = (raw_text or "").strip()
    if not text:
        return ""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    decoded_lines: List[str] = []

    # avwx-engine path
    try:
        import avwx  # type: ignore
        # We don't know station a priori per line; use from_report helpers.
        for ln in lines:
            try:
                if ln.startswith(("METAR", "SPECI")):
                    m = avwx.Metar.from_report(ln)  # type: ignore[attr-defined]
                    if m and m.translations:
                        decoded_lines.append(m.translations.get("summary", "") or m.summary or "")
                    else:
                        decoded_lines.append(m.summary if m else "")
                elif ln.startswith("TAF"):
                    t = avwx.Taf.from_report(ln)  # type: ignore[attr-defined]
                    if t and t.translations:
                        decoded_lines.append(t.translations.get("summary", "") or t.summary or "")
                    else:
                        decoded_lines.append(t.summary if t else "")
            except Exception:
                # keep going
                pass
    except Exception:
        # python-metar fallback (METAR only)
        try:
            from metar import Metar as _Metar  # type: ignore
            for ln in lines:
                try:
                    if ln.startswith(("METAR", "SPECI")):
                        obs = _Metar.Metar(ln)
                        decoded_lines.append(obs.string())  # human-readable sentence
                except Exception:
                    pass
        except Exception:
            pass

    return "\n".join([l for l in decoded_lines if l]).strip()

def _rows_to_api(rows, include_decoded: bool = False):
    out = []
    for r in rows:
        try:
            ids = [x for x in (r["ids"] or "").split(",") if x]
        except Exception:
            ids = []
        rec = {
            "id": int(r["id"]),
            "ids": ids,
            "method": r.get("method") or "",
            "raw_text": r.get("raw_text") or "",
            "source_url": r.get("source_url") or "",
            "fetched_at_utc": r.get("fetched_at_utc") or r.get("created_at_utc") or "",
        }
        if include_decoded:
            try:
                rec["decoded_text"] = _maybe_decode_text(rec["raw_text"])
            except Exception:
                rec["decoded_text"] = ""
        out.append(rec)
    return out

# ----------------------------- SAME API ------------------------------
@bp_api.get("/alerts")
def alerts():
    """
    Recent SAME alerts (decoded + raw header).
    Query params:
      - n= count (<=200)
      - include_hidden= 0|1
    """
    n = 50
    try:
        n = max(1, min(200, int(request.args.get("n", "50"))))
    except Exception:
        pass
    include_hidden = str(request.args.get("include_hidden", "0")).lower() in ("1","true","yes")
    alerts = same_ingest.same_recent(n, include_hidden=include_hidden)
    latest = alerts[0]["received_at_utc"] if alerts else same_ingest.latest_nonhidden_utc()
    return jsonify({
        "ok": True,
        "status": same_ingest.same_status(),
        "alerts": alerts,
        "latest_utc": latest,
    })

@bp_api.post("/same/start")
def same_start():
    try:
        same_ingest.maybe_start_same_monitor()
        return jsonify({"ok": True, "status": same_ingest.same_status()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@bp_api.get("/same/channels")
def same_channels():
    try:
        return jsonify({"ok": True, "channels": same_ingest.same_channels(), "status": same_ingest.same_status()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@bp_api.get("/same/stream")
def same_stream():
    """
    Stream a live channel as audio (PCM/WAV by default for easy debugging).
    Pick by ?ch=0..6 or ?port=<udp|monitor>.
    Optional: ?fmt=wav|ogg|webm (default: wav to avoid codec deps)
    """
    try:
        ch = request.args.get("ch")
        port = request.args.get("port")
        fmt = (request.args.get("fmt") or "wav").strip().lower()
        cmap = same_ingest.same_channels()
        if fmt not in ("wav", "ogg", "webm"):
            fmt = "wav"
        if ch is not None:
            i = max(0, min(6, int(ch)))
            mon = cmap[i]["monitor_port"]
        elif port is not None:
            p = int(port)
            rec = next((c for c in cmap if c["monitor_port"] == p or c["udp_port"] == p), None)
            if not rec:
                return jsonify({"ok": False, "error": "unknown port"}), 400
            mon = rec["monitor_port"]
        else:
            mon = cmap[0]["monitor_port"]

        # Use reuse=1 so a new reader can bind while the previous ffmpeg is tearing down.
        input_url = f"udp://127.0.0.1:{mon}?listen=1&reuse=1&fifo_size=1048576&overrun_nonfatal=1"
        if fmt == "wav":
            container = "wav"
            content_type = "audio/wav"
            codec_args = "-c:a pcm_s16le"
        else:
            container = "ogg" if fmt == "ogg" else "webm"
            content_type = "audio/ogg" if fmt == "ogg" else "audio/webm"
            # Use libopus when available
            codec_args = "-c:a libopus -application lowdelay -b:a 64k -frame_duration 20"

        cmd = [
            "bash", "-lc",
            (
              "ffmpeg -hide_banner -loglevel error -nostdin "
              "-fflags +nobuffer "
              f"-f {same_ingest.UDP_IN_FMT} -ar {same_ingest.UDP_IN_RATE} -ac 1 -i '{input_url}' "
              f"{codec_args} -f {container} -"
            )
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)

        # Drain stderr in the background so any ffmpeg error is visible in logs
        from threading import Thread as _T
        def _drain():
            try:
                from flask import current_app
                for chunk in iter(lambda: proc.stderr.read(1024), b""):
                    if not chunk:
                        break
                    try:
                        msg = chunk.decode("utf-8", "ignore").strip()
                    except Exception:
                        msg = ""
                    if msg:
                        current_app.logger.warning("same_stream ffmpeg: %s", msg)
            except Exception:
                pass
        _T(target=_drain, daemon=True).start()

        def _gen():
            try:
                while True:
                    chunk = proc.stdout.read(4096)
                    if not chunk:
                        break
                    yield chunk
            finally:
                try: proc.terminate()
                except Exception: pass

        headers = {
            "Content-Type": content_type,
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
        }
        return Response(stream_with_context(_gen()), headers=headers, direct_passthrough=True)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@bp_api.get("/same/diag")
def same_diag():
    """
    Probe a monitor UDP port briefly to confirm packets/levels.
    Use: /api/weather/same/diag?ch=0&ms=800   (or ?port=5651)
    Returns: {ok, port, packets, bytes, approx_rms_s16, fmt}
    """
    try:
        ch = request.args.get("ch")
        port = request.args.get("port")
        fmt = (request.args.get("fmt") or same_ingest.UDP_IN_FMT).strip().lower()
        if ch is not None:
            i = max(0, min(6, int(ch)))
            mon = same_ingest.same_channels()[i]["monitor_port"]
        elif port is not None:
            mon = int(port)
        else:
            mon = same_ingest.same_channels()[0]["monitor_port"]
        dur_ms = max(100, min(5000, int(request.args.get("ms", "800"))))

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass
        sock.bind(("127.0.0.1", mon))
        sock.setblocking(False)

        end = time.time() + (dur_ms / 1000.0)
        pkts = 0
        total = 0
        rms_acc = 0.0
        rms_n = 0
        while time.time() < end:
            r, _, _ = select.select([sock], [], [], 0.05)
            if not r:
                continue
            try:
                data, _addr = sock.recvfrom(65536)
            except BlockingIOError:
                continue
            if not data:
                continue
            pkts += 1
            total += len(data)
            # Compute approximate RMS in "s16 units" for compatibility.
            # - if fmt=f32: scale by 32768 before squaring
            # - if fmt=s16: use raw int16 values directly
            if fmt.startswith("f32"):
                n = len(data) // 4
                if n:
                    arr = array.array('f')
                    arr.frombytes(memoryview(data)[:n*4])
                    step = max(1, len(arr)//2000)
                    acc = 0.0; cnt = 0
                    for v in arr[::step]:
                        sample = float(v) * 32768.0
                        acc += sample * sample
                        cnt += 1
                    if cnt:
                        rms_acc += acc / cnt
                        rms_n += 1
            else:
                n = len(data) // 2
                if n:
                    arr = array.array('h')
                    arr.frombytes(memoryview(data)[:n*2])
                    step = max(1, len(arr)//2000)
                    acc = 0.0; cnt = 0
                    for v in arr[::step]:
                        sample = float(v)
                        acc += sample * sample
                        cnt += 1
                    if cnt:
                        rms_acc += acc / cnt
                        rms_n += 1
        try:
            sock.close()
        except Exception:
            pass
        approx_rms = float(math.sqrt(rms_acc / rms_n)) if rms_n else 0.0
        return jsonify({
            "ok": True,
            "port": mon,
            "duration_ms": dur_ms,
            "packets": pkts,
            "bytes": total,
            "fmt": fmt,
            "approx_rms_s16": round(approx_rms, 1)
        })

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@bp_api.post("/alerts/hide")
def alerts_hide():
    js = request.get_json(silent=True) or {}
    try:
        alert_id = int(js.get("id"))
        hide = bool(js.get("hide", True))
    except Exception:
        return jsonify({"ok": False, "error": "invalid payload"}), 400
    ok = same_ingest.hide_alert(alert_id, hide=hide)
    return jsonify({"ok": ok})

@bp_api.get("/alerts/head")
def alerts_head():
    return jsonify({"ok": True, "latest": same_ingest.latest_nonhidden_utc()})

@bp_api.post("/same/stop")
def same_stop():
    try:
        same_ingest.stop_same_monitor()
        return jsonify({"ok": True, "status": same_ingest.same_status()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ----------------------------- Page ---------------------------------
@bp_page.get("/")
def index():
    # Render template if present; otherwise return a tiny fallback shell.
    try:
        try:
            wl_active = (scheduler.get_job('winlink_poll') is not None)
        except Exception:
            wl_active = False
        return render_template("weather.html", active="weather",
                               winlink_job_active=wl_active)
    except TemplateNotFound:
        html = """
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Weather</title></head>
  <body>
    <h1>Weather</h1>
    <p>This is a placeholder page. Add <code>templates/weather.html</code> for a full UI.</p>
  </body>
</html>"""
        resp = make_response(html, 200)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        return resp


# ----------------------------- API ----------------------------------
@bp_api.get("/catalog")
def catalog():
    # Normalize configured keys to canonical stems (e.g., WCVS.JPG -> WCVS)
    keys_cfg = list(get_wx_keys() or [])
    wanted = list(dict.fromkeys([_stem(k) for k in keys_cfg]))  # order-preserving de-dupe

    if wanted:
        qmarks = ",".join("?" * len(wanted))
        sql = f"""
          SELECT key, display_name, mime, content_hash AS etag, source,
                 received_at_utc, updated_at_utc
            FROM weather_products
           WHERE key IN ({qmarks})
        """
        rows = dict_rows(sql, tuple(wanted))
    else:
        rows = dict_rows("""
          SELECT key, display_name, mime, content_hash AS etag, source,
                 received_at_utc, updated_at_utc
            FROM weather_products
        """)

    by_key = { _stem(r.get("key")): r for r in rows }
    out = []
    for k in (wanted or []):
        r = by_key.get(_stem(k))
        if r:
            out.append({
                "key": r["key"],
                "display_name": r["display_name"],
                "mime": r["mime"],
                "received_at_utc": r["received_at_utc"],
                "updated_at_utc": r["updated_at_utc"],
                "etag": f"sha256:{r['etag']}" if r.get("etag") else "",
                "source": r.get("source", ""),
            })
        else:
            out.append({
                "key": k,
                "display_name": get_wx_display_name(k),
                "mime": "",
                "received_at_utc": "",
                "updated_at_utc": "",
                "etag": "",
                "source": "",
            })
    return jsonify(out)


@bp_api.get("/blob/<path:key>")
def blob(key):
    # Accept either canonical key or filename with extension
    k = _stem(key)
    rows = dict_rows("SELECT mime, content, content_hash FROM weather_products WHERE key=?", (k,))
    if not rows:
        abort(404)
    r = rows[0]
    resp = make_response(r["content"])
    resp.headers["Content-Type"] = r["mime"] or "application/octet-stream"
    resp.headers["ETag"] = f"sha256:{r['content_hash']}"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp_api.get("/text/<path:key>")
def text(key):
    # Accept either canonical key or filename with extension
    k = _stem(key)
    rows = dict_rows("SELECT content, mime FROM weather_products WHERE key=?", (k,))
    if not rows:
        abort(404)
    r = rows[0]
    if not (r["mime"] or "").startswith("text/"):
        abort(415)
    try:
        body = (r["content"] or b"").decode("utf-8", errors="replace")
    except Exception:
        body = ""
    resp = make_response(body)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp_api.post("/upload")
def upload():
    """
    Authenticated upload into a specific slot via form field `key`.
    Filename does not need to match the slot; we infer MIME safely.
    """
    f = request.files.get("file")
    # Allow users to submit either 'WCVS' or 'WCVS.JPG' for the slot key
    key = _stem(request.form.get("key") or "")
    if not f or not key:
        abort(400)

    data = f.read(12 * 1024 * 1024)  # 12 MiB guardrail
    fname = secure_filename(f.filename or "")
    mime = infer_mime_for_upload(fname, data)

    # Slot-specific constraints
    if key == "WA_FOR_WA":
        mime = "text/plain"
    else:
        # Allow images or (optionally) plain text for other keys.
        if not (mime.startswith("image/") or mime == "text/plain"):
            abort(415)

    info = upsert_weather_product(key, data, mime, source="manual")
    return jsonify({"ok": True, **info})

def _canon_wx_key(raw: str) -> tuple[str, str]:
    """
    Map any incoming token to (product_id, wire_key).
    - product_id: canonical stem used for de-duplication (e.g., 'WCVS')
    - wire_key  : what we actually send in the INQUIRY body (e.g., 'WCVS.JPG')
    """
    s = (raw or "").strip().upper()
    stem = os.path.splitext(s)[0]  # 'WCVS.JPG' → 'WCVS'
    # Known canonical filenames expected by the service:
    mapping = {
        "WCVS":       "WCVS.JPG",      # GOES West visible sector
        "WCIR":       "WCIR.JPG",      # GOES West IR sector
        "USWXRAD":    "USWXRAD.GIF",   # US composite radar
        "WA_FOR_WA":  "WA_FOR_WA",     # Spokane AFD/forecast text
    }
    wire = mapping.get(stem, s)
    return stem, wire

def _catalog_keys_from_request() -> List[str]:
    """
    Read keys from JSON ('keys') or fall back to configured catalog.
    Normalize → de-duplicate by product_id → return canonical wire-keys in order.
    """
    try:
        js = request.get_json(silent=True) or {}
    except Exception:
        js = {}
    raw = js.get("keys") or []
    if not isinstance(raw, list):
        raw = []
    keys = [ (str(k or "").strip().upper()) for k in raw if (k or "").strip() ]
    if not keys:
        keys = list(get_wx_keys() or [])

    out, seen = [], set()
    for k in keys:
        pid, wire = _canon_wx_key(k)
        if not pid:
            continue
        if pid in seen:
            continue
        seen.add(pid)
        out.append(wire)
    return out

def _build_messages(keys: List[str], split: bool, to_addr: str) -> List[Dict[str,str]]:
    """
    Return a list of {to, subject, body} payloads. If split=True, one per key.
    Body spec: one key per line (even when split) for consistency.
    """
    subj = "REQUEST"
    if not split:
        body = "\n".join(keys)
        return [{"to": to_addr, "subject": subj, "body": body}]
    msgs = []
    for k in keys:
        msgs.append({"to": to_addr, "subject": subj, "body": k})
    return msgs

@bp_api.post("/request")
def request_updates():
    """
    Request weather products.
      JSON:
        { "mode": "pat" | "preview",
          "split": true|false,           # default true (one message per product)
          "to": "INQUIRY",               # optional recipient
          "keys": ["WCCOL.JPG", ...] }   # optional; defaults to configured catalog
    - mode=preview → returns list of {to,subject,body} without sending.
    - mode=pat     → sends via PAT; returns per-message status.
    """
    js = request.get_json(silent=True) or {}
    mode  = (js.get("mode") or "pat").strip().lower()
    split = bool(js.get("split", True))
    to    = (js.get("to") or "INQUIRY").strip().upper()
    async_send = bool(js.get("async", True))  # default: async to avoid DB stalls
    keys  = _catalog_keys_from_request()

    # Nothing to request
    if not keys:
        return jsonify({"ok": False, "error": "no keys specified"}), 400

    # Log exactly what we'll send (helps confirm canonicalization/dedupe)
    try:
        from flask import current_app
        current_app.logger.info("WX request: to=%s split=%s keys=%s", to, split, keys)
    except Exception:
        pass

    msgs = _build_messages(keys, split, to)
    if mode == "preview":
        return jsonify({"ok": True, "messages": msgs, "count": len(msgs)})

    # mode=pat → only when poller is running, and PAT is configured
    if mode == "pat":
        try:
            if scheduler.get_job('winlink_poll') is None:
                return jsonify({"ok": False, "error": "WinLink polling not running"}), 503
        except Exception:
            return jsonify({"ok": False, "error": "WinLink scheduler unavailable"}), 503
        if not pat_config_exists():
            return jsonify({"ok": False, "error": "PAT not configured"}), 503

    ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Light idempotency guard (prevents double-click duplicates within ~3s)
    # We keep the response shape stable ('mode': 'pat_async') so the UI text stays sane.
    sig_payload = {"to": to, "split": split, "keys": keys}
    req_sig = hashlib.sha256(json.dumps(sig_payload, sort_keys=True).encode()).hexdigest()
    _guard = getattr(request_updates, "_last_req", {"sig": None, "ts": 0.0})
    now_s = time.time()
    if _guard.get("sig") == req_sig and (now_s - float(_guard.get("ts", 0.0))) < 3.0:
        setattr(request_updates, "_last_req", {"sig": req_sig, "ts": now_s})
        return jsonify({"ok": True, "requested_at": ts, "enqueued": 0, "mode": "pat_async", "dupe": True})
    setattr(request_updates, "_last_req", {"sig": req_sig, "ts": now_s})

    if async_send:
        # Fire-and-forget to avoid holding the HTTP request or any DB handle.
        def _worker(batch):
            for m in batch:
                try:
                    send_winlink_message(m["to"], m["subject"], m["body"])
                except Exception:
                    pass
        Thread(target=_worker, args=(msgs,), daemon=True).start()
        return jsonify({"ok": True, "requested_at": ts, "enqueued": len(msgs), "mode": "pat_async"})
    else:
        # Synchronous path (legacy behavior; can cause long waits if PAT is slow)
        results = []
        any_ok = False
        for m in msgs:
            try:
                ok = bool(send_winlink_message(m["to"], m["subject"], m["body"]))
                any_ok = any_ok or ok
                results.append({"to": m["to"], "subject": m["subject"], "ok": ok})
            except Exception as e:
                results.append({"to": m["to"], "subject": m["subject"], "ok": False, "error": str(e)})
        return jsonify({"ok": any_ok, "requested_at": ts, "results": results, "count": len(results), "mode": "pat_sync"})


# --------------------------- NEW: METAR/TAF API -----------------------
@bp_api.post("/metar_taf/fetch")
def metar_taf_fetch():
    """Fetch METAR/TAF from aviationweather.gov and store raw text."""
    js = request.get_json(silent=True) or {}
    ids = _sanitize_ids(js.get("ids") or [])
    if not ids:
        return jsonify({"ok": False, "error": "no ICAO ids"}), 400
    try:
        q = { "ids": ",".join(ids), "hours": "0", "sep": "true", "taf": "true" }
        url = "https://aviationweather.gov/api/data/metar?" + urllib.parse.urlencode(q)
        req = urllib.request.Request(url, headers={"User-Agent":"AOCT/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            body = r.read().decode("utf-8", "replace")
        rec_id = _insert_metar_record(ids, "internet", body, source_url=url)
        return jsonify({"ok": True, "id": rec_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@bp_api.post("/metar_taf/store")
def metar_taf_store():
    """Store a pasted METAR/TAF response (tolerates whole emails)."""
    js = request.get_json(silent=True) or {}
    raw = (js.get("raw_text") or "").strip()
    if not raw:
        return jsonify({"ok": False, "error": "empty raw_text"}), 400
    ids, extracted = _extract_metar_taf_blocks(raw)
    if not ids:
        # Fall back to any tokens if we truly couldn't find products
        ids = _sanitize_ids(re.findall(r"\b[A-Z0-9]{3,4}\b", raw.upper()))
    rec_id = _insert_metar_record(ids, "manual", extracted or raw, source_url=None)
    return jsonify({"ok": True, "id": rec_id})

@bp_api.get("/metar_taf/list")
def metar_taf_list():
    """
    Recent METAR/TAF request history.
    Optional: ?n=50 (<=200), ?decode=0|1 (include plain-English if libs available)
    (also accepts ?translate=1 for compatibility)
    """
    try:
        n = int(request.args.get("n", "50"))
    except Exception:
        n = 50
    n = max(1, min(200, n))
    want_decode = str(request.args.get("decode", request.args.get("translate", "0"))).lower() in ("1","true","yes")
    rows = dict_rows("""
      SELECT id, ids, method, raw_text, source_url, fetched_at_utc, created_at_utc
        FROM wx_metar_taf_log
       ORDER BY id DESC
       LIMIT ?
    """, (n,))
    items = _rows_to_api(rows)
    if want_decode:
        for it in items:
            try:
                it["plain"] = _try_decode_metar_taf(it.get("raw_text") or "")
            except Exception:
                it["plain"] = ""
    return jsonify({"ok": True, "items": items})

# NOTE: Winlink polling status is already available at /radio/winlink/poller_status
# (see modules/routes/radio.py). The weather page timer uses that existing endpoint.
