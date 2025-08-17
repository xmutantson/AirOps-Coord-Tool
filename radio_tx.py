# radio_tx.py
import os, json, time, subprocess, threading, tempfile, shutil, base64, zlib, random
from typing import Callable, Dict, Any, List, Iterable, Tuple

# ---- ENV / knobs ----
KISS_HOST          = os.getenv("KISS_HOST", "127.0.0.1")
KISS_PORT          = int(os.getenv("KISS_PORT", "8001"))
MYCALL             = os.getenv("MYCALL") or os.getenv("AX25_CALLSIGN", "N0CALL")
DEST               = os.getenv("AX25_DEST", "AOCTDB")[:6]
PATH               = os.getenv("AX25_PATH", "")
FULL_INTERVAL_SEC  = int(os.getenv("FULL_INTERVAL_SEC", "900"))   # 15 minutes
DIFF_INTERVAL_SEC  = int(os.getenv("DIFF_INTERVAL_SEC", "30"))    # 30 seconds
CHUNK_BYTES        = int(os.getenv("CHUNK_BYTES", "200"))         # per-frame payload AFTER encoding
PACE_MS            = int(os.getenv("PACE_MS", "350"))             # ms between files in a burst
BURST_SIZE         = int(os.getenv("BURST_SIZE", "6"))            # frames per kissutil session
BURST_PAUSE_MS     = int(os.getenv("BURST_PAUSE_MS", "750"))      # pause between bursts
KISS_WARMUP_MS     = int(os.getenv("KISS_WARMUP_MS", "250"))      # ms before first file after starting kissutil
KISS_VERBOSE       = os.getenv("KISS_VERBOSE", "0") == "1"
COMPRESS           = os.getenv("COMPRESS", "1") == "1"
ENCODING           = (os.getenv("ENCODING", "B91") or "B91").upper()  # B91 or B64

# ---- tiny base91 encoder (encode only; client decodes) ----
_B91_ENC = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "!#$%&()*+,./:;<=>?@[]^_`{|}~\""
)
def _b91_encode(b: bytes) -> str:
    v = 0; n = 0; out: List[str] = []
    for c in b:
        v |= c << n
        n += 8
        while n > 13:
            x = v & 8191
            if x > 88:
                v >>= 13; n -= 13
            else:
                x = v & 16383
                v >>= 14; n -= 14
            out.append(_B91_ENC[x % 91]); out.append(_B91_ENC[x // 91])
    if n:
        out.append(_B91_ENC[v % 91])
        if n > 7 or v > 90:
            out.append(_B91_ENC[v // 91])
    return "".join(out)

# ---- helpers ----
def _session_id() -> str:
    # 4-char base32-ish (digits + A–V). Collisions across long time are acceptable.
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    return "".join(random.choice(alphabet) for _ in range(4))

def _format_tnc2(dest: str | None, src: str | None, path: str | None, payload: str) -> str:
    """
    Build a TNC2 frame line. Tolerates None for dest/src/path to avoid crashes
    if callers pass through unset env vars.
    """
    d = (dest or "").strip() or "N0CALL"
    s = (src  or "").strip() or "N0CALL"
    p = (path or "").strip()
    hdr = f"{d}>{s}" + (f",{p}" if p else "")
    return f"{hdr}:{payload}\r\n"  # CRLF for kissutil line parsing

def _chunks(s: str, n: int) -> Iterable[str]:
    for i in range(0, len(s), n):
        yield s[i:i+n]

def _compact(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    RF object per flight (matches client table expectations):
      i,t,d,p,s,c,et,al,at,re,nt  plus optional pc,ct,cw,rm
    nt (needs tx) := (re==1 and s==0)
    """
    out: Dict[str, Any] = {}
    for r in rows:
        fid = r.get("id")
        if fid is None:
            continue
        s  = int(r.get("sent") or 0)
        c  = int(r.get("complete") or 0)
        re = int(r.get("is_ramp_entry") or 0)
        nt = 1 if (re == 1 and s == 0) else 0
        obj = {
            "i": fid,
            "t": r.get("tail_number") or "",
            "d": r.get("direction") or "",
            "p": r.get("pilot_name") or "",
            "s": s,
            "c": c,
            "et": r.get("eta") or "",
            "al": r.get("airfield_landing") or "",
            "at": r.get("airfield_takeoff") or "",
            "re": re,
            "nt": nt,
        }
        if r.get("pax_count"):    obj["pc"] = r.get("pax_count")
        if r.get("cargo_type"):   obj["ct"] = r.get("cargo_type")
        if r.get("cargo_weight"): obj["cw"] = r.get("cargo_weight")
        if r.get("remarks"):      obj["rm"] = r.get("remarks")
        out[str(fid)] = obj
    return out

def _diff(prev: Dict[str, Any], cur: Dict[str, Any]) -> Dict[str, Any]:
    delta: Dict[str, Any] = {"u": {}, "rm": []}
    for k, v in cur.items():
        pv = prev.get(k)
        if pv != v:
            if isinstance(pv, dict) and isinstance(v, dict):
                changed = {fk: fv for fk, fv in v.items() if pv.get(fk) != fv}
                changed["i"] = v.get("i")
                delta["u"][k] = changed
            else:
                delta["u"][k] = v
    for k in prev.keys() - cur.keys():
        delta["rm"].append(k)
    return delta

def _fetch_rows(fetch_rows_fn: Callable[[str, tuple], list]) -> List[Dict[str, Any]]:
    sql = """
      SELECT *
        FROM flights
       ORDER BY
         CASE
           WHEN sent=0     THEN 0
           WHEN complete=0 THEN 1
           ELSE 2
         END,
         id DESC
       LIMIT 20
    """
    return fetch_rows_fn(sql, ())

# ---- KISS burst sender (FIFO-style) ----
def _send_burst_stream(frames: List[str]) -> None:
    if not frames:
        return
    txdir = tempfile.mkdtemp(prefix="kiss_burst_")
    try:
        cmd = ["kissutil", "-h", str(KISS_HOST), "-p", str(KISS_PORT), "-f", txdir]
        if KISS_VERBOSE:
            cmd.append("-v")
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        time.sleep(KISS_WARMUP_MS / 1000.0)
        for i, line in enumerate(frames, start=1):
            path = os.path.join(txdir, f"{i:03d}.txt")
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(line); f.flush(); os.fsync(f.fileno())
            time.sleep(PACE_MS / 1000.0)
        time.sleep(max(150, PACE_MS // 2) / 1000.0)
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        shutil.rmtree(txdir, ignore_errors=True)

# ---- encoding helper (payload only) ----
def _encode_payload(obj: Dict[str, Any]) -> Tuple[str, str]:
    """
    Returns (encoding_flag, text) where:
      - "Z": zlib + base91 (ENCODING=B91 and COMPRESS=1)
      - "B": zlib + base64 (ENCODING=B64 and COMPRESS=1, or fallback)
      - "J": plain JSON text (COMPRESS=0)
    The returned 'text' is what gets split into CHUNK_BYTES and put in frames.
    """
    if not COMPRESS:
        return "J", json.dumps(obj, separators=(",", ":"))

    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    z = zlib.compress(raw, level=9)

    if ENCODING in ("B91", "91", "BASE91"):
        try:
            return "Z", _b91_encode(z)
        except Exception as e:
            print(f"[radio_tx] base91 encode failed ({e}); falling back to base64")
            return "B", base64.b64encode(z).decode("ascii")

    # default to base64
    return "B", base64.b64encode(z).decode("ascii")

# ---- TX loop (15-min fulls, ≤30s diffs) ----
def tx_loop(fetch_rows_fn: Callable[[str, tuple], list]):
    prev_snapshot: Dict[str, Any] = {}
    session_sid: str | None = None
    last_full = 0.0
    last_diff = 0.0

    while True:
        try:
            now = time.time()
            need_full = (now - last_full) >= FULL_INTERVAL_SEC or not prev_snapshot
            need_diff = (now - last_diff) >= DIFF_INTERVAL_SEC and not need_full

            rows = _fetch_rows(fetch_rows_fn)
            cur  = _compact(rows)

            if need_full:
                session_sid = _session_id()
                body_obj = {"full": True, "fl": cur}
                enc_flag, blob = _encode_payload(body_obj)
                parts = list(_chunks(blob, CHUNK_BYTES)) or [""]
                total = len(parts)

                frames: List[str] = []
                for seq, part in enumerate(parts, start=1):
                    # AOT <seq>/<total>|F|<sid>|<J|Z|B>|<chunk>
                    msg = f"AOT {seq}/{total}|F|{session_sid}|{enc_flag}|{part}"
                    frames.append(_format_tnc2(DEST, MYCALL, PATH, msg))

                i = 0
                while i < len(frames):
                    j = min(i + BURST_SIZE, len(frames))
                    _send_burst_stream(frames[i:j])
                    i = j
                    if i < len(frames):
                        time.sleep(BURST_PAUSE_MS / 1000.0)

                prev_snapshot = cur
                last_full = now
                last_diff = now  # reset diff cadence after a full

            elif need_diff:
                df = _diff(prev_snapshot, cur)
                if df["u"] or df["rm"]:
                    body_obj = {"full": False, "df": df}
                    enc_flag, blob = _encode_payload(body_obj)
                    parts = list(_chunks(blob, CHUNK_BYTES)) or [""]
                    total = len(parts)
                    sid = session_sid or _session_id()

                    frames: List[str] = []
                    for seq, part in enumerate(parts, start=1):
                        # AOT <seq>/<total>|D|<sid>|<J|Z|B>|<chunk>
                        msg = f"AOT {seq}/{total}|D|{sid}|{enc_flag}|{part}"
                        frames.append(_format_tnc2(DEST, MYCALL, PATH, msg))

                    i = 0
                    while i < len(frames):
                        j = min(i + BURST_SIZE, len(frames))
                        _send_burst_stream(frames[i:j])
                        i = j
                        if i < len(frames):
                            time.sleep(BURST_PAUSE_MS / 1000.0)

                    prev_snapshot = cur
                # Even if diff was empty, we update the timer so we don't hammer every loop.
                last_diff = now

        except Exception as e:
            print(f"[radio_tx] loop error: {e}")

        # Sleep until the next smallest deadline (cap 5s for responsiveness)
        now = time.time()
        t_full = FULL_INTERVAL_SEC - (now - last_full)
        t_diff = DIFF_INTERVAL_SEC - (now - last_diff)
        next_wait = max(0.0, min(t_full, t_diff))
        time.sleep(min(next_wait, 5.0))

def start_radio_tx(fetch_rows_fn: Callable[[str, tuple], list]):
    threading.Thread(target=tx_loop, args=(fetch_rows_fn,), daemon=True).start()
