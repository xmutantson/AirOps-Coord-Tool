from __future__ import annotations
import os, re, json, time, threading, subprocess, shlex, logging, tempfile, textwrap, signal, socket, fcntl, shutil
from datetime import datetime, timezone
from typing import Optional, List, Dict
from modules.utils.common import connect, get_db_file  # traced sqlite wrapper + app DB path

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Config (env)
SAME_ENABLE        = os.getenv("AOCT_SAME_ENABLE", "0").lower() in ("1","true","yes")
SAME_MODE          = os.getenv("AOCT_SAME_MODE", "rtl_fm").strip().lower()  # 'rtl_fm' | 'udp' | 'airband'
SAME_SERIAL        = os.getenv("AOCT_SAME_SERIAL", "978").strip()
# Prefer index=1 by default (device 0 is spoken for on this platform).
# You can still override with AOCT_SAME_INDEX explicitly.
SAME_INDEX         = os.getenv("AOCT_SAME_INDEX", "1").strip()
SAME_GAIN          = os.getenv("AOCT_SAME_GAIN", "38.6").strip()
SAME_FREQ          = float(os.getenv("AOCT_SAME_FREQ", "162.550"))
SAME_START_DELAY   = int(os.getenv("AOCT_SAME_START_DELAY", "30"))  # defer start to avoid double-boot clashes

# UDP mapping like: "5551:162.400,5552:162.425,..." (used by SAME_MODE='udp')
SAME_UDP_MAP       = os.getenv("AOCT_SAME_UDP", "").strip()

# Keep last N alerts in memory for quick GET
MEM_CACHE_LIMIT    = int(os.getenv("AOCT_SAME_CACHE", "200"))
DEDUPE_SEC         = int(os.getenv("AOCT_SAME_DEDUPE_SEC", "60"))
UDP_BASE_PORT      = int(os.getenv("AOCT_SAME_UDP_BASE", "5551"))

# Input format/rate coming from rtl_airband → UDP.
# Preferred modern setup (udp_stream): f32le@16000 (rtl_airband NFM build)
# Legacy fallback (udp):               s16le@22050 (explicitly configured)
UDP_IN_FMT         = os.getenv("AOCT_SAME_UDP_FMT", "f32le").strip().lower()  # "f32le" or "s16le"
UDP_IN_RATE        = int(os.getenv("AOCT_SAME_UDP_RATE", "16000"))

# Monitor (listen) mirror ports: 5551..5557 → 5651..5657 by default.
# Support both env names for backward compatibility:
#   AOCT_SAME_MONITOR_BASE (new) or AOCT_SAME_MON_BASE (legacy)
MONITOR_BASE       = int(os.getenv("AOCT_SAME_MONITOR_BASE", os.getenv("AOCT_SAME_MON_BASE", "5651")))

# rtl_airband controls
#   AIRBAND_UDP_TYPE: preferred output type (auto-fallback handled at runtime)
#     "udp_stream" → modern (float32@16k), keys dest_address/dest_port
#     "udp"        → legacy (we set s16le@22050), keys address/port
#   AIRBAND_MODE_OPT: optional device mode (omitted by default)
AIRBAND_UDP_TYPE   = os.getenv("AOCT_SAME_AIRBAND_UDP_TYPE", "udp_stream").strip().lower()
AIRBAND_MODE_OPT   = (os.getenv("AOCT_SAME_AIRBAND_MODE") or "").strip().lower()  # "", "multichannel", "scan"

# Keep squelch permanently open in multichannel mode by using a very low manual threshold.
# Override with AOCT_SAME_SQUELCH_DBFS if needed.
# NOTE: rtl_airband rejects floats here. Use an int, and render with parentheses.
SQUELCH_DBFS       = int(float(os.getenv("AOCT_SAME_SQUELCH_DBFS", "-90")))

# Cross-process singleton & lifecycle controls
LOCK_PATH          = os.getenv("AOCT_SAME_LOCK_FILE", "/tmp/aoct-same.lock")
PID_PATH           = os.getenv("AOCT_SAME_PID_FILE",  "/tmp/aoct-same.pid")
TAKEOVER           = os.getenv("AOCT_SAME_TAKEOVER", "1").lower() in ("1","true","yes")  # second wins
KILL_GRACE_SEC     = float(os.getenv("AOCT_SAME_KILL_GRACE", "1.0"))

# Tools for stdout line-buffering
_HAS_STDBUF = shutil.which("stdbuf") is not None
_HAS_SCRIPT = shutil.which("script") is not None  # util-linux

# 7 NOAA WX freqs
NOAA_WX = [162.400, 162.425, 162.450, 162.475, 162.500, 162.525, 162.550]

# ──────────────────────────────────────────────────────────────────────────────
# Channel/port helpers (for UI + monitor stream)
def _port_index_for_udp(port: int) -> int:
    return int(port) - int(UDP_BASE_PORT)

def _monitor_port_for_udp(port: int) -> int:
    return MONITOR_BASE + _port_index_for_udp(port)

def _channel_map() -> List[Dict]:
    return [
        {"ch": i, "freq_mhz": f, "udp_port": UDP_BASE_PORT + i, "monitor_port": MONITOR_BASE + i}
        for i, f in enumerate(NOAA_WX)
    ]

# ──────────────────────────────────────────────────────────────────────────────
# DB
def _ensure_schema():
    with connect(get_db_file()) as db:
        db.execute("""
        CREATE TABLE IF NOT EXISTS same_alerts (
            id INTEGER PRIMARY KEY,
            received_at_utc TEXT NOT NULL,
            source TEXT,
            frequency_mhz REAL,
            header TEXT NOT NULL,
            decoded_json TEXT,
            UNIQUE(header, received_at_utc, source) ON CONFLICT IGNORE
        )""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_same_rx ON same_alerts(received_at_utc DESC)")
        db.commit()

    # Soft-delete / hide flag (idempotent migration)
    try:
        with connect(get_db_file()) as db:
            db.execute("ALTER TABLE same_alerts ADD COLUMN is_hidden INTEGER DEFAULT 0")
            db.commit()
    except Exception:
        pass

def _insert_alert(rec: Dict):
    _ensure_schema()
    with connect(get_db_file()) as db:
        db.execute("""INSERT OR IGNORE INTO same_alerts
            (received_at_utc, source, frequency_mhz, header, decoded_json)
            VALUES (?,?,?,?,?)""",
            (rec["received_at_utc"], rec.get("source",""), rec.get("frequency_mhz"),
             rec["header"], json.dumps(rec.get("decoded", {}), ensure_ascii=False)))
        db.commit()

def get_recent_alerts(limit: int = 50, include_hidden: bool = False) -> List[Dict]:
    _ensure_schema()
    with connect(get_db_file()) as db:
        rows = db.execute("""
            SELECT id, received_at_utc, source, frequency_mhz, header, decoded_json,
                   COALESCE(is_hidden,0) AS is_hidden
              FROM same_alerts
             WHERE (? = 1 OR COALESCE(is_hidden,0) = 0)
             ORDER BY received_at_utc DESC LIMIT ?""",
             (1 if include_hidden else 0, limit)).fetchall()
    out = []
    for r in rows:
        try: dec = json.loads(r[5] or "{}")
        except Exception: dec = {}
        out.append({
            "id": r[0],
            "received_at_utc": r[1],
            "source": r[2], "frequency_mhz": r[3],
            "header": r[4], "decoded": dec,
            "is_hidden": bool(r[6]),
        })
    return out

# ──────────────────────────────────────────────────────────────────────────────
# De-duplication
_dedupe_lock = threading.Lock()
_dedupe_seen : Dict[str, float] = {}  # header -> epoch seconds last seen

def _is_dup_recent(header: str, ts_epoch: float) -> bool:
    now = ts_epoch
    win_start = now - max(1, DEDUPE_SEC)
    with _dedupe_lock:
        last = _dedupe_seen.get(header)
        if last is not None and last >= win_start:
            return True
    iso_low = datetime.fromtimestamp(win_start, tz=timezone.utc).isoformat().replace("+00:00","Z")
    iso_hi  = datetime.fromtimestamp(now, tz=timezone.utc).isoformat().replace("+00:00","Z")
    with connect(get_db_file()) as db:
        row = db.execute("""SELECT 1 FROM same_alerts
                             WHERE header=? AND received_at_utc BETWEEN ? AND ? LIMIT 1""",
                          (header, iso_low, iso_hi)).fetchone()
    return bool(row)

# ──────────────────────────────────────────────────────────────────────────────
# Opportunistic SAME header decode
def _decode_with_dsame(header: str) -> Dict:
    try:
        from dsame3_simple.dsame import same_decode_string
        dec = same_decode_string(header.strip())
        if isinstance(dec, dict): return dec
        return {"text": str(dec)}
    except Exception as e:
        return {"error": str(e)}

# ──────────────────────────────────────────────────────────────────────────────
# Soft delete helpers
def hide_alert(alert_id: int, hide: bool = True) -> bool:
    _ensure_schema()
    with connect(get_db_file()) as db:
        db.execute("UPDATE same_alerts SET is_hidden=? WHERE id=?", (1 if hide else 0, int(alert_id)))
        db.commit()
        return db.total_changes > 0

def latest_nonhidden_utc() -> str:
    with connect(get_db_file()) as db:
        row = db.execute("SELECT received_at_utc FROM same_alerts WHERE COALESCE(is_hidden,0)=0 ORDER BY received_at_utc DESC LIMIT 1").fetchone()
    return row[0] if row else ""

# ──────────────────────────────────────────────────────────────────────────────
# Cross-process helpers
def _udp_port_free(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()

def _write_pidfile(pid: int):
    try:
        with open(PID_PATH, "w") as fh:
            fh.write(str(pid))
    except Exception:
        pass

def _read_pidfile() -> Optional[int]:
    try:
        with open(PID_PATH, "r") as fh:
            pid = int((fh.read() or "").strip())
            return pid if pid > 1 else None
    except Exception:
        return None

def _kill_pgid_of(pid: int):
    try:
        pgid = os.getpgid(pid)
    except Exception:
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except Exception:
        pass

def _acquire_lock() -> Optional[int]:
    """Return an open FD with exclusive flock held, or None if busy."""
    fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BlockingIOError:
        os.close(fd)
        return None

def _acquire_lock_or_takeover() -> Optional[int]:
    fd = _acquire_lock()
    if fd is not None:
        return fd
    if not TAKEOVER:
        log.info("SAME: another instance holds lock; not taking over")
        return None
    owner = _read_pidfile()
    if owner:
        log.info("SAME: taking over from pid=%s", owner)
        _kill_pgid_of(owner)
        time.sleep(KILL_GRACE_SEC)
    fd = _acquire_lock()
    if fd is None:
        log.warning("SAME: takeover failed; lock still held")
    return fd

# ──────────────────────────────────────────────────────────────────────────────
# Workers
class _LineReader(threading.Thread):
    def __init__(self, label: str, proc: subprocess.Popen, freq: Optional[float]):
        super().__init__(name=f"SAME-{label}", daemon=True)
        self.label = label
        self.proc = proc
        self.freq = freq

    def run(self):
        while True:
            line = self.proc.stdout.readline()
            if not line:
                rc = self.proc.poll()
                if rc is not None:
                    log.warning("SAME pipeline '%s' exited rc=%s", self.label, rc)
                    break
                time.sleep(0.05)
                continue
            try:
                s = line.decode("utf-8", "ignore").strip()
            except Exception:
                continue

            # ---- ACCEPT ANYTHING THAT CONTAINS 'ZCZC' ----
            idx = s.find("ZCZC")
            if idx == -1:
                continue

            # Take everything from ZCZC to end-of-line (as requested).
            header = s[idx:].strip()

            # Opportunistic decode; but we will store regardless of decode result.
            dec = _decode_with_dsame(header)

            dt = datetime.now(timezone.utc)
            ts = dt.isoformat().replace("+00:00","Z")
            ts_epoch = dt.timestamp()

            if _is_dup_recent(header, ts_epoch):
                log.info("SAME %s %.3f: duplicate within %ss, suppressed: %s",
                         self.label, (self.freq or 0.0), DEDUPE_SEC, header)
                continue

            rec = {
                "received_at_utc": ts,
                "source": self.label,
                "frequency_mhz": self.freq,
                "header": header,
                "decoded": dec
            }
            _insert_alert(rec)
            _MemoryCache.append(rec)
            with _dedupe_lock:
                _dedupe_seen[header] = ts_epoch
            log.info("SAME %s %.3f: %s", self.label, (self.freq or 0.0), header)

class _StderrDrain(threading.Thread):
    """Drain a subprocess' stderr so buffers don’t fill and so we can surface errors."""
    def __init__(self, label: str, proc: subprocess.Popen, level=logging.WARNING):
        super().__init__(name=f"SAME-ERR-{label}", daemon=True)
        self.label = label
        self.proc = proc
        self.level = level

    def run(self):
        if not self.proc.stderr:
            return
        for raw in iter(self.proc.stderr.readline, b""):
            try:
                line = raw.decode("utf-8", "ignore").strip()
            except Exception:
                continue
            if not line:
                continue
            log.log(self.level, "SAME [%s] stderr: %s", self.label, line)

class _MemoryCache:
    _buf: List[Dict] = []
    _lock = threading.Lock()

    @classmethod
    def append(cls, rec):
        with cls._lock:
            cls._buf.insert(0, rec)
            if len(cls._buf) > MEM_CACHE_LIMIT:
                del cls._buf[MEM_CACHE_LIMIT:]

    @classmethod
    def recent(cls, n=50):
        with cls._lock:
            return cls._buf[:n]

# ──────────────────────────────────────────────────────────────────────────────
# Manager
class SameManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.workers : List[_LineReader] = []
        self.procs   : List[subprocess.Popen] = []
        self._pgids  : List[int] = []             # process groups we manage
        self.running = False

        # Deferred start control
        self._start_timer: Optional[threading.Timer] = None
        self._start_lock = threading.Lock()

        # Cross-process lock FD
        self._lock_fd: Optional[int] = None

    # ---------- Deferred start orchestration ----------
    def schedule_start(self, delay: Optional[int] = None):
        """Schedule a one-shot start after `delay` seconds (idempotent)."""
        if delay is None:
            delay = max(0, int(SAME_START_DELAY))
        with self._start_lock:
            if self.running:
                log.debug("SAME: already running; schedule_start ignored")
                return
            if self._start_timer and self._start_timer.is_alive():
                log.debug("SAME: start already scheduled; schedule_start ignored")
                return
            def _go():
                try:
                    self.start()
                except Exception as e:
                    log.exception("SAME: deferred start failed: %s", e)
                finally:
                    with self._start_lock:
                        self._start_timer = None
            t = threading.Timer(delay, _go)
            t.daemon = True
            self._start_timer = t
            t.start()
            log.info("SAME: start scheduled in %s sec", delay)

    def cancel_scheduled_start(self):
        with self._start_lock:
            if self._start_timer and self._start_timer.is_alive():
                self._start_timer.cancel()
                self._start_timer = None
                log.info("SAME: scheduled start canceled")

    # ---------- RTLSDR mapping ----------
    def _rtl_index(self) -> Optional[int]:
        if SAME_INDEX:
            try: return int(SAME_INDEX)
            except Exception: return None
        try:
            from rtlsdr import RtlSdr
            idx = RtlSdr.get_device_index_by_serial(SAME_SERIAL)
            return int(idx) if idx is not None and idx >= 0 else None
        except Exception as e:
            log.warning("pyrtlsdr not available or failed to map serial '%s': %s", SAME_SERIAL, e)
            return None

    def _spawn_pipe(self, label: str, cmd: str, freq: Optional[float]):
        proc = subprocess.Popen(
            ["bash","-lc", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid  # new session / process group
        )
        try:
            pgid = os.getpgid(proc.pid)
            self._pgids.append(pgid)
        except Exception:
            pass
        rdr  = _LineReader(label, proc, freq)
        rdr.start()
        _StderrDrain(label, proc, level=logging.WARNING).start()
        self.procs.append(proc)
        self.workers.append(rdr)
        log.info("SAME spawn %s", label)

    # ----- rtl_airband management (UDP streaming) -----
    def _build_airband_config(self, out_type: str) -> str:
        """
        Build rtl_airband config with **two outputs per channel**:
          • monitor  → MONITOR_BASE+ch
          • decoder  → UDP_BASE_PORT+ch
        out_type:
          - "udp_stream": float32@16000 (continuous=true)
          - "udp":       s16le@22050 (explicit format/rate)
        """
        pairs = [(UDP_BASE_PORT + i, f) for i, f in enumerate(NOAA_WX)]
        # also expose mapping for 'udp' mode consumers (port:freq)
        os.environ["AOCT_SAME_UDP"] = ",".join(f"{p}:{f:.3f}" for p, f in pairs)

        # Choose device selector: prefer explicit index (default 1 to avoid device 0);
        # else resolve serial to index; else omit.
        try_gain = float(SAME_GAIN)
        idx_from_env: Optional[int] = None
        if SAME_INDEX:
            try:
                idx_from_env = int(SAME_INDEX)
            except Exception:
                idx_from_env = None
        idx_resolved = self._rtl_index() if not idx_from_env else idx_from_env
        env_serial_raw = os.environ.get("AOCT_SAME_SERIAL", "").strip()
        dev_serial = SAME_SERIAL.replace('"','')

        # Center freq and sample rate to cover all WX channels
        center_mhz = (min(NOAA_WX) + max(NOAA_WX)) / 2.0
        sample_rate_msps = 2.40

        chans = []
        for port, freq_mhz in pairs:
            mon_port = _monitor_port_for_udp(port)
            if out_type == "udp_stream":
                outputs = textwrap.dedent(f"""
                  outputs:
                  (
                    {{
                      type = "udp_stream";
                      dest_address = "127.0.0.1";
                      dest_port = {mon_port};
                      continuous = true;
                    }},
                    {{
                      type = "udp_stream";
                      dest_address = "127.0.0.1";
                      dest_port = {port};
                      continuous = true;
                    }}
                  );
                """).strip()
            else:
                outputs = textwrap.dedent(f"""
                  outputs:
                  (
                    {{ type="udp"; address="127.0.0.1"; port={mon_port}; format="s16le"; sample_rate=22050; channels=1; }},
                    {{ type="udp"; address="127.0.0.1"; port={port};     format="s16le"; sample_rate=22050; channels=1; }}
                  );
                """).strip()
            chans.append(textwrap.dedent(f"""
              {{
                freq = {freq_mhz:.5f};
                modulation = "nfm";
                squelch_threshold = ({SQUELCH_DBFS});
                {outputs}
              }}
            """).strip())

        # Device selector line + helpful log
        if idx_resolved is not None:
            dev_selector = f"index = {int(idx_resolved)};"
            sel_msg = f"index={int(idx_resolved)}"
        elif env_serial_raw:
            dev_selector = f'serial = "{dev_serial}";'
            sel_msg = f'serial="{dev_serial}"'
        else:
            dev_selector = ""  # let rtl_airband pick the first device
            sel_msg = "first available"
        log.info("rtl_airband device selector: %s", sel_msg)

        # Optional mode line (off by default for broader compatibility)
        mode_line = f'mode = "{AIRBAND_MODE_OPT}";' if AIRBAND_MODE_OPT in ("multichannel","scan") else ""

        cfg = textwrap.dedent(f"""
        devices:
        (
          {{
            type = "rtlsdr";
            {dev_selector}
            gain = {try_gain};
            centerfreq = {center_mhz:.5f};
            sample_rate = {sample_rate_msps:.2f};
            {mode_line}
            channels:
            (
              {",".join(chans)}
            );
          }}
        );
        """).strip() + "\n"

        path = os.path.join(tempfile.gettempdir(), "aoct-rtlairband-wx.conf")
        with open(path, "w") as fh:
            fh.write(cfg)
        log.info("rtl_airband config written to %s", path)
        return path

    def _ffmpeg_pipe_cmd(self, port: int) -> str:
        """
        Decoder path only:
          rtl_airband/UDP → ffmpeg (convert to s16le@22050) → multimon-ng (-a EAS -t raw -)
        """
        url = f"udp://127.0.0.1:{port}?listen=1&fifo_size=1048576&overrun_nonfatal=1"
        in_fmt = "f32le" if UDP_IN_FMT not in ("f32le", "s16le") else UDP_IN_FMT

        # Prefer stdbuf if available; otherwise fall back to 'script' (PTY trick).
        if _HAS_STDBUF:
            mm = "stdbuf -oL -eL multimon-ng -q -a EAS -t raw -"
        elif _HAS_SCRIPT:
            mm = 'script -q -c "multimon-ng -q -a EAS -t raw -" /dev/null'
            log.warning("SAME: using 'script' fallback for line-buffering (stdbuf not found)")
        else:
            mm = "multimon-ng -q -a EAS -t raw -"
            log.warning("SAME: no stdbuf/script found; multimon-ng output may be block-buffered")

        # In: raw mono at UDP_IN_RATE; Out: s16@22050 to multimon-ng
        cmd = (
            "ffmpeg -hide_banner -loglevel error -nostdin "
            "-fflags +nobuffer "
            f"-f {in_fmt} -ar {UDP_IN_RATE} -ac 1 -i '{url}' "
            "-ar 22050 -ac 1 -f s16le pipe:1 | "
            f"{mm}"
        )
        log.info("SAME decoder bind UDP:%d → multimon-ng (mode=%s)", port, SAME_MODE)
        return cmd

    def _classify_airband_error(self, diag_text: str) -> str:
        """
        Return one of: 'config_error', 'device_error', 'other'
        """
        s = diag_text or ""
        if re.search(r"Configuration error:.*outputs.*unknown output type", s, re.I) or \
           re.search(r"Configuration error", s, re.I):
            return "config_error"
        if re.search(r"No supported devices found", s, re.I) or \
           re.search(r"rtlsdr_open.*failed", s, re.I) or \
           re.search(r"No device matching .* (index|serial)", s, re.I):
            return "device_error"
        return "other"

    def _airband_preflight(self, cfg_path: str) -> tuple[bool, str]:
        """
        Start rtl_airband in foreground to surface parse/open errors; stop shortly after.
        Returns (ok, combined_stdout_stderr_tail_with_rc)
        """
        proc = subprocess.Popen(
            # -f = foreground (don't daemonize), -e = log to stderr (we capture it)
            # keep our own timing/kill to treat "still running" as OK
            ["rtl_airband", "-f", "-e", "-c", cfg_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid
        )
        time.sleep(1.2)  # allow parse and device init to run (some builds flush late)
        rc = proc.poll()

        if rc is None:
            # Process is healthy and still running → treat as OK,
            # but terminate it *before* touching pipes to avoid blocking on read().
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                pass
            # Collect any buffered output with a timeout so we never block.
            try:
                out, err = proc.communicate(timeout=1.0)
            except subprocess.TimeoutExpired:
                # Be ruthless; we never want to block the server thread here.
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    pass
                try:
                    out, err = proc.communicate(timeout=0.5)
                except Exception:
                    out, err = b"", b""
            except Exception:
                out, err = b"", b""

            combo = ((out or b"") + (b"\n" if (out and err) else b"") + (err or b"")).decode("utf-8", "ignore").strip()
            return True, combo

        # Process exited quickly → surface diagnostics with return code.
        try:
            out, err = proc.communicate(timeout=1.0)
        except Exception:
            out, err = b"", b""
        combo = ((out or b"") + (b"\n" if (out and err) else b"") + (err or b"")).decode("utf-8", "ignore").strip()
        return False, (combo + ("" if combo.endswith("\n") else "\n") + f"[exit={rc}]").strip()

    def start(self):
        with self.lock:
            if self.running:
                return

            # Cross-process singleton / takeover
            if self._lock_fd is None:
                fd = _acquire_lock_or_takeover()
                if fd is None:
                    # Someone else is (still) running; don't start here.
                    return
                self._lock_fd = fd
                _write_pidfile(os.getpid())

            _ensure_schema()

            if SAME_MODE == "rtl_fm":
                idx = self._rtl_index()
                dev = f"-d {idx}" if idx is not None else ""
                if _HAS_STDBUF:
                    cmd = (
                        f"rtl_fm {dev} -f {SAME_FREQ:.6f}M -M fm -s 22050 -l 0 "
                        f"-g {shlex.quote(SAME_GAIN)} -E deemp | "
                        "stdbuf -oL -eL multimon-ng -q -a EAS -t raw -"
                    )
                else:
                    mm = ('script -q -c "multimon-ng -q -a EAS -t raw -" /dev/null'
                          if _HAS_SCRIPT else "multimon-ng -q -a EAS -t raw -")
                    cmd = (
                        f"rtl_fm {dev} -f {SAME_FREQ:.6f}M -M fm -s 22050 -l 0 "
                        f"-g {shlex.quote(SAME_GAIN)} -E deemp | {mm}"
                    )
                self._spawn_pipe(f"rtl_fm:{SAME_FREQ:.3f}", cmd, SAME_FREQ)

            elif SAME_MODE == "udp":
                pairs = []
                for tok in (SAME_UDP_MAP.split(",") if SAME_UDP_MAP else []):
                    tok = tok.strip()
                    if not tok:
                        continue
                    p, f = tok.split(":")
                    try:
                        port = int(p); freq = float(f)
                        pairs.append((port, freq))
                    except Exception:
                        continue
                for port, freq in pairs:
                    if not _udp_port_free(port):
                        log.info("SAME: port %d already bound; skipping spawn", port)
                        continue
                    cmd = self._ffmpeg_pipe_cmd(port)
                    log.info("SAME binding UDP:%d → multimon-ng (mode=udp)", port)
                    self._spawn_pipe(f"udp:{port}", cmd, freq)

            elif SAME_MODE == "airband":
                # Always generate udp_stream outputs (modern NFM build) and preflight in foreground.
                cfg_path = self._build_airband_config("udp_stream")
                ok, diag = self._airband_preflight(cfg_path)
                if not ok:
                    # Include a small cfg excerpt in logs for fast eyeballing
                    try:
                        with open(cfg_path, "r") as _fh:
                            cfg_excerpt = "".join(_fh.readlines()[:60]).strip()
                    except Exception:
                        cfg_excerpt = "(failed to read cfg for excerpt)"
                    cls = self._classify_airband_error(diag)
                    if cls == "config_error":
                        log.error("rtl_airband config error (udp_stream): %s\n--- cfg head ---\n%s\n-----------------", diag, cfg_excerpt)
                        return
                    if cls == "device_error":
                        log.error("rtl_airband device error: %s\n--- cfg head ---\n%s\n-----------------", diag, cfg_excerpt)
                        return
                    log.error("rtl_airband failed to start (udp_stream); last output:\n%s\n--- cfg head ---\n%s\n-----------------", diag, cfg_excerpt)
                    return

                # Start long-lived process in foreground (-f) and log to stderr (-e) so we can manage it.
                air = subprocess.Popen(
                    ["rtl_airband", "-f", "-e", "-c", cfg_path],
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, preexec_fn=os.setsid
                )
                try:
                    self._pgids.append(os.getpgid(air.pid))
                except Exception:
                    pass
                _StderrDrain("rtl_airband", air, level=logging.INFO).start()
                self.procs.append(air)
                # Lock in consumer expectations (fmt/rate) for the decoder chain
                os.environ["AOCT_SAME_UDP_FMT"]  = "f32le"
                os.environ["AOCT_SAME_UDP_RATE"] = "16000"
                log.info("SAME rtl_airband running (udp_stream, foreground)")
                for i, freq in enumerate(NOAA_WX):
                    port = UDP_BASE_PORT + i
                    if not _udp_port_free(port):
                        log.info("SAME: port %d already bound; skipping spawn", port)
                        continue
                    cmd = self._ffmpeg_pipe_cmd(port)
                    log.info("SAME binding decoder UDP:%d → multimon-ng (mode=airband)", port)
                    self._spawn_pipe(f"airband:{port}", cmd, freq)

            else:
                log.warning("AOCT_SAME_MODE=%s is unknown; not starting", SAME_MODE)
                return

            self.running = True
            log.info("SAME monitor started (mode=%s)", SAME_MODE)

    def stop(self):
        with self.lock:
            self.cancel_scheduled_start()

            # Kill whole process groups first
            for pgid in list(set(self._pgids)):
                try: os.killpg(pgid, signal.SIGTERM)
                except Exception: pass
            time.sleep(KILL_GRACE_SEC)
            for pgid in list(set(self._pgids)):
                try: os.killpg(pgid, signal.SIGKILL)
                except Exception: pass
            self._pgids.clear()

            # Backstop: terminate direct children if any remain
            for p in self.procs:
                try: p.terminate()
                except Exception: pass
            for p in self.procs:
                try: p.wait(timeout=2.0)
                except Exception: pass
            self.procs.clear()
            self.workers.clear()
            self.running = False

            # Release cross-process lock
            try:
                if self._lock_fd is not None:
                    os.close(self._lock_fd)
                    self._lock_fd = None
            except Exception:
                pass
            log.info("SAME monitor stopped")

    def status(self) -> Dict:
        with self.lock:
            scheduled = bool(self._start_timer and self._start_timer.is_alive())
        return {
            "running": self.running,
            "mode": SAME_MODE,
            "serial": SAME_SERIAL,
            "index": self._rtl_index(),
            "freq": SAME_FREQ,
            "scheduled": scheduled,
            "start_delay_sec": SAME_START_DELAY,
            "pidfile_pid": _read_pidfile(),
            "lock_path": LOCK_PATH,
        }

# ──────────────────────────────────────────────────────────────────────────────
_manager: Optional[SameManager] = None
_manager_lock = threading.Lock()

def maybe_start_same_monitor():
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = SameManager()
        # Defer start to avoid “already in use” when app boots twice
        if SAME_ENABLE:
            _manager.schedule_start(SAME_START_DELAY)
    return _manager

def stop_same_monitor():
    global _manager
    with _manager_lock:
        if _manager:
            _manager.stop()

def same_status() -> Dict:
    def _current_udp_input() -> tuple[str,int]:
        fmt = (os.environ.get("AOCT_SAME_UDP_FMT") or UDP_IN_FMT or "f32le").strip().lower()
        try:
            rate = int(os.environ.get("AOCT_SAME_UDP_RATE") or str(UDP_IN_RATE))
        except Exception:
            rate = UDP_IN_RATE
        return fmt, rate
    with _manager_lock:
        base = (_manager.status() if _manager else {
            "running": False, "mode": SAME_MODE, "scheduled": False,
            "start_delay_sec": SAME_START_DELAY, "pidfile_pid": _read_pidfile(),
            "lock_path": LOCK_PATH,
        })
    fmt, rate = _current_udp_input()
    # Expose latest non-hidden SAME alert so the UI can do per-user "seen" tracking
    # without affecting other operators' browsers (multi-user safe).
    base.update({
        "udp_input_fmt": fmt,
        "udp_input_rate": rate,
        "latest_nonhidden_utc": latest_nonhidden_utc() or ""
    })
    return base

def same_recent(n=50, include_hidden: bool = False) -> List[Dict]:
    # Memory cache only keeps non-hidden; DB fetch honors include_hidden flag.
    if not include_hidden:
        mem = _MemoryCache.recent(n)
        if mem:
            return mem
    return get_recent_alerts(n, include_hidden)

def same_channels() -> List[Dict]:
    return _channel_map()
