# aot_client.pyw
# AOT KISS client (RX + TX) with Callsign + "Request Upd".
# - Auto-connects on launch
# - "Request Upd" sends:  AOT REQ UPD
# - Button enabled only when connected and callsign length >= 4
#
# Build (no console window):
#   pyinstaller --noconfirm --windowed --onefile aot_client.pyw

import socket
import threading
import json
import sys
import zlib
import base64
from pathlib import Path
from tkinter import (
    Tk, StringVar, BooleanVar, ttk, Text, END, DISABLED, NORMAL,
    VERTICAL, HORIZONTAL
)

APP_NAME = "AOT KISS Client"
DEFAULT_DEST = "AOCTDB"   # must match server DEST
DEFAULT_KISS_PORT = 8001  # Direwolf default

# ---------- Settings ----------
def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent

SETTINGS_PATH = app_dir() / "settings.json"

def load_settings():
    try:
        with SETTINGS_PATH.open("r", encoding="utf-8") as f:
            s = json.load(f)
        return {
            "host": s.get("host", "127.0.0.1"),
            "port": int(s.get("port", DEFAULT_KISS_PORT)),
            "callsign": s.get("callsign", "")
        }
    except Exception:
        return {"host": "127.0.0.1", "port": DEFAULT_KISS_PORT, "callsign": ""}

def save_settings(host, port, callsign):
    try:
        with SETTINGS_PATH.open("w", encoding="utf-8") as f:
            json.dump({"host": host, "port": int(port), "callsign": (callsign or "")}, f, indent=2)
    except Exception:
        pass

# ---------- KISS helpers ----------
FEND=0xC0; FESC=0xDB; TFEND=0xDC; TFESC=0xDD

def _kiss_unescape(data: bytes) -> bytes:
    out = bytearray(); i = 0
    while i < len(data):
        b = data[i]
        if b == FESC and i + 1 < len(data):
            nb = data[i+1]
            out.append(FEND if nb==TFEND else FESC if nb==TFESC else nb); i += 2
        else:
            out.append(b); i += 1
    return bytes(out)

def _kiss_escape(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b == FEND:
            out.append(FESC); out.append(TFEND)
        elif b == FESC:
            out.append(FESC); out.append(TFESC)
        else:
            out.append(b)
    return bytes(out)

def _kiss_frames(stream: bytes):
    buf = bytearray(); in_frame = False
    for b in stream:
        if b == FEND:
            if in_frame and buf: yield bytes(buf)
            buf.clear(); in_frame = True
        elif in_frame:
            buf.append(b)

def _ax25_addr_to_str(addr7: bytes) -> str:
    cs = ''.join(chr((b >> 1) & 0x7F) for b in addr7[:6]).strip()
    ssid = (addr7[6] >> 1) & 0x0F
    return f"{cs}-{ssid}" if ssid else cs

def _parse_ax25(frame: bytes):
    if len(frame) < 2*7+2: return None
    i=0; addrs=[]
    while True:
        if i+7>len(frame): return None
        a=frame[i:i+7]; addrs.append(a); i+=7
        if a[6]&0x01: break
        if len(addrs)>10: return None
    if i+2>len(frame): return None
    control=frame[i]; pid=frame[i+1]; i+=2
    if control!=0x03 or pid!=0xF0: return None
    info = frame[i:]
    try: text = info.decode("utf-8", errors="strict")
    except UnicodeDecodeError: text = info.decode("latin-1", errors="replace")
    return (_ax25_addr_to_str(addrs[0]), _ax25_addr_to_str(addrs[1]), text)

def _encode_ax25_addr(callsign: str, last: bool) -> bytes:
    # Accept SSID like "N0CALL-7"
    callsign = (callsign or "").upper().strip()
    ssid = 0
    if "-" in callsign:
        base, suf = callsign.split("-", 1)
        callsign = base.strip()
        try: ssid = max(0, min(15, int(suf)))
        except Exception: ssid = 0
    cs = (callsign + "      ")[:6]
    b = bytearray((ord(ch) << 1) & 0xFE for ch in cs)
    ss = 0x60 | ((ssid & 0x0F) << 1) | (0x01 if last else 0x00)
    b.append(ss)
    return bytes(b)

def _build_ui_frame(dest: str, src: str, info_text: str) -> bytes:
    ax = _encode_ax25_addr(dest, last=False) + _encode_ax25_addr(src, last=True) + bytes([0x03, 0xF0]) + info_text.encode("utf-8")
    kiss = bytes([0x00]) + ax  # port 0 data frame
    return bytes([FEND]) + _kiss_escape(kiss) + bytes([FEND])

# ---------- base91 (decode) ----------
_B91_DEC = {c:i for i,c in enumerate(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "!#$%&()*+,./:;<=>?@[]^_`{|}~\""
)}
def _b91_decode(s: str) -> bytes:
    v = -1; b = 0; n = 0; out = bytearray()
    for ch in s:
        c = _B91_DEC.get(ch, None)
        if c is None:
            continue
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n >= 8:
                out.append(b & 255); b >>= 8; n -= 8
            v = -1
    if v >= 0:
        b |= v << n
        n += 7
        while n >= 8:
            out.append(b & 255); b >>= 8; n -= 8
    return bytes(out)

# ---------- AOT reassembly ----------
class AOTAssembler:
    def __init__(self, log_fn, show_json_fn, refresh_table_fn):
        self.sessions = {}
        self.latest_full = None
        self.log = log_fn
        self.show_json = show_json_fn
        self.refresh_table = refresh_table_fn

    def _extract_flights_dict(self):
        if not isinstance(self.latest_full, dict): return None
        fl = self.latest_full.get("fl")
        if isinstance(fl, dict): return fl
        if "full" in self.latest_full and isinstance(self.latest_full["full"], dict):
            return self.latest_full["full"]
        return self.latest_full if isinstance(self.latest_full, dict) else None

    def _decode_payload(self, enc: str, data: str) -> str:
        try:
            if enc == "Z":
                raw = _b91_decode(data); return zlib.decompress(raw).decode("utf-8")
            elif enc == "B":
                raw = base64.b64decode(data.encode("ascii"), validate=False)
                return zlib.decompress(raw).decode("utf-8")
            else:
                return data
        except Exception as e:
            raise ValueError(f"decode({enc}) failed: {e}")

    def feed(self, aot_line: str):
        if not aot_line.startswith("AOT "): return
        try:
            head, rest = aot_line[4:].split("|", 1)
            seq_s, total_s = head.split("/")
            seq, total = int(seq_s), int(total_s)
            flag, rest2 = rest.split("|", 1)
            sid, rest3  = rest2.split("|", 1)
            if "|" in rest3: enc, chunk = rest3.split("|", 1)
            else:            enc, chunk = "J", rest3
        except Exception:
            self.log(f"Bad AOT header: {aot_line}"); return

        S = self.sessions.setdefault(sid, {"total": total, "parts": {}, "flag": flag})
        S["total"] = total; S["flag"] = flag; S["parts"][seq] = (enc, chunk)
        have = len(S["parts"])
        self.log(f"recv sid={sid} {have}/{S['total']} ({flag},{enc})")

        if have == S["total"]:
            pieces = [S["parts"][i] for i in range(1, S["total"]+1)]
            self.sessions.pop(sid, None)
            encs = [e for e,_ in pieces]; enc = encs[0]
            data = "".join(p for _,p in pieces)
            try:
                text = self._decode_payload(enc, data)
                obj = json.loads(text)
            except Exception as e:
                self.log(f"JSON decode error sid={sid}: {e}"); return

            if flag == "F":
                self.latest_full = obj
                self.show_json(obj); self.refresh_table()
                self.log(f"✅ full applied (sid {sid})")
            elif flag == "D":
                if not self.latest_full: self.log(f"⚠ diff without full (sid {sid})"); return
                base = self._extract_flights_dict()
                df = obj.get("df", {}) if isinstance(obj, dict) else {}
                if not isinstance(base, dict): self.log("⚠ unexpected full structure; skipping diff"); return
                for k, upd in df.get("u", {}).items():
                    cur = base.get(str(k), {})
                    if isinstance(cur, dict) and isinstance(upd, dict):
                        cur.update(upd); base[str(k)] = cur
                    else:
                        base[str(k)] = upd
                for k in df.get("rm", []): base.pop(str(k), None)
                self.show_json(self.latest_full); self.refresh_table()
                self.log(f"✅ diff applied (sid {sid})")

# ---------- KISS client ----------
class KissClient(threading.Thread):
    def __init__(self, host, port, log_fn, on_aot):
        super().__init__(daemon=True)
        self.host=host; self.port=port; self.log=log_fn; self.on_aot=on_aot
        self._stop=False; self._sock=None; self._lock=threading.Lock()

    def stop(self):
        self._stop=True
        try:
            if self._sock: self._sock.close()
        except Exception:
            pass

    def send_info(self, dest: str, src: str, text: str):
        try:
            frame = _build_ui_frame(dest, src, text)
        except Exception as e:
            self.log(f"Build frame error: {e}"); return
        with self._lock:
            if not self._sock:
                self.log("TX failed: not connected"); return
            try:
                self._sock.sendall(frame)
                self.log(f"TX: {text} (SRC={src} → {dest})")
            except Exception as e:
                self.log(f"TX error: {e}")

    def run(self):
        while not self._stop:
            try:
                with socket.create_connection((self.host, self.port), timeout=5) as s:
                    self._sock = s
                    s.settimeout(1.0)
                    self.log(f"Connected to KISS {self.host}:{self.port}")
                    while not self._stop:
                        try:
                            chunk = s.recv(4096)
                            if not chunk:
                                self.log("KISS socket closed"); break
                            for raw in _kiss_frames(chunk):
                                body = _kiss_unescape(raw)
                                if not body: continue
                                if (body[0] & 0xF0) >> 4 != 0x0:  # data frames only
                                    continue
                                ax = body[1:]
                                parsed = _parse_ax25(ax)
                                if not parsed: continue
                                _, _, info = parsed
                                if info.startswith("AOT "):
                                    self.on_aot(info)
                        except socket.timeout:
                            continue
                        except Exception as e:
                            self.log(f"RX error: {e}")
                            break
            except Exception as e:
                self.log(f"Connect error: {e}")
            finally:
                self._sock = None
            if not self._stop:
                # small backoff before reconnect
                try: import time; time.sleep(1.0)
                except Exception: pass

# ---------- GUI ----------
class App:
    def __init__(self, root: Tk):
        root.title(APP_NAME); self.root = root
        s = load_settings()
        self.client=None
        self.show_log = BooleanVar(value=True)
        self.show_json = BooleanVar(value=True)
        self.show_table = BooleanVar(value=True)

        # top controls
        topbar = ttk.Frame(root, padding=(8,8,8,4)); topbar.grid(row=0,column=0,sticky="ew")
        root.columnconfigure(0, weight=1)

        ttk.Label(topbar,text="Host").grid(row=0,column=0,sticky="w")
        self.host = StringVar(value=s["host"])
        ttk.Entry(topbar,textvariable=self.host,width=16).grid(row=0,column=1,sticky="w",padx=(4,12))

        ttk.Label(topbar,text="KISS Port").grid(row=0,column=2,sticky="w")
        self.port = StringVar(value=str(s["port"]))
        ttk.Entry(topbar,textvariable=self.port,width=8).grid(row=0,column=3,sticky="w",padx=(4,12))

        ttk.Label(topbar,text="Callsign").grid(row=0,column=4,sticky="w")
        self.callsign = StringVar(value=(s.get("callsign") or ""))
        self.callsign_entry = ttk.Entry(topbar,textvariable=self.callsign,width=12)
        self.callsign_entry.grid(row=0,column=5,sticky="w",padx=(4,12))

        self.btn = ttk.Button(topbar,text="Connect",command=self.toggle_connect)
        self.btn.grid(row=0,column=6,sticky="w",padx=(0,12))
        self.req_btn = ttk.Button(topbar,text="Request Upd",command=self._request_upd)
        self.req_btn.grid(row=0,column=7,sticky="w",padx=(0,12))

        self.cb_log  = ttk.Checkbutton(topbar,text="Show Packet Log", variable=self.show_log,  command=self._on_toggle_view)
        self.cb_json = ttk.Checkbutton(topbar,text="Show JSON",       variable=self.show_json, command=self._on_toggle_view)
        self.cb_tbl  = ttk.Checkbutton(topbar,text="Show Dashboard",  variable=self.show_table, command=self._on_toggle_view)
        self.cb_log.grid(row=0,column=8,sticky="w",padx=(8,8))
        self.cb_json.grid(row=0,column=9,sticky="w",padx=(0,8))
        self.cb_tbl.grid(row=0,column=10,sticky="w")
        for c in range(11): topbar.columnconfigure(c, weight=0)
        topbar.columnconfigure(10, weight=1)

        # layout frames
        self.content = ttk.Frame(root, padding=(8,4,8,8)); self.content.grid(row=1,column=0,sticky="nsew")
        root.rowconfigure(1, weight=1)
        self.content.columnconfigure(0, weight=1)
        self.content.rowconfigure(0, weight=1); self.content.rowconfigure(1, weight=1)

        self.top_frame = ttk.Frame(self.content); self.top_frame.grid(row=0,column=0,sticky="nsew",pady=(0,6))
        self.top_frame.columnconfigure(0, weight=1); self.top_frame.columnconfigure(1, weight=1)
        self.top_frame.rowconfigure(0, weight=1)

        # packet log
        self.log_txt = Text(self.top_frame, height=12)
        self.log_scr = ttk.Scrollbar(self.top_frame, orient=VERTICAL, command=self.log_txt.yview)
        self.log_txt.configure(yscrollcommand=self.log_scr.set, state=DISABLED)

        # json view
        self.json_txt = Text(self.top_frame, height=12)
        self.json_scr = ttk.Scrollbar(self.top_frame, orient=VERTICAL, command=self.json_txt.yview)
        self.json_txt.configure(yscrollcommand=self.json_scr.set, state=DISABLED)

        # dashboard table
        self.table_frame = ttk.Frame(self.content)
        cols = ("ID","Tail","Direction","Pilot","Needs TX","Sent","Complete","ETA","Landing","Takeoff","Ramp?","Pax","CargoType","CargoWeight","Remarks")
        self.table = ttk.Treeview(self.table_frame, columns=cols, show="headings", height=12)
        widths = [60,90,90,100,80,60,80,60,70,70,60,60,120,100,240]
        for col,w in zip(cols,widths):
            self.table.heading(col, text=col)
            self.table.column(col, width=w, anchor="center" if col in ("ID","Needs TX","Sent","Complete","ETA","Ramp?","Pax") else "w")
        self.tbl_sy = ttk.Scrollbar(self.table_frame, orient=VERTICAL,   command=self.table.yview)
        self.tbl_sx = ttk.Scrollbar(self.table_frame, orient=HORIZONTAL, command=self.table.xview)
        self.table.configure(yscrollcommand=self.tbl_sy.set, xscrollcommand=self.tbl_sx.set)

        self._apply_layout()
        self.assembler = AOTAssembler(self._log, self._show_json, self._refresh_table)

        # hooks
        self.callsign.trace_add("write", self._on_callsign_changed)
        root.after(250, self.toggle_connect)  # auto-connect
        self._validate_controls()

    # UI helpers
    def _log(self, line: str):
        self.log_txt.configure(state=NORMAL); self.log_txt.insert(END, line+"\n"); self.log_txt.see(END); self.log_txt.configure(state=DISABLED)

    def _show_json(self, obj):
        self.json_txt.configure(state=NORMAL); self.json_txt.delete("1.0", END)
        try: self.json_txt.insert(END, json.dumps(obj, indent=2))
        except Exception: self.json_txt.insert(END, str(obj))
        self.json_txt.see("1.0"); self.json_txt.configure(state=DISABLED)

    def _refresh_table(self):
        lf = self.assembler.latest_full
        flights = None
        if isinstance(lf, dict):
            flights = lf.get("fl") if isinstance(lf.get("fl"), dict) else None
            if flights is None and isinstance(lf.get("full"), dict): flights = lf.get("full")
            if flights is None and all(k in lf for k in ("i","t","d")): flights = lf
        for iid in self.table.get_children(): self.table.delete(iid)
        if not isinstance(flights, dict): return

        def key_for(item):
            _, v = item
            nt = v.get("nt",0) or 0; s=v.get("s",0) or 0; c=v.get("c",0) or 0
            try: idnum = int(v.get("i",0))
            except: idnum = 0
            return (-nt, s, c, -idnum)

        for _, v in sorted(flights.items(), key=key_for):
            row = (
                v.get("i",""), v.get("t",""), v.get("d",""), v.get("p",""),
                "Yes" if v.get("nt",0) else "No",
                "Yes" if v.get("s",0) else "No",
                "Yes" if v.get("c",0) else "No",
                v.get("et",""), v.get("al",""), v.get("at",""),
                "Yes" if v.get("re",0) else "No",
                v.get("pc",""), v.get("ct",""), v.get("cw",""), v.get("rm",""),
            )
            self.table.insert("", END, values=row)

    def handle_aot(self, info_line: str): self.assembler.feed(info_line)

    def _request_upd(self):
        if self.client is None:
            self._log("Not connected."); return
        cs = (self.callsign.get() or "").strip().upper()
        if len(cs) < 4:
            self._log("Enter a callsign (≥ 4 chars) before requesting an update."); return
        save_settings((self.host.get() or "127.0.0.1").strip(),
                      int((self.port.get() or str(DEFAULT_KISS_PORT)).strip()),
                      cs)
        self.client.send_info(DEFAULT_DEST, cs, "AOT REQ UPD")

    def toggle_connect(self):
        if self.client is None:
            host = (self.host.get() or "127.0.0.1").strip()
            try: port = int((self.port.get() or str(DEFAULT_KISS_PORT)).strip())
            except ValueError: port = DEFAULT_KISS_PORT; self.port.set(str(port))
            save_settings(host, port, (self.callsign.get() or "").strip().upper())
            def log_ts(msg): self.root.after(0, lambda: self._log(msg))
            def on_aot(line): self.root.after(0, lambda: self.handle_aot(line))
            self.client = KissClient(host, port, log_ts, on_aot); self.client.start()
            self.btn.configure(text="Disconnect")
        else:
            self.client.stop(); self.client=None
            self._log("Disconnected."); self.btn.configure(text="Connect")
        self._validate_controls()

    def _on_toggle_view(self):
        if not self.show_log.get() and not self.show_json.get() and not self.show_table.get():
            self.show_table.set(True)
        self._apply_layout()

    def _apply_layout(self):
        for w in (self.log_txt,self.log_scr,self.json_txt,self.json_scr): w.grid_forget()
        self.table_frame.grid_forget(); self.top_frame.grid_forget()
        show_log, show_json, show_table = self.show_log.get(), self.show_json.get(), self.show_table.get()
        if not show_log and not show_json:
            if show_table:
                self.table_frame.grid(row=0,column=0,sticky="nsew")
                self.content.rowconfigure(0, weight=1); self.content.rowconfigure(1, weight=0)
                self._grid_table_full()
            return
        self.top_frame.grid(row=0,column=0,sticky="nsew",pady=(0,6))
        self.content.rowconfigure(0, weight=1)
        if show_table:
            self.table_frame.grid(row=1,column=0,sticky="nsew")
            self.content.rowconfigure(1, weight=1); self._grid_table_bottom()
        else:
            self.content.rowconfigure(1, weight=0)
        if show_log and show_json:
            self.top_frame.columnconfigure(0, weight=1); self.top_frame.columnconfigure(1, weight=1)
            self.log_txt.grid(row=0,column=0,sticky="nsew"); self.log_scr.grid(row=0,column=0,sticky="nse")
            self.json_txt.grid(row=0,column=1,sticky="nsew"); self.json_scr.grid(row=0,column=1,sticky="nse")
        else:
            self.top_frame.columnconfigure(0, weight=1); self.top_frame.columnconfigure(1, weight=0)
            if show_log:
                self.log_txt.grid(row=0,column=0,sticky="nsew"); self.log_scr.grid(row=0,column=0,sticky="nse")
            else:
                self.json_txt.grid(row=0,column=0,sticky="nsew"); self.json_scr.grid(row=0,column=0,sticky="nse")
        self.top_frame.rowconfigure(0, weight=1)

    def _grid_table_bottom(self):
        for w in (self.table,self.tbl_sy,self.tbl_sx): w.grid_forget()
        self.table.grid(row=0,column=0,sticky="nsew")
        self.tbl_sy.grid(row=0,column=1,sticky="ns")
        self.tbl_sx.grid(row=1,column=0,sticky="ew")
        self.table_frame.columnconfigure(0, weight=1)
        self.table_frame.rowconfigure(0, weight=1)
        self.table_frame.rowconfigure(1, weight=0)

    def _grid_table_full(self): self._grid_table_bottom()

    # callsign helpers / gating
    def _on_callsign_changed(self, *_):
        cs = self.callsign.get()
        u  = (cs or "").upper()
        if cs != u:
            pos = self.callsign_entry.index("insert")
            self.callsign.set(u)
            try: self.callsign_entry.icursor(pos)
            except Exception: pass
        save_settings((self.host.get() or "127.0.0.1").strip(),
                      int((self.port.get() or str(DEFAULT_KISS_PORT)).strip()),
                      u)
        self._validate_controls()

    def _validate_controls(self):
        cs_ok = len((self.callsign.get() or "").strip().upper()) >= 4
        connected = self.client is not None
        state = "normal" if (connected and cs_ok) else "disabled"
        try: self.req_btn.configure(state=state)
        except Exception: pass

# ---------- main ----------
if __name__ == "__main__":
    root = Tk(); App(root)
    root.geometry("1200x820"); root.minsize(950, 600)
    root.mainloop()
