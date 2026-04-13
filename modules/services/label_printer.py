# modules/services/label_printer.py
"""Direct printing to Brother QL-820NWB via TCP (brother_ql library).

Renders label HTML to a cropped PNG, then sends raster data to the printer
over the network. No driver installation needed on workstations.
"""

import io
import logging
import socket
import threading

from PIL import Image

logger = logging.getLogger(__name__)

# brother_ql constants
_MODEL = "QL-820NWB"
_LABEL_SIZE = "62"          # DK-2205 62mm continuous tape
_NATIVE_WIDTH_PX = 696      # 62mm at 300 DPI


def generate_barcode_svg(value):
    """Generate a Code128 barcode as inline SVG markup.

    Returns raw SVG string (no XML declaration) for embedding in HTML.
    Used for server-side rendering where JsBarcode is unavailable.
    """
    import barcode
    from barcode.writer import SVGWriter

    writer = SVGWriter()
    writer.set_options({
        "module_width": 0.25,
        "module_height": 6.0,
        "font_size": 8,
        "text_distance": 1.0,
        "quiet_zone": 2.0,
        "write_text": True,
    })
    code = barcode.get("code128", value, writer=writer)
    buf = io.BytesIO()
    code.write(buf, options={"compress": False})
    svg_bytes = buf.getvalue()
    svg_str = svg_bytes.decode("utf-8")
    # Strip XML declaration and doctype — we want bare <svg>...</svg>
    for marker in ("<?xml", "<!DOCTYPE"):
        idx = svg_str.find(marker)
        if idx >= 0:
            end = svg_str.find(">", idx)
            if end >= 0:
                svg_str = svg_str[:idx] + svg_str[end + 1:]
    return svg_str.strip()


def render_label_png(label_data, label_type="inventory"):
    """Render a label directly to a PNG using Pillow.

    Draws at 696px wide (62mm @ 300 DPI) for the Brother QL.
    If content needs more width, renders wider and rotates 90 degrees.

    Returns PNG bytes.
    """
    from PIL import ImageDraw, ImageFont

    W = _NATIVE_WIDTH_PX  # 696
    PAD = 24
    LINE_GAP = 6

    # Font loader with fallback chain
    _fc = {}
    def font(size):
        if size not in _fc:
            for n in ("DejaVuSans-Bold.ttf", "DejaVuSans.ttf",
                      "LiberationSans-Bold.ttf", "LiberationSans-Regular.ttf",
                      "FreeSans.ttf", "arial.ttf"):
                try:
                    _fc[size] = ImageFont.truetype(n, size)
                    break
                except (OSError, IOError):
                    continue
            else:
                _fc[size] = ImageFont.load_default(size=size)
        return _fc[size]

    # Get real mission number from preferences
    mission_num = ""
    try:
        from modules.utils.common import get_preference
        mission_num = get_preference("mission_number") or ""
    except Exception:
        pass

    # ── Build content rows: list of (text, font_size) ──
    rows = []

    if label_type == "inventory":
        rows.append((label_data.get("name", ""), 38))
        rows.append((f'{label_data.get("weight_lb", "")} lb per unit', 28))
        if label_data.get("origin"):
            rows.append((label_data["origin"], 24))
        if label_data.get("unit_label"):
            rows.append((f'Unit {label_data["unit_label"]}', 30))

    else:  # cargo
        title = "CARGO ID"
        if label_data.get("unit_label"):
            title += f'  {label_data["unit_label"]}'
        rows.append((title, 32))

        # Use real mission number, fall back to label data
        m = mission_num or label_data.get("mission", "")
        kv = []
        if m:
            kv.append(("Mission", m))
        for key, display in [("tail", "Tail"), ("origin", "From"),
                              ("destination", "To"), ("date_sealed", "Date"),
                              ("contents", "Item"), ("cargo_origin", "Source")]:
            v = label_data.get(key, "")
            if v:
                kv.append((display, str(v)))
        wt = label_data.get("weight_lb", "")
        if wt:
            kv.append(("Weight", f"{wt} lb"))

        for k, v in kv:
            rows.append((f"{k}: {v}", 24))

    # ── Calculate dimensions ──
    total_h = PAD
    for text, sz in rows:
        total_h += sz + LINE_GAP
    # Add space for barcode
    bc_val = label_data.get("barcode", "")
    bc_block_h = 0
    if bc_val:
        bc_block_h = 100
        total_h += bc_block_h + LINE_GAP
    total_h += PAD

    # ── Draw ──
    img = Image.new("RGB", (W, total_h), "white")
    draw = ImageDraw.Draw(img)
    draw.rectangle([3, 3, W - 4, total_h - 4], outline="black", width=2)

    y = PAD

    # Barcode at top
    if bc_val:
        try:
            import barcode as bc_lib
            from barcode.writer import ImageWriter
            writer = ImageWriter()
            writer.set_options({
                "module_width": 0.35,
                "module_height": 10.0,
                "font_size": 12,
                "text_distance": 1.5,
                "quiet_zone": 3.0,
                "write_text": True,
                "dpi": 300,
            })
            code = bc_lib.get("code128", bc_val, writer=writer)
            bc_buf = io.BytesIO()
            code.write(bc_buf)
            bc_img = Image.open(bc_buf).convert("RGB")
            # Scale to fit width
            max_w = W - 2 * PAD
            if bc_img.width > max_w:
                r = max_w / bc_img.width
                bc_img = bc_img.resize((max_w, int(bc_img.height * r)), Image.LANCZOS)
            # Center
            img.paste(bc_img, ((W - bc_img.width) // 2, y))
            y += bc_img.height + LINE_GAP
        except Exception as e:
            logger.warning("Barcode render failed: %s", e)
            draw.text((PAD, y), bc_val, fill="black", font=font(18))
            y += 24

    # Separator line after barcode
    if bc_val:
        draw.line([(PAD, y), (W - PAD, y)], fill="gray", width=1)
        y += LINE_GAP

    # Text rows
    for text, sz in rows:
        f = font(sz)
        # Center inventory labels, left-align cargo
        if label_type == "inventory":
            bbox = draw.textbbox((0, 0), text, font=f)
            tw = bbox[2] - bbox[0]
            x = max(PAD, (W - tw) // 2)
        else:
            x = PAD
        draw.text((x, y), text, fill="black", font=f)
        y += sz + LINE_GAP

    # Crop to content
    y += PAD
    img = img.crop((0, 0, W, min(y, img.height)))

    # Convert to RGB (safety)
    if img.mode != "RGB":
        bg = Image.new("RGB", img.size, (255, 255, 255))
        bg.paste(img)
        img = bg

    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


def send_to_printer(image_bytes, printer_ip, cut=True):
    """Send a PNG image to the Brother QL printer via TCP.

    Returns dict: {"ok": True} on success, {"ok": False, "error": "..."} on failure.
    """
    from brother_ql.conversion import convert
    from brother_ql.backends.helpers import send as ql_send
    from brother_ql.raster import BrotherQLRaster

    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")

        qlr = BrotherQLRaster(_MODEL)
        instructions = convert(
            qlr=qlr,
            images=[img],
            label=_LABEL_SIZE,
            cut=cut,
            dither=False,
            hq=True,
        )

        printer_uri = f"tcp://{printer_ip}:9100"
        result = ql_send(
            instructions=instructions,
            printer_identifier=printer_uri,
            backend_identifier="network",
        )

        if result is None:
            # Network backend often returns None but still prints
            return {"ok": True}
        if result.get("did_print") or result.get("instructions_sent"):
            return {"ok": True}
        errors = (result.get("printer_state") or {}).get("errors", ["Unknown error"])
        return {"ok": False, "error": str(errors)}

    except ConnectionRefusedError:
        msg = f"Printer at {printer_ip} refused connection (is it on?)"
        logger.warning(msg)
        return {"ok": False, "error": msg}
    except socket.timeout:
        msg = f"Printer at {printer_ip} timed out"
        logger.warning(msg)
        return {"ok": False, "error": msg}
    except Exception as e:
        msg = f"Print failed: {e}"
        logger.exception(msg)
        return {"ok": False, "error": msg}


def check_printer_status(printer_ip):
    """Quick TCP connect probe to port 9100.

    Returns {"reachable": True/False, "ip": printer_ip}.
    """
    try:
        s = socket.create_connection((printer_ip, 9100), timeout=2)
        s.close()
        return {"reachable": True, "ip": printer_ip}
    except Exception:
        return {"reachable": False, "ip": printer_ip}


# ── mDNS / Zeroconf auto-discovery ────────────────────────────────────

_discovered_ip = None  # module-level cache


def discover_printer(timeout=5):
    """Scan the LAN for a Brother QL printer via mDNS.

    Looks for _pdl-datastream._tcp.local. and _printer._tcp.local. services
    whose name contains 'Brother' or 'QL'. Returns the IP address string
    or None if not found.
    """
    global _discovered_ip
    from zeroconf import Zeroconf, ServiceBrowser

    found = {}

    class _Listener:
        def add_service(self, zc, stype, name):
            info = zc.get_service_info(stype, name)
            if info and info.parsed_addresses():
                low = name.lower()
                # Only match QL-series label printers, not other Brother devices
                if "ql" in low or "ql-820" in low or "ql-800" in low:
                    found[name] = info.parsed_addresses()[0]
                elif "brother" in low:
                    logger.debug("Skipping non-QL Brother device: %s", name)

        def remove_service(self, zc, stype, name):
            pass

        def update_service(self, zc, stype, name):
            pass

    zc = Zeroconf()
    listener = _Listener()
    browsers = []
    for stype in ("_pdl-datastream._tcp.local.", "_printer._tcp.local.", "_ipp._tcp.local."):
        browsers.append(ServiceBrowser(zc, stype, listener))

    import time
    time.sleep(timeout)
    for b in browsers:
        b.cancel()
    zc.close()

    if found:
        ip = list(found.values())[0]
        _discovered_ip = ip
        logger.info("Auto-discovered Brother printer at %s (%s)", ip, list(found.keys())[0])
        return ip

    logger.info("No Brother printer found via mDNS")
    return None


def get_printer_ip():
    """Return the configured or auto-discovered printer IP.

    Priority: preference > cached discovery > fresh discovery scan.
    """
    try:
        from modules.utils.common import get_preference
        ip = (get_preference("printer_ip") or "").strip()
        if ip:
            return ip
    except Exception:
        pass

    if _discovered_ip:
        return _discovered_ip

    return discover_printer(timeout=3)


def auto_configure_printer():
    """Run at startup: discover printer and set preferences if not already configured.

    Sets printer_ip and direct_print_enabled=yes when a printer is found
    and no IP is configured yet.
    """
    try:
        from modules.utils.common import get_preference, set_preference
        existing_ip = (get_preference("printer_ip") or "").strip()
        if existing_ip:
            logger.info("Printer IP already configured: %s", existing_ip)
            # Still default direct printing to on if not explicitly set
            if get_preference("direct_print_enabled") is None:
                set_preference("direct_print_enabled", "yes")
            return existing_ip

        ip = discover_printer(timeout=5)
        if ip:
            set_preference("printer_ip", ip)
            set_preference("direct_print_enabled", "yes")
            logger.info("Auto-configured printer at %s, direct printing enabled", ip)
            return ip
        else:
            # No printer found — still default direct_print to yes so it works
            # when a printer appears later
            if get_preference("direct_print_enabled") is None:
                set_preference("direct_print_enabled", "yes")
            return None
    except Exception as e:
        logger.warning("Auto-configure printer failed: %s", e)
        return None


def print_label_async(html_string, base_url, printer_ip):
    """Render label HTML and send to printer in a background thread.

    Fires a daemon thread — caller returns immediately.
    """
    def _job():
        try:
            png = render_label_png(html_string, base_url)
            result = send_to_printer(png, printer_ip)
            if result["ok"]:
                logger.info("Label printed successfully to %s", printer_ip)
            else:
                logger.warning("Label print failed: %s", result.get("error"))
        except Exception as e:
            logger.exception("Label print job crashed: %s", e)

    t = threading.Thread(target=_job, daemon=True)
    t.start()
    return t
