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
    """Render a label directly to a 696px-wide PNG using Pillow.

    Bypasses WeasyPrint entirely — draws text and barcodes directly for
    predictable output at 300 DPI on the Brother QL 62mm tape.

    Args:
        label_data: dict with label fields (barcode, name, weight_lb, origin,
                    unit_label for inventory; or mission, tail, origin, destination,
                    date_sealed, contents, cargo_origin, weight_lb, barcode,
                    unit_label for cargo)
        label_type: "inventory" or "cargo"

    Returns PNG bytes (696px wide, variable height).
    """
    from PIL import ImageDraw, ImageFont

    W = _NATIVE_WIDTH_PX  # 696
    MARGIN = 20
    TEXT_W = W - 2 * MARGIN
    y = MARGIN

    # Try to load a decent font; fall back to default
    font_cache = {}
    def get_font(size):
        if size not in font_cache:
            for name in ("DejaVuSans.ttf", "LiberationSans-Regular.ttf",
                         "FreeSans.ttf", "arial.ttf", "Helvetica.ttf"):
                try:
                    font_cache[size] = ImageFont.truetype(name, size)
                    break
                except (OSError, IOError):
                    continue
            else:
                font_cache[size] = ImageFont.load_default(size=size)
        return font_cache[size]

    font_title = get_font(36)
    font_large = get_font(28)
    font_med   = get_font(22)
    font_small = get_font(18)
    font_label = get_font(16)

    # First pass: calculate height
    lines = []  # (font, text, bold)

    if label_type == "inventory":
        lines.append((font_title, label_data.get("name", ""), True))
        lines.append((font_large, f"{label_data.get('weight_lb', '')} lb per unit", False))
        if label_data.get("origin"):
            lines.append((font_med, label_data["origin"], False))
        if label_data.get("unit_label"):
            lines.append((font_large, f"Unit {label_data['unit_label']}", True))
    else:  # cargo
        lines.append((font_title, "CARGO ID", True))
        if label_data.get("unit_label"):
            lines[-1] = (font_title, f"CARGO ID  {label_data['unit_label']}", True)
        for label_key, display in [("mission", "Mission"), ("tail", "Tail #"),
                                    ("origin", "From"), ("destination", "To"),
                                    ("date_sealed", "Date"), ("contents", "Item"),
                                    ("cargo_origin", "Source"), ("weight_lb", "Weight")]:
            val = label_data.get(label_key, "")
            if not val:
                continue
            if label_key == "weight_lb":
                val = f"{val} lb"
            lines.append((font_label, f"{display}:", True))
            lines.append((font_med, f"  {val}", False))

    # Calculate total height
    barcode_height = 80 if label_data.get("barcode") else 0
    text_height = sum(f.size + 8 for f, _, _ in lines)
    total_h = MARGIN + barcode_height + 10 + text_height + MARGIN

    # Create image
    img = Image.new("RGB", (W, total_h), "white")
    draw = ImageDraw.Draw(img)

    # Draw border
    draw.rectangle([4, 4, W - 5, total_h - 5], outline="black", width=2)

    y = MARGIN

    # Draw barcode if present
    bc_val = label_data.get("barcode", "")
    if bc_val:
        try:
            import barcode as bc_lib
            from barcode.writer import ImageWriter
            writer = ImageWriter()
            writer.set_options({
                "module_width": 0.4,
                "module_height": 12.0,
                "font_size": 14,
                "text_distance": 2.0,
                "quiet_zone": 4.0,
                "write_text": True,
                "dpi": 300,
            })
            code = bc_lib.get("code128", bc_val, writer=writer)
            bc_buf = io.BytesIO()
            code.write(bc_buf)
            bc_img = Image.open(bc_buf)
            # Scale barcode to fit width
            bc_w = min(TEXT_W, bc_img.width)
            ratio = bc_w / bc_img.width
            bc_h = int(bc_img.height * ratio)
            bc_img = bc_img.resize((bc_w, bc_h), Image.LANCZOS)
            # Center barcode
            x_offset = (W - bc_w) // 2
            img.paste(bc_img, (x_offset, y))
            y += bc_h + 8
        except Exception as e:
            logger.warning("Barcode render failed: %s", e)
            draw.text((MARGIN, y), bc_val, fill="black", font=font_small)
            y += 24

    # Draw text lines
    for font, text, bold in lines:
        draw.text((MARGIN, y), text, fill="black", font=font)
        y += font.size + 8

    # Crop to actual content
    y += MARGIN
    img = img.crop((0, 0, W, min(y, img.height)))

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
