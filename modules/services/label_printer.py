# modules/services/label_printer.py
"""Direct printing to Brother QL-820NWB via TCP (brother_ql library).

Renders labels as PNG images via Pillow, sends raster data to the printer
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
    """Generate a Code128 barcode as inline SVG markup."""
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
    for marker in ("<?xml", "<!DOCTYPE"):
        idx = svg_str.find(marker)
        if idx >= 0:
            end = svg_str.find(">", idx)
            if end >= 0:
                svg_str = svg_str[:idx] + svg_str[end + 1:]
    return svg_str.strip()


def _load_font(size, _cache={}):
    """Load a TrueType font with fallback chain."""
    from PIL import ImageFont
    if size not in _cache:
        for n in ("DejaVuSans-Bold.ttf", "DejaVuSans.ttf",
                  "LiberationSans-Bold.ttf", "LiberationSans-Regular.ttf",
                  "FreeSans.ttf", "arial.ttf"):
            try:
                _cache[size] = ImageFont.truetype(n, size)
                break
            except (OSError, IOError):
                continue
        else:
            _cache[size] = ImageFont.load_default(size=size)
    return _cache[size]


def _load_label_icon(size=48):
    """Load the Air Ops icon for label printing (B&W, transparent background)."""
    import os
    icon_path = os.path.join(os.path.dirname(__file__), "..", "..", "static", "label_icon.png")
    try:
        icon = Image.open(icon_path).convert("RGBA")
        icon = icon.resize((size, size), Image.LANCZOS)
        return icon
    except Exception:
        return None


def _render_barcode_image(bc_val, target_width=None, target_height=None):
    """Render a Code128 barcode as a Pillow Image."""
    import barcode as bc_lib
    from barcode.writer import ImageWriter
    writer = ImageWriter()
    writer.set_options({
        "module_width": 0.5,
        "module_height": 15.0,
        "font_size": 14,
        "text_distance": 2.0,
        "quiet_zone": 4.0,
        "write_text": True,
        "dpi": 300,
    })
    code = bc_lib.get("code128", bc_val, writer=writer)
    buf = io.BytesIO()
    code.write(buf)
    img = Image.open(buf).convert("RGB")
    # Scale to fit target dimensions if specified
    if target_width and img.width > target_width:
        r = target_width / img.width
        img = img.resize((target_width, int(img.height * r)), Image.LANCZOS)
    if target_height and img.height > target_height:
        r = target_height / img.height
        img = img.resize((int(img.width * r), target_height), Image.LANCZOS)
    return img


def render_label_png(label_data, label_type="inventory_tag"):
    """Render a label to a 696px-wide PNG for 62mm continuous tape.

    label_type:
      "inventory_tag" — compact portrait: barcode across full width + name + weight.
                        Minimal tape. Purpose: slap a barcode on an item.
      "cargo"         — full shipping label: rotated landscape with barcode on left,
                        all flight info on right, uses full 2.4" tape width for text.

    Returns PNG bytes (always 696px wide).
    """
    from PIL import ImageDraw

    W = _NATIVE_WIDTH_PX  # 696
    PAD = 20

    bc_val = label_data.get("barcode", "")
    unit_label = label_data.get("unit_label", "")

    if label_type == "inventory_tag":
        return _render_inventory_tag(label_data, bc_val, unit_label)
    else:
        return _render_cargo_label(label_data, bc_val, unit_label)


def _render_inventory_tag(label_data, bc_val, unit_label):
    """Compact portrait label: barcode + name + weight. Minimal tape usage."""
    from PIL import ImageDraw

    W = _NATIVE_WIDTH_PX
    PAD = 16
    LINE_GAP = 6

    # Content
    name = label_data.get("name", "")
    weight = f'{label_data.get("weight_lb", "")} lb/unit'
    source = (label_data.get("cargo_origin") or label_data.get("origin") or "").strip()

    # Calculate height
    y = PAD
    bc_h = 0
    if bc_val:
        try:
            bc_img = _render_barcode_image(bc_val, target_width=W - 2 * PAD)
            bc_h = bc_img.height
        except Exception:
            bc_h = 30
    y += bc_h + LINE_GAP if bc_val else 0

    # Text sizes — fit across 696px width, don't need to be huge
    name_sz = min(40, max(24, (W - 2 * PAD) // max(1, len(name)) * 2))
    wt_sz = 24
    origin_sz = 20

    y += name_sz + LINE_GAP
    y += wt_sz + LINE_GAP
    if source:
        y += origin_sz + LINE_GAP
    # Reserve space for icon at bottom
    icon = _load_label_icon(108)
    icon_h = icon.height + LINE_GAP if icon else 0
    y += icon_h + PAD

    # Draw
    img = Image.new("RGB", (W, y), "white")
    draw = ImageDraw.Draw(img)
    draw.rectangle([2, 2, W - 3, y - 3], outline="black", width=2)

    cy = PAD

    # Barcode across full width (no unit counter on inventory tags)
    if bc_val:
        try:
            bc_img = _render_barcode_image(bc_val, target_width=W - 2 * PAD)
            img.paste(bc_img, ((W - bc_img.width) // 2, cy))
            cy += bc_img.height + LINE_GAP
        except Exception as e:
            logger.warning("Barcode render failed: %s", e)
            draw.text((PAD, cy), bc_val, fill="black", font=_load_font(16))
            cy += 22

    # Name centered
    f = _load_font(name_sz)
    bbox = draw.textbbox((0, 0), name, font=f)
    tw = bbox[2] - bbox[0]
    draw.text((max(PAD, (W - tw) // 2), cy), name, fill="black", font=f)
    cy += name_sz + LINE_GAP

    # Weight centered
    f = _load_font(wt_sz)
    bbox = draw.textbbox((0, 0), weight, font=f)
    tw = bbox[2] - bbox[0]
    draw.text((max(PAD, (W - tw) // 2), cy), weight, fill="black", font=f)
    cy += wt_sz + LINE_GAP

    # Source centered
    if source:
        src_text = f"Source: {source}"
        f = _load_font(origin_sz)
        bbox = draw.textbbox((0, 0), src_text, font=f)
        tw = bbox[2] - bbox[0]
        draw.text((max(PAD, (W - tw) // 2), cy), src_text, fill="black", font=f)
        cy += origin_sz + LINE_GAP

    # Air Ops icon bottom-right
    if icon:
        img.paste(icon, (W - PAD - icon.width, y - PAD - icon.height), icon)

    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


def _render_cargo_label(label_data, bc_val, unit_label):
    """Full shipping label: landscape draw, rotated 90 deg for tape feed."""
    from PIL import ImageDraw

    TAPE_PX = _NATIVE_WIDTH_PX  # 696
    PAD = 20
    LINE_GAP = 4
    CONTENT_H = TAPE_PX - 2 * PAD

    # Get real mission number
    mission_num = ""
    try:
        from modules.utils.common import get_preference
        mission_num = get_preference("mission_number") or ""
    except Exception:
        pass

    # Build text rows: (text, relative_weight)
    raw_rows = []
    raw_rows.append(("CARGO ID", 4))
    m = mission_num or label_data.get("mission", "")
    if m:
        raw_rows.append((f"Mission: {m}", 3))
    if label_data.get("tail"):
        raw_rows.append((f"Tail: {label_data['tail']}", 3))
    orig = label_data.get("origin", "")
    dest = label_data.get("destination", "")
    if orig and dest:
        raw_rows.append((f"{orig} -> {dest}", 3))
    elif orig:
        raw_rows.append((f"From: {orig}", 3))
    elif dest:
        raw_rows.append((f"To: {dest}", 3))
    if label_data.get("date_sealed"):
        raw_rows.append((f"Date: {label_data['date_sealed']}", 3))
    contents = label_data.get("contents", "")
    if contents:
        if ": " in contents:
            parts = contents.split(": ", 1)
            if len(parts[0]) < 30:
                contents = parts[1]
        item_text = f"Item: {contents}"
        if unit_label:
            item_text += f" ({unit_label})"
        raw_rows.append((item_text, 3))
    if label_data.get("cargo_origin"):
        raw_rows.append((f"Source: {label_data['cargo_origin']}", 3))
    wt = label_data.get("weight_lb", "")
    if wt:
        raw_rows.append((f"Weight: {wt} lb", 3))

    # Scale fonts to fill tape height
    total_weight = sum(w for _, w in raw_rows)
    num_gaps = len(raw_rows) - 1
    px_per_weight = CONTENT_H / (total_weight + num_gaps * 0.3)
    rows = [(text, max(20, min(80, int(px_per_weight * w)))) for text, w in raw_rows]

    # Render barcode rotated 90 deg left (bars span tape width)
    bc_block_w = 0
    bc_img_final = None
    if bc_val:
        try:
            bc_raw = _render_barcode_image(bc_val)
            bc_rotated = bc_raw.rotate(90, expand=True)
            if bc_rotated.height > CONTENT_H:
                r = CONTENT_H / bc_rotated.height
                bc_rotated = bc_rotated.resize(
                    (int(bc_rotated.width * r), int(bc_rotated.height * r)),
                    Image.LANCZOS)
            bc_img_final = bc_rotated
            bc_block_w = bc_rotated.width + PAD
        except Exception as e:
            logger.warning("Barcode render failed: %s", e)

    # Measure text width
    _m = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    text_block_w = max(
        _m.textbbox((0, 0), t, font=_load_font(s))[2] for t, s in rows
    )
    unit_w = 0

    # Reserve space for icon column on the right — never truncate text,
    # just make the label longer (tape is continuous, length is free)
    _icon_reserve = 120 + PAD * 2  # icon size + padding
    total_w = PAD + bc_block_w + text_block_w + PAD + _icon_reserve + PAD
    total_w = max(total_w, 400)

    # Draw landscape
    img = Image.new("RGB", (total_w, TAPE_PX), "white")
    draw = ImageDraw.Draw(img)
    draw.rectangle([3, 3, total_w - 4, TAPE_PX - 4], outline="black", width=2)

    # Barcode on left
    if bc_img_final:
        img.paste(bc_img_final, (PAD, (TAPE_PX - bc_img_final.height) // 2))
        sep_x = PAD + bc_block_w - PAD // 2
        draw.line([(sep_x, PAD), (sep_x, TAPE_PX - PAD)], fill="#999999", width=1)

    text_x = PAD + bc_block_w

    # Icon top-right (unit counter is now part of the Item: line)
    icon = _load_label_icon(120)
    icon_y_offset = PAD
    icon_reserve = (icon.width + PAD * 2) if icon else 0
    if icon:
        img.paste(icon, (total_w - PAD - icon.width, icon_y_offset), icon)

    # Text rows vertically centered
    total_text_h = sum(sz + LINE_GAP for _, sz in rows) - LINE_GAP
    y = max(PAD, (TAPE_PX - total_text_h) // 2)
    for text, sz in rows:
        draw.text((text_x, y), text, fill="black", font=_load_font(sz))
        y += sz + LINE_GAP

    # Rotate 90 deg CW for tape feed
    img = img.rotate(-90, expand=True)

    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


def send_to_printer(image_bytes, printer_ip, cut=True):
    """Send a PNG image to the Brother QL printer via TCP."""
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
    """Quick TCP connect probe to port 9100."""
    try:
        s = socket.create_connection((printer_ip, 9100), timeout=2)
        s.close()
        return {"reachable": True, "ip": printer_ip}
    except Exception:
        return {"reachable": False, "ip": printer_ip}


# ── mDNS / Zeroconf auto-discovery ────────────────────────────────────

_discovered_ip = None


def discover_printer(timeout=5):
    """Scan the LAN for a Brother QL printer via mDNS."""
    global _discovered_ip
    from zeroconf import Zeroconf, ServiceBrowser

    found = {}

    class _Listener:
        def add_service(self, zc, stype, name):
            info = zc.get_service_info(stype, name)
            if info and info.parsed_addresses():
                low = name.lower()
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
    """Return the configured or auto-discovered printer IP."""
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
    """Run at startup: always re-scan for the printer (IP may change via DHCP)."""
    try:
        from modules.utils.common import get_preference, set_preference

        # Always re-scan — don't skip just because an IP is saved
        ip = discover_printer(timeout=5)
        existing_ip = (get_preference("printer_ip") or "").strip()

        if ip and ip != existing_ip:
            set_preference("printer_ip", ip)
            logger.info("Printer IP updated: %s -> %s", existing_ip, ip)
        elif ip:
            logger.info("Printer IP confirmed: %s", ip)
        elif existing_ip:
            # Discovery failed but we have a saved IP — keep it
            logger.info("Printer discovery failed, keeping saved IP: %s", existing_ip)
            ip = existing_ip
        else:
            logger.info("No printer found and no saved IP")

        if get_preference("direct_print_enabled") is None:
            set_preference("direct_print_enabled", "yes")
        return ip
    except Exception as e:
        logger.warning("Auto-configure printer failed: %s", e)
        return None


def backfill_barcodes():
    """Generate barcodes for inventory items that predate the barcode system."""
    try:
        import sqlite3
        import hashlib
        from datetime import datetime
        from app import DB_FILE
        from modules.routes_inventory.barcodes import _generate_barcode_id, _ensure_barcode_schema

        _ensure_barcode_schema()
        count = 0
        with sqlite3.connect(DB_FILE) as c:
            c.row_factory = sqlite3.Row
            rows = c.execute("""
                SELECT e.category_id, e.sanitized_name, e.weight_per_unit,
                       MIN(e.raw_name) AS raw_name
                  FROM inventory_entries e
                 WHERE e.sanitized_name IS NOT NULL
                   AND e.weight_per_unit > 0
                   AND NOT EXISTS (
                     SELECT 1 FROM inventory_barcodes b
                      WHERE b.category_id = e.category_id
                        AND b.sanitized_name = e.sanitized_name
                        AND ABS(b.weight_per_unit - e.weight_per_unit) < 0.001
                        AND (b.deleted = 0 OR b.deleted IS NULL)
                   )
                 GROUP BY e.category_id, e.sanitized_name, e.weight_per_unit
            """).fetchall()

            now = datetime.utcnow().isoformat()
            for r in rows:
                bc = _generate_barcode_id(r["category_id"], r["sanitized_name"], r["weight_per_unit"])
                existing = c.execute("SELECT 1 FROM inventory_barcodes WHERE barcode=?", (bc,)).fetchone()
                if existing:
                    bc = bc + "-" + hashlib.sha256(
                        f"{bc}{now}".encode()
                    ).hexdigest()[:4].upper()
                c.execute(
                    """INSERT INTO inventory_barcodes(barcode, category_id, sanitized_name,
                         raw_name, weight_per_unit, created_at, updated_at, deleted)
                       VALUES (?,?,?,?,?,?,?,0)""",
                    (bc, r["category_id"], r["sanitized_name"],
                     r["raw_name"] or r["sanitized_name"], r["weight_per_unit"], now, now),
                )
                count += 1
            if count:
                c.commit()
                logger.info("Backfilled %d barcodes for pre-existing inventory items", count)
    except Exception as e:
        logger.warning("Barcode backfill failed: %s", e)


def print_label_async(html_string, base_url, printer_ip):
    """Render label HTML and send to printer in a background thread."""
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
