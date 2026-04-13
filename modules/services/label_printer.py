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


def render_label_png(html_string, base_url):
    """Render label HTML to a cropped PNG sized for 62mm tape.

    Uses WeasyPrint to render HTML -> PNG, then Pillow to crop trailing
    whitespace and resize to 696px wide (62mm at 300 DPI).

    Returns PNG bytes.
    """
    from weasyprint import HTML, CSS

    # Force 62mm page width for consistent rendering
    override_css = CSS(string="""
        @page { size: 62mm auto; margin: 2mm; }
        body { margin: 0; width: 62mm; }
    """)
    png_bytes = HTML(
        string=html_string, base_url=base_url
    ).write_png(stylesheets=[override_css])

    img = Image.open(io.BytesIO(png_bytes)).convert("RGBA")

    # Crop trailing whitespace: find last non-white row
    # Convert to grayscale, find bounding box of non-white content
    gray = img.convert("L")
    bbox = gray.getbbox()  # (left, upper, right, lower)
    if bbox:
        # Keep full width, crop height to content + 20px padding
        bottom = min(bbox[3] + 20, img.height)
        img = img.crop((0, 0, img.width, bottom))

    # Resize to native 62mm width (696px at 300 DPI)
    if img.width != _NATIVE_WIDTH_PX:
        ratio = _NATIVE_WIDTH_PX / img.width
        new_h = max(1, int(img.height * ratio))
        img = img.resize((_NATIVE_WIDTH_PX, new_h), Image.LANCZOS)

    # Convert to RGB (brother_ql expects no alpha channel)
    if img.mode != "RGB":
        bg = Image.new("RGB", img.size, (255, 255, 255))
        if img.mode == "RGBA":
            bg.paste(img, mask=img.split()[3])
        else:
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

        if result.get("did_print"):
            return {"ok": True}
        return {"ok": False, "error": result.get("printer_state", {}).get("errors", ["Unknown error"])}

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
