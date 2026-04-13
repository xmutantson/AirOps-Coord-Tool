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

    # Render at a size where CSS pixels map to 300 DPI print pixels.
    # 62mm at 300 DPI = 696px. At PDF's 72 DPI that's 696*(72/300) = 166.9pt.
    # But we want fonts to look right, so we render the page at a wider pt size
    # and then rasterize at a higher DPI to hit 696px final width.
    # Strategy: 250pt wide page (~88mm), render PDF at 200 DPI → ~694px.
    # This makes CSS px fonts ~2.8x larger than the 62mm approach.
    override_css = CSS(string="""
        @page { size: 250pt 800pt; margin: 6pt; }
        body { margin: 0; width: 238pt; font-size: 14pt; }
        header, nav, .sidebar, .hide-on-print, .main-nav,
        button, .button, input, select, textarea,
        .label-size-hint, .inv-tag-hint,
        .print-page, #toast-container, .hamburger-container,
        #nav-dropdown, #nav-backdrop, footer,
        .initialize-btn { display: none !important; }
        /* Scale up label fonts for thermal print readability */
        .inv-tag .tag-name { font-size: 16pt !important; }
        .inv-tag .tag-weight { font-size: 12pt !important; }
        .inv-tag .tag-origin { font-size: 10pt !important; }
        .inv-tag .tag-unit { font-size: 13pt !important; font-weight: 700 !important; }
        .label-card h3 { font-size: 14pt !important; }
        .label-card td { font-size: 11pt !important; padding: 2pt 4pt !important; }
        .label-card td:first-child { font-weight: 700; }
    """)

    # WeasyPrint 60+ removed write_png(); render PDF then convert via Pillow
    pdf_bytes = HTML(
        string=html_string, base_url=base_url
    ).write_pdf(stylesheets=[override_css], presentational_hints=True)

    # PDF -> PNG via pypdfium2 or fitz fallback
    # Render at 200 DPI: 250pt * (200/72) ≈ 694px wide (close to 696 target)
    try:
        import pypdfium2 as pdfium
        pdf = pdfium.PdfDocument(pdf_bytes)
        page = pdf[0]
        bitmap = page.render(scale=200 / 72)
        pil_img = bitmap.to_pil()
        png_buf = io.BytesIO()
        pil_img.save(png_buf, format="PNG")
        png_bytes = png_buf.getvalue()
    except ImportError:
        try:
            import fitz  # PyMuPDF
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            page = doc[0]
            pix = page.get_pixmap(dpi=300)
            png_bytes = pix.tobytes("png")
        except ImportError:
            # Last resort: use pdf2image / Pillow with ghostscript
            raise RuntimeError(
                "No PDF-to-PNG converter available. Install pypdfium2 or PyMuPDF."
            )

    img = Image.open(io.BytesIO(png_bytes)).convert("RGBA")

    # Crop trailing whitespace: find last non-white row
    # Convert to grayscale, find bounding box of non-white content
    gray = img.convert("L")
    bbox = gray.getbbox()  # (left, upper, right, lower)
    if bbox:
        # Keep full width, crop height to content + 20px padding
        bottom = min(bbox[3] + 20, img.height)
        img = img.crop((0, 0, img.width, bottom))

    # If the image is wider than tall (landscape), rotate 90° so it feeds
    # correctly on the 62mm tape (tape width = image width)
    if img.width > img.height:
        img = img.rotate(90, expand=True)

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
