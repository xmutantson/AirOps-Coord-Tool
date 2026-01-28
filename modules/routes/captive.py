# modules/routes/captive.py — Captive Portal Detection Responses
# ==============================================================
# These routes respond to connectivity checks from mobile devices
# to prevent them from disconnecting when WiFi has no internet.
#
# DNS Configuration Required (dnsmasq or router):
#   All endpoints below are HTTP-only (no HTTPS hijacking needed)
#
#   # Android (Google)
#   address=/connectivitycheck.gstatic.com/192.168.8.2
#   address=/clients3.google.com/192.168.8.2
#   address=/play.googleapis.com/192.168.8.2
#   address=/connectivitycheck.samsung.com/192.168.8.2
#
#   # iOS/macOS (Apple)
#   address=/captive.apple.com/192.168.8.2
#
#   # Windows (Microsoft)
#   address=/www.msftconnecttest.com/192.168.8.2
#   address=/www.msftncsi.com/192.168.8.2
#
#   # Firefox
#   address=/detectportal.firefox.com/192.168.8.2
#
# Note: DNS points to 192.168.8.253 (router secondary IP), which DNATs to Flask on 192.168.8.2:5150
# HTTP-only - HTTPS connectivity checks (e.g., GrapheneOS) will show "limited connection"
# Do NOT hijack www.google.com or www.apple.com - those are for real browsing

from flask import Blueprint, Response

bp = Blueprint('captive', __name__)


# ──────────────────────────────────────────────────────────────────────────────
# Android (Google) — expects HTTP 204 No Content
# ──────────────────────────────────────────────────────────────────────────────

@bp.route('/generate_204')
def android_generate_204():
    """Android connectivity check (connectivitycheck.gstatic.com, www.google.com, etc.)"""
    return Response(status=204)


# ──────────────────────────────────────────────────────────────────────────────
# iOS / macOS (Apple) — expects HTML body containing "Success"
# ──────────────────────────────────────────────────────────────────────────────

@bp.route('/hotspot-detect.html')
def ios_hotspot_detect():
    """iOS connectivity check (captive.apple.com)"""
    return Response(
        '<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>',
        status=200,
        content_type='text/html'
    )


# ──────────────────────────────────────────────────────────────────────────────
# Windows (Microsoft) — expects specific text responses
# ──────────────────────────────────────────────────────────────────────────────

@bp.route('/connecttest.txt')
def windows_connecttest():
    """Windows 10+ connectivity check (www.msftconnecttest.com)"""
    return Response('Microsoft Connect Test', status=200, content_type='text/plain')


@bp.route('/ncsi.txt')
def windows_ncsi():
    """Older Windows connectivity check (www.msftncsi.com)"""
    return Response('Microsoft NCSI', status=200, content_type='text/plain')


# ──────────────────────────────────────────────────────────────────────────────
# Firefox — expects "success\n"
# ──────────────────────────────────────────────────────────────────────────────

@bp.route('/success.txt')
def firefox_success():
    """Firefox connectivity check (detectportal.firefox.com)"""
    return Response('success\n', status=200, content_type='text/plain')


# ──────────────────────────────────────────────────────────────────────────────
# Samsung — some devices use their own endpoint, expects HTTP 204
# ──────────────────────────────────────────────────────────────────────────────
# Samsung uses /generate_204 on connectivitycheck.samsung.com
# Already covered by android_generate_204 above


