import os, json, time, re, mimetypes
from datetime import datetime, timezone
from urllib.parse import unquote
from flask import Blueprint, request, jsonify, session
from flask import send_from_directory, abort
from markupsafe import escape

import sqlite3 as _sqlite
from modules.utils.common import ensure_help_tables, seed_help_from_yaml, get_db_file

bp = Blueprint("help", __name__, url_prefix="/help")

# ─────────────────────────────────────────────────────────────
# Helpers

def _now_utc_iso():
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00","Z")

def _norm_path(p: str) -> str:
    p = (p or "/").strip()
    if not p.startswith("/"):
        p = "/" + p
    # strip trailing slash except root
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1]
    return p

def _admin_unlocked() -> bool:
    s = session
    return bool(
        s.get("admin_unlocked") or
        s.get("is_admin") or
        s.get("admin")
    )

def _conn():
    # Use the app DB path from common.py to avoid circular imports
    return _sqlite.connect(get_db_file())

# ─────────────────────────────────────────────────────────────
# Markdown rendering (server-side) with sanitization

def _md_to_html(md_text: str) -> str:
    """
    Convert Markdown → sanitized HTML.
    - Tries python-markdown first, then markdown2, then commonmark.
    - Always sanitizes with bleach (if available).
    - Graceful fallback: escape + <pre> when no libs installed.
    """
    raw = md_text or ""
    html = None
    # 1) Convert
    try:
        import markdown  # python-markdown
        exts = ["extra", "sane_lists", "tables", "fenced_code", "codehilite"]
        html = markdown.markdown(raw, extensions=exts, output_format="html5")
    except Exception:
        try:
            import markdown2  # fallback
            extras = ["fenced-code-blocks", "tables", "strike", "cuddled-lists", "task_list"]
            html = markdown2.markdown(raw, extras=extras)
        except Exception:
            try:
                import commonmark
                parser = commonmark.Parser()
                renderer = commonmark.HtmlRenderer()
                ast = parser.parse(raw)
                html = renderer.render(ast)
            except Exception:
                html = None
    # 2) Sanitize + linkify
    try:
        import bleach
        # Use Linker to add rel="nofollow" and target="_blank" safely
        try:
            from bleach.linkifier import Linker, nofollow, target_blank
        except Exception:
            Linker = None  # type: ignore
            nofollow = None  # type: ignore
            target_blank = None  # type: ignore
        allowed_tags = [
            "p","br","hr","pre","code","kbd","samp",
            "h1","h2","h3","h4","h5","h6",
            "strong","em","del","sup","sub","blockquote",
            "ul","ol","li","dl","dt","dd",
            "table","thead","tbody","tr","th","td",
            "a","img"
        ]
        allowed_attrs = {
            "a": ["href","title","rel","target"],
            "img": ["src","alt","title","width","height"],
            "*": ["id","class"]
        }
        if html is None:
            # last-ditch readable fallback
            html = "<pre>" + escape(raw) + "</pre>"
        clean = bleach.clean(html, tags=allowed_tags, attributes=allowed_attrs, strip=True)
        if Linker is not None and nofollow is not None and target_blank is not None:
            linked = Linker(callbacks=[nofollow, target_blank]).linkify(clean)
        else:
            # Fallback: plain clean HTML without Linker callbacks
            linked = clean
        return f'<div class="help-md">{linked}</div>'
    except Exception:
        # No bleach installed — still return something (escaped if needed)
        if html is None:
            return "<pre>" + escape(raw) + "</pre>"
        return f'<div class="help-md">{html}</div>'

_FORMAT_GUIDE_MD = """# Markdown quick guide

**Headings**
```
# H1
## H2
### H3
```

**Emphasis**: `*italic*`, `**bold**`, `` `code` ``

**Lists**
```
- item
  - nested
1. ordered
```

**Links & images**
```
[Open Map](/map)
![Alt text](/static/img/example.png)
```

**Code blocks**
````
```python
def hello():
    print("hi")
```
````

**Tables**
```
| Item | Qty | Notes |
|---|---:|---|
| water | 20 | lbs each |
```

**Rules**: `---`
"""

def _get_article_for(path: str):
    path = _norm_path(path)
    # try exact, then walk up to parent(s); allow root fallback only if path == "/"
    candidates = []
    parts = path.strip("/").split("/") if path != "/" else []
    if path != "/":
        # exact
        candidates.append(path)
        # parents
        while parts:
            parts.pop()
            if parts:
                candidates.append("/" + "/".join(parts))
    else:
        candidates.append("/")

    with _conn() as cx:
        for rp in candidates:
            row = cx.execute("""SELECT route_prefix,title,body_md,version,updated_at_utc,is_active
                                 FROM help_articles
                                WHERE route_prefix=? AND is_active=1
                             """, (rp,)).fetchone()
            if row:
                return {
                    "route_prefix": row[0],
                    "title": row[1],
                    "body_md": row[2],
                    "version": row[3],
                    "updated_at_utc": row[4],
                    "editable": _admin_unlocked(),
                    "body_html": _md_to_html(row[2] or ""),
                }
    # No match. Per your constraint: do not 404 — return a placeholder.
    return {
        "route_prefix": None,
        "title": "No help for this page (yet)",
        "body_md": "There isn’t a help article for this page yet.\n\nAdmins can create one using the **Edit** button.",
        "version": 0,
        "updated_at_utc": _now_utc_iso(),
        "editable": _admin_unlocked(),
        "body_html": _md_to_html("There isn’t a help article for this page yet.\n\nAdmins can create one using the **Edit** button."),
        "not_found": True,
    }

# ─────────────────────────────────────────────────────────────
# Bootstrap (self-uninstalling) — works on Flask 3 where
# before_app_first_request was removed.

_help_bootstrapped = False

def _bootstrap_help_once():
    global _help_bootstrapped
    if _help_bootstrapped:
        return
    ensure_help_tables()
    seed_help_from_yaml(only_if_empty=True)
    _help_bootstrapped = True

@bp.before_app_request
def _bootstrap_hook():
    _bootstrap_help_once()

@bp.get("/api/article")
def api_get_article():
    _bootstrap_help_once()  # extra safety; idempotent
    # Accept several aliases so old callers keep working.
    path = (
        request.args.get("path")
        or request.args.get("for")
        or request.args.get("p")
        or "/"
    )
    path = unquote(path)
    art = _get_article_for(path)
    # Include a small Markdown guide when editing is allowed (or opt-in via ?guide=1)
    want_guide = request.args.get("guide") in ("1","true","yes") or art.get("editable")
    if want_guide:
        art["formatting_guide_md"] = _FORMAT_GUIDE_MD
        art["formatting_guide_html"] = _md_to_html(_FORMAT_GUIDE_MD)
    # ── Back-compat aliases so old clients work immediately ──────────────
    # body = rendered/sanitized HTML, raw = original Markdown
    try:
        art["body"] = art.get("body_html")
        art["raw"]  = art.get("body_md", "")
    except Exception:
        pass
    return jsonify(art)

@bp.put("/api/article")
def api_put_article():
    if not _admin_unlocked():
        return jsonify({"error":"forbidden"}), 403

    try:
        payload = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"error":"bad_json"}), 400

    rp   = _norm_path(payload.get("route_prefix",""))
    ttl  = (payload.get("title") or "").strip()
    body = payload.get("body_md") or ""
    ver  = int(payload.get("version") or 0)
    upd_by = session.get("callsign") or session.get("username") or None
    upd_at = _now_utc_iso()

    if not rp or not ttl:
        return jsonify({"error":"missing_fields"}), 400

    ensure_help_tables()
    with _conn() as cx:
        # optimistic concurrency: update where version matches; else 409
        cur = cx.execute("""UPDATE help_articles
                               SET title=?, body_md=?, version=version+1,
                                   updated_by=?, updated_at_utc=?, is_active=1, seeded=0
                             WHERE route_prefix=? AND version=?""",
                         (ttl, body, upd_by, upd_at, rp, ver))
        if cur.rowcount == 0:
            # Either new row or version mismatch; check existence
            exists = cx.execute("SELECT version FROM help_articles WHERE route_prefix=?", (rp,)).fetchone()
            if exists:
                return jsonify({"error":"version_conflict",
                                "current_version": exists[0]}), 409
            # Insert new
            cx.execute("""INSERT INTO help_articles
                          (route_prefix,title,body_md,is_active,seeded,version,updated_by,updated_at_utc)
                          VALUES (?,?,?,?,0,1,?,?)""",
                       (rp, ttl, body, 1, upd_by, upd_at))
            ver = 1

    return jsonify({
        "ok": True,
        "route_prefix": rp,
        "title": ttl,
        "body_md": body,
        "body_html": _md_to_html(body),
        # keep same aliases on write responses too
        "body": _md_to_html(body),
        "raw": body,
        "version": ver if ver else 1,
        "updated_at_utc": upd_at,
    })

# Back-compat for clients that POST instead of PUT.
@bp.post("/api/article")
def api_post_article():
    return api_put_article()

# ─────────────────────────────────────────────────────────────
# Video attachments (read-only, per help topic)

ALLOWED_VIDEO_EXTS = {'.mp4', '.m4v', '.mov', '.webm', '.avi', '.mkv'}

def _data_root():
    # same directory as the DB file
    from modules.utils.common import get_db_file
    return os.path.dirname(get_db_file())

def _videos_root():
    return os.path.join(_data_root(), "videos")

def _slugify_topic(path_or_slug: str) -> str:
    slug = (path_or_slug or "").lower().strip().strip("/")
    slug = re.sub(r"[^a-z0-9_-]+", "-", slug)
    return slug or "root"

def _find_single_video(topic_dir: str) -> str | None:
    if not os.path.isdir(topic_dir):
        return None
    files = []
    for name in os.listdir(topic_dir):
        if name.startswith("."):
            continue
        full = os.path.join(topic_dir, name)
        if os.path.islink(full) or not os.path.isfile(full):
            continue
        ext = os.path.splitext(name)[1].lower()
        if ext in ALLOWED_VIDEO_EXTS:
            files.append(name)
    if len(files) == 1:
        return files[0]
    return None

@bp.get("/video/<slug>")
def help_video(slug):
    # Serve the single allowed video for this help topic (if present)
    slug = _slugify_topic(slug)
    topic_dir = os.path.join(_videos_root(), slug)
    fname = _find_single_video(topic_dir)
    if not fname:
        abort(404)
    mime = mimetypes.guess_type(fname)[0] or "application/octet-stream"
    resp = send_from_directory(topic_dir, fname, mimetype=mime, as_attachment=False, conditional=True)
    resp.headers["X-Video-Filename"] = fname
    return resp
