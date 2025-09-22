# modules/routes/training.py
from __future__ import annotations
import os
from typing import List, Dict
from flask import Blueprint, current_app, render_template, send_from_directory, abort, request, url_for
from werkzeug.utils import safe_join

bp = Blueprint("training", __name__, url_prefix="/training")

def _training_dir() -> str:
    """Resolve the directory holding training files."""
    data_root = os.getenv("AOCT_DATA_DIR") or os.path.join(os.getcwd(), "data")
    path = os.path.join(data_root, "training")
    os.makedirs(path, exist_ok=True)
    return path

def _list_files() -> List[Dict]:
    root = _training_dir()
    out: List[Dict] = []
    try:
        for name in sorted(os.listdir(root)):
            # Skip dotfiles and directories
            if name.startswith("."):
                continue
            full = os.path.join(root, name)
            if not os.path.isfile(full):
                continue
            out.append({
                "name": name,
                "bytes": os.path.getsize(full) if os.path.exists(full) else 0,
                "url": url_for("training.training_file", filename=name),
            })
    except Exception as e:
        try:
            current_app.logger.warning("Training list failed: %s", e)
        except Exception:
            pass
    return out

@bp.get("")
def training_index():
    """Training hub: lists files and shows the collapsible 'All Help Topics' directory."""
    files = _list_files()
    return render_template("training.html", files=files, training_dir=_training_dir())

@bp.get("/files/<path:filename>")
def training_file(filename: str):
    """Stream a file from the training directory (no upload, no delete)."""
    root = _training_dir()
    # prevent traversal; ensure path resolves under training dir
    safe_path = safe_join(root, filename)
    if not safe_path or not os.path.isfile(safe_path):
        abort(404)
    # Stream inline; let Flask/werkzeug infer content-type
    return send_from_directory(root, filename, as_attachment=False)
