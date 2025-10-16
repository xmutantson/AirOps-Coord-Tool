# modules/routes/wgclient.py

from flask import Blueprint, render_template, session

try:
    from flask_login import current_user  # optional
except Exception:  # pragma: no cover
    current_user = None  # type: ignore

bp = Blueprint("wgclient", __name__)

def _display_name() -> str:
    """
    Pick a friendly display name from session or flask_login current_user.
    Falls back to 'Guest'.
    """
    for key in ("display_name", "name", "username", "user"):
        val = session.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    try:
        if current_user and getattr(current_user, "is_authenticated", False):
            for attr in ("display_name", "name", "username", "email"):
                val = getattr(current_user, attr, None)
                if isinstance(val, str) and val.strip():
                    return val.strip()
    except Exception:
        pass
    return "Guest"

@bp.get("/wargame/play")
def wargame_play():
    player_name = _display_name()
    # `active` becomes a body class in base.html → lets us scope page-specific layout
    return render_template("wargame_play.html", player_name=player_name, active="wargame_play")
