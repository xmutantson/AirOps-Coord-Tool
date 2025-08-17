

from flask import Blueprint, current_app
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

@bp.route('/trigger-500')
def trigger_500():
    # this will always throw, producing a 500
    raise RuntimeError("💥 Test internal server error")
