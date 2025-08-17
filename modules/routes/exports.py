
import sqlite3, csv, io, zipfile

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from app import DB_FILE
from flask import Blueprint, current_app
from flask import flash, redirect, request, url_for, send_file
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

@bp.route('/export_csv')
def export_csv():
    """Download all raw Winlink traffic as a CSV file, including remarks."""
    buf   = io.StringIO()
    csv_w = csv.writer(buf)

    # 1) Header now has 12 columns
    csv_w.writerow([
        'Sender','Subject','Body','Timestamp',
        'Tail#','From','To','T/O','ETA','Cargo','Weight','Remarks'
    ])

    with sqlite3.connect(DB_FILE) as c:
        # 2) Pull the remarks column as the final field
        rows = c.execute("""
            SELECT
              sender, subject, body, timestamp,
              tail_number, airfield_takeoff, airfield_landing,
              takeoff_time, eta, cargo_type, cargo_weight,
              remarks
            FROM incoming_messages
        """)
        for row in rows:
            # row is a tuple of 12 items, so s for s in row works
            csv_w.writerow([
                # flatten any internal line breaks
                s.replace('\r',' ').replace('\n',' ')
                if isinstance(s, str) else s
                for s in row
            ])

    # 3) Stream it back as before
    buf.seek(0)
    return send_file(
        io.BytesIO(buf.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='incoming_messages.csv'
    )

@bp.route('/export_all_csv')
def export_all_csv():
    """Download incoming, outgoing, and inventory logs as a ZIP."""
    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        conn = sqlite3.connect(DB_FILE)

        # --- communications.csv (mixed inbound + outbound) ---
        buf = io.StringIO(); cw = csv.writer(buf)
        cw.writerow([
            'Timestamp','Direction','Contact','Tail#',
            'From','To','T/O','ETA','Cargo','Weight',
            'Subject','Body'
        ])
        query = """
          SELECT timestamp,
                 'Inbound'    AS direction,
                 sender       AS contact,
                 tail_number,
                 airfield_takeoff  AS origin,
                 airfield_landing  AS destination,
                 takeoff_time      AS takeoff,
                 eta,
                 cargo_type        AS cargo,
                 cargo_weight      AS weight,
                 subject,
                 body
            FROM incoming_messages
          UNION ALL
          SELECT om.timestamp,
                 'Outbound'   AS direction,
                 om.operator_call   AS contact,
                 f.tail_number,
                 f.airfield_takeoff AS origin,
                 f.airfield_landing AS destination,
                 f.takeoff_time     AS takeoff,
                 f.eta,
                 f.cargo_type       AS cargo,
                 f.cargo_weight     AS weight,
                 om.subject,
                 om.body
            FROM outgoing_messages om
            JOIN flights f ON f.id = om.flight_id
          ORDER BY timestamp
        """
        for row in conn.execute(query):
            cw.writerow([
                (s.replace('\r',' ').replace('\n',' ')
                  if isinstance(s, str) else s)
                for s in row
            ])
        zf.writestr('communications.csv', buf.getvalue())

        # --- inventory_entries.csv ---
        buf = io.StringIO(); cw = csv.writer(buf)
        cw.writerow([
            'ID','CategoryID','RawName','SanitizedName',
            'WeightPerUnit','Quantity','TotalWeight',
            'Direction','Timestamp','Source'
        ])
        for row in conn.execute("""
            SELECT id, category_id, raw_name, sanitized_name,
                   weight_per_unit, quantity, total_weight,
                   direction, timestamp, source
              FROM inventory_entries
        """):
            cw.writerow(row)
        zf.writestr('inventory_entries.csv', buf.getvalue())

        conn.close()

    mem_zip.seek(0)
    return send_file(
        mem_zip,
        mimetype='application/zip',
        as_attachment=True,
        download_name='export_all.zip'
    )

@bp.route('/import_csv', methods=['POST'])
def import_csv():
    f = request.files.get('csv_file')
    if not f:
        flash("No file selected for import.", "error")
        return redirect(url_for('preferences.preferences'))

    text   = f.read().decode('utf-8', errors='replace')
    rdr    = csv.reader(io.StringIO(text))
    header = [h.strip().lower() for h in next(rdr, [])]
    expected = ['sender','subject','body','timestamp',
                'tail#','from','to','t/o','eta','cargo','weight','remarks']
    if header != expected:
        flash(f"Bad CSV header: {header}", "error")
        return redirect(url_for('preferences.preferences'))

    inserted = 0
    # switch to DictReader so we can refer to rec['Remarks']
    dictreader = csv.DictReader(io.StringIO(text), fieldnames=header)
    # skip the header row
    next(dictreader)

    for rec in dictreader:
        # build a parsed record
        p = parse_csv_record({
            'Sender':    rec['sender'],
            'Subject':   rec['subject'],
            'Body':      rec['body'],
            'Timestamp': rec['timestamp'],
            'Tail#':     rec['tail#'],
            'From':      rec['from'],
            'To':        rec['to'],
            'T/O':       rec['t/o'],
            'ETA':       rec['eta'],
            'Cargo':     rec['cargo'],
            'Weight':    rec['weight'],
            'Remarks':   rec['remarks']
        })

        # apply it — this writes to incoming_messages *and* updates/creates a flights row
        fid, action = apply_incoming_parsed(p)
        inserted += 1

    flash(f"Imported and applied {inserted} rows from CSV.", "import")
    # if we came from the Admin console, stay there
    ref = request.referrer or ""
    if ref.endswith(url_for('admin.admin')) or "/admin" in ref:
        return redirect(url_for('admin.admin'))
    return redirect(url_for('preferences.preferences'))
