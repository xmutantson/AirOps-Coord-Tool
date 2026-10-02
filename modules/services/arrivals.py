"""Durable direct-arrival request identity, owned by the flight write transaction."""
import hashlib
import json
from modules.services.inventory import InventoryConflict


def ensure_arrival_schema(c):
    c.execute("""CREATE TABLE IF NOT EXISTS arrival_requests (
        request_key TEXT PRIMARY KEY, payload_hash TEXT NOT NULL,
        flight_id INTEGER NOT NULL, session_id TEXT, response_json TEXT NOT NULL)""")


def resolve_arrival_request(c, request_id, data, manifest_id, flight_code):
    if not c.in_transaction:
        raise RuntimeError('Arrival identity requires a write transaction')
    ensure_arrival_schema(c)
    token = (request_id or '').strip()
    if len(token) > 128:
        raise InventoryConflict('Arrival request identity is too long.', 'arrival_conflict')
    payload = dict(data, manifest_id=manifest_id or '', flight_code=flight_code or '')
    digest = hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    # Legacy callers cannot distinguish two physically separate identical events.
    # Keep retries safe; a deliberate new event must provide a fresh request ID.
    key = 'request:' + token if token else 'legacy:' + digest
    prior = c.execute('SELECT payload_hash,flight_id,response_json FROM arrival_requests WHERE request_key=?', (key,)).fetchone()
    if prior:
        if prior[0] != digest:
            raise InventoryConflict('This arrival request was already used with different details.', 'arrival_conflict')
        if not c.execute('SELECT 1 FROM flights WHERE id=?', (prior[1],)).fetchone():
            raise InventoryConflict('This arrival was recorded and subsequently removed; reconcile before retrying.', 'arrival_closed')
        return key,digest,json.loads(prior[2])
    return key,digest,None


def record_arrival_request(c, key, digest, flight_id, session_id, action):
    if not c.in_transaction:
        raise RuntimeError('Arrival identity requires a write transaction')
    cursor = c.execute('SELECT * FROM flights WHERE id=?', (flight_id,))
    row = cursor.fetchone()
    response = dict(zip((col[0] for col in cursor.description),row))
    response['action'] = action
    c.execute('INSERT INTO arrival_requests VALUES (?,?,?,?,?)',
        (key,digest,flight_id,session_id,json.dumps(response)))
