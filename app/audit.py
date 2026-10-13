"""Tamper-evident audit log.

Every row stores prev_hash and hash = SHA-256(prev_hash || canonical-JSON(row fields)),
so editing, inserting or deleting any earlier row breaks every later hash. On top of that
SQLite triggers (models.py) refuse UPDATE/DELETE on the table at the database level.
Rows are written in the same transaction as the change they describe.

Limitations: deleting the *newest* rows cannot be detected from inside the database --
export the head hash (`flask audit-verify`) to a separate system periodically.
Writes are serialised with a process lock; use PostgreSQL + advisory lock for multi-process.
"""
import hashlib
import json
import re
import threading
from datetime import datetime, timezone

from flask import has_request_context, request
from flask_login import current_user

from .models import AuditLog, db

GENESIS = "0" * 64
FIELDS = ("ts", "actor_id", "actor_name", "role", "action", "entity", "entity_id", "old_value", "new_value", "ip")
_lock = threading.Lock()
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=True)


def _hash(prev: str, payload: dict) -> str:
    return hashlib.sha256((prev + _canon(payload)).encode()).hexdigest()


def clean(value, n=80) -> str:
    """Strip control characters (log-injection) and bound the length."""
    return _CTRL.sub("", str(value))[:n]


def log(action, entity=None, entity_id=None, old=None, new=None, actor=None):
    """Append an audit row inside the caller's transaction. actor = (id, name, role)."""
    if actor is None:
        if has_request_context() and current_user.is_authenticated:
            actor = (current_user.id, current_user.username, current_user.role)
        else:
            actor = (None, "anonymous", None)
    payload = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "actor_id": actor[0],
        "actor_name": clean(actor[1]),
        "role": actor[2],
        "action": action,
        "entity": entity,
        "entity_id": None if entity_id is None else str(entity_id),
        "old_value": _canon(old) if old is not None else None,
        "new_value": _canon(new) if new is not None else None,
        "ip": request.remote_addr if has_request_context() else None,
    }
    with _lock:
        last = AuditLog.query.order_by(AuditLog.id.desc()).first()
        prev = last.hash if last else GENESIS
        row = AuditLog(**payload, prev_hash=prev, hash=_hash(prev, payload))
        db.session.add(row)
        db.session.flush()
    return row


def verify_rows(rows):
    """rows: iterable of dict-likes in id order. Returns (ok, rows_checked, first_bad_id, head_hash)."""
    prev, n = GENESIS, 0
    for r in rows:
        payload = {k: r[k] for k in FIELDS}
        if r["prev_hash"] != prev or r["hash"] != _hash(prev, payload):
            return False, n, r["id"], prev
        prev, n = r["hash"], n + 1
    return True, n, None, prev


def verify_chain():
    def rows():
        for r in AuditLog.query.order_by(AuditLog.id).yield_per(500):
            d = {k: getattr(r, k) for k in FIELDS}
            d.update(id=r.id, prev_hash=r.prev_hash, hash=r.hash)
            yield d
    return verify_rows(rows())
