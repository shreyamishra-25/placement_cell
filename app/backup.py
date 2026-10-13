"""Encrypted backups with a verified restore procedure.

backup : consistent copy via SQLite's online-backup API -> Fernet-encrypted file.
restore: decrypt -> PRAGMA integrity_check -> audit hash-chain verification -> only then
         swap into place (the previous DB is kept as <db>.pre-restore).
Keep the backup key (FIELD_KEYS / instance/field.key) separate from the backup files.
"""
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken

from . import audit


def _first_key(keys):
    return (keys.split(",")[0] if isinstance(keys, str) else keys[0]).strip()


def create_backup(db_path, out_dir, keys):
    os.makedirs(out_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        src, dst = sqlite3.connect(db_path), sqlite3.connect(tmp)
        with dst:
            src.backup(dst)
        src.close()
        dst.close()
        with open(tmp, "rb") as f:
            blob = Fernet(_first_key(keys).encode()).encrypt(f.read())
    finally:
        os.remove(tmp)
    path = os.path.join(out_dir, f"placement-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.db.enc")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(blob)
    return path


def verify_backup(path, keys):
    """Decrypt and check a backup without touching the live DB. Returns (ok, message, plain_tmp_path)."""
    klist = [k.strip() for k in (keys.split(",") if isinstance(keys, str) else keys)]
    with open(path, "rb") as f:
        blob = f.read()
    plain = None
    for k in klist:
        try:
            plain = Fernet(k.encode()).decrypt(blob)
            break
        except InvalidToken:
            continue
    if plain is None:
        return False, "Cannot decrypt backup with the supplied key(s).", None
    fd, tmp = tempfile.mkstemp(suffix=".db")
    with os.fdopen(fd, "wb") as f:
        f.write(plain)
    con = sqlite3.connect(tmp)
    con.row_factory = sqlite3.Row
    try:
        if con.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            return False, "SQLite integrity check failed.", tmp
        rows = con.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        ok, n, bad, _ = audit.verify_rows([dict(r) for r in rows])
        if not ok:
            return False, f"Audit chain broken at row {bad}.", tmp
        return True, f"OK - integrity passed, audit chain intact ({n} rows).", tmp
    finally:
        con.close()


def restore_backup(path, target_db_path, keys):
    ok, msg, tmp = verify_backup(path, keys)
    try:
        if not ok:
            return False, msg
        if os.path.exists(target_db_path):
            shutil.copy2(target_db_path, target_db_path + ".pre-restore")
        shutil.copy2(tmp, target_db_path)
        return True, msg
    finally:
        if tmp and os.path.exists(tmp):
            os.remove(tmp)
