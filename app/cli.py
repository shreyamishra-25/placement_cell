"""Operational commands:  flask --app run <command>"""
import os
import secrets

import click

from . import audit, backup, crypto
from .auth import hash_password, password_problems
from .models import Offer, Student, User, db


def register(app):
    @app.cli.command("seed")
    def seed():
        """Load demo data (fake students, companies, offers, demo logins)."""
        from .seed import seed_demo
        seed_demo()
        click.echo("Demo data loaded. See README for the demo logins.")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.password_option()
    def create_admin(username, password):
        """Create (or reset) an administrator account."""
        username = username.strip().lower()
        problems = password_problems(password, username)
        if problems:
            raise click.ClickException("Password needs: " + ", ".join(problems))
        u = User.query.filter_by(username=username).first()
        if u is None:
            u = User(username=username, role="admin", password_hash="x", session_token=secrets.token_hex(16))
            db.session.add(u)
        u.password_hash, u.role, u.active = hash_password(password), "admin", True
        db.session.flush()
        audit.log("USER_CREATE", "user", u.id, new={"username": username, "role": "admin", "via": "cli"},
                  actor=(None, "cli", "system"))
        db.session.commit()
        click.echo(f"Admin '{username}' ready.")

    @app.cli.command("backup")
    def do_backup():
        """Write an encrypted backup to instance/backups/."""
        path = backup.create_backup(_db_path(app), app.config["BACKUP_DIR"], app.config["FIELD_KEYS"])
        audit.log("BACKUP_CREATE", "backup", os.path.basename(path), actor=(None, "cli", "system"))
        db.session.commit()
        click.echo(path)

    @app.cli.command("restore")
    @click.argument("backup_file", type=click.Path(exists=True))
    @click.option("--verify-only", is_flag=True, help="Check the backup without restoring it.")
    def do_restore(backup_file, verify_only):
        """Verify an encrypted backup and (unless --verify-only) swap it in. Stop the app first."""
        if verify_only:
            ok, msg, tmp = backup.verify_backup(backup_file, app.config["FIELD_KEYS"])
            if tmp and os.path.exists(tmp):
                os.remove(tmp)
        else:
            db.engine.dispose()
            ok, msg = backup.restore_backup(backup_file, _db_path(app), app.config["FIELD_KEYS"])
        click.echo(msg)
        raise SystemExit(0 if ok else 1)

    @app.cli.command("audit-verify")
    def audit_verify():
        """Check the audit hash chain; print the head hash to anchor off-system."""
        ok, n, bad, head = audit.verify_chain()
        click.echo(f"chain {'OK' if ok else 'BROKEN at row ' + str(bad)}; {n} rows; head={head}")
        raise SystemExit(0 if ok else 1)

    @app.cli.command("rotate-keys")
    def rotate_keys():
        """Re-encrypt every sensitive field with the PRIMARY key (first in FIELD_KEYS)."""
        n = 0
        for s in Student.query.all():
            db.session.execute(db.text("UPDATE students SET mobile=:m WHERE id=:i"),
                               {"m": crypto.encrypt(s.mobile) if s.mobile else None, "i": s.id})
            n += 1
        for o in Offer.query.all():
            db.session.execute(db.text("UPDATE offers SET ctc_lpa=:c, stipend=:s WHERE id=:i"),
                               {"c": crypto.encrypt(repr(o.ctc_lpa)) if o.ctc_lpa is not None else None,
                                "s": crypto.encrypt(repr(o.stipend)) if o.stipend is not None else None, "i": o.id})
        audit.log("KEYS_ROTATED", "system", None, new={"students": n}, actor=(None, "cli", "system"))
        db.session.commit()
        click.echo(f"Re-encrypted {n} students and all offers.")


def _db_path(app):
    return app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "", 1)
