"""Secure, policy-driven Student Placement Management System (NFSU, session 2026-27)."""
import os
import secrets
from datetime import timedelta

from cryptography.fernet import Fernet
from flask import Flask, render_template, request
from flask_login import LoginManager
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf
from markupsafe import Markup, escape

from . import crypto
from .models import COURSES, User, db
from .security import RateLimiter, can_see, has_perm

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
csrf = CSRFProtect()
login_manager = LoginManager()


def _persisted(instance_path, env, filename, make):
    """Env var wins; otherwise create-once, mode-0600 key file in instance/."""
    if os.environ.get(env):
        return os.environ[env]
    path = os.path.join(instance_path, filename)
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    value = make()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value)
    return value


@login_manager.user_loader
def load_user(session_id):
    try:
        uid, token = session_id.split(":", 1)
        user = db.session.get(User, int(uid))
    except (ValueError, AttributeError):
        return None
    if user and user.active and secrets.compare_digest(user.session_token, token):
        return user
    return None


def create_app(overrides=None):
    app = Flask(__name__, instance_path=os.path.join(BASE_DIR, "instance"))
    os.makedirs(app.instance_path, exist_ok=True)
    app.config.update(
        SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(app.instance_path, "placement.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("PLACEMENT_HTTPS") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),  # idle timeout (refreshed on every request)
        SESSION_REFRESH_EACH_REQUEST=True,
        ABSOLUTE_SESSION_HOURS=8,
        WTF_CSRF_TIME_LIMIT=3600,
        MAX_CONTENT_LENGTH=1024 * 1024,
        BCRYPT_ROUNDS=12,
        LOGIN_RATE=(10, 60),  # attempts per window (seconds) per client IP
        LOCKOUT_THRESHOLD=5,
        LOCKOUT_MINUTES=15,
        RETENTION_YEARS=5,
        EXPORT_ROW_CAP=5000,
        SWITCH_BY_CATEGORY=True,
        BACKUP_DIR=os.path.join(app.instance_path, "backups"),
    )
    if overrides:
        app.config.update(overrides)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = _persisted(app.instance_path, "SECRET_KEY", "secret.key", lambda: secrets.token_hex(32))
    if not app.config.get("FIELD_KEYS"):
        app.config["FIELD_KEYS"] = _persisted(app.instance_path, "FIELD_KEYS", "field.key",
                                              lambda: Fernet.generate_key().decode())
    crypto.init(app.config["FIELD_KEYS"])

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.session_protection = "strong"
    limit, per = app.config["LOGIN_RATE"]
    app.extensions["login_limiter"] = RateLimiter(limit, per)

    from .admin import bp as admin_bp
    from .auth import auth, main
    from .offers import bp as offers_bp
    from .students import bp as students_bp
    for bp in (main, auth, students_bp, offers_bp, admin_bp):
        app.register_blueprint(bp)

    @app.context_processor
    def inject():
        from flask_login import current_user
        return dict(
            has_perm=lambda p: has_perm(current_user, p),
            can_see=lambda field, student=None, company_id=None: can_see(current_user, field, student, company_id),
            COURSES=COURSES,
        )

    app.jinja_env.globals["csrf_input"] = lambda: Markup(
        f'<input type="hidden" name="csrf_token" value="{escape(generate_csrf())}">')

    @app.template_filter("ist")
    def ist(dt):
        return "-" if not dt else (dt + timedelta(hours=5, minutes=30)).strftime("%d %b %Y %H:%M IST")

    @app.template_filter("lpa")
    def lpa(v):
        return "-" if v is None else f"₹{v:,.2f} LPA"

    @app.template_filter("inr")
    def inr(v):
        return "-" if v is None else f"₹{v:,.0f}"

    @app.template_filter("pretty")
    def pretty(v):
        return str(v or "-").replace("_", " ")

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"  # personal and salary data must not be cached
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    def _err(code, title, msg):
        def handler(e):
            return render_template("error.html", code=code, title=title, msg=msg), code
        return handler

    app.register_error_handler(400, _err(400, "Bad request", "The request could not be processed."))
    app.register_error_handler(403, _err(403, "Forbidden", "Your role is not allowed to do that. The attempt was logged."))
    app.register_error_handler(404, _err(404, "Not found", "That page or record does not exist, or you cannot access it."))
    app.register_error_handler(405, _err(405, "Method not allowed", "That action is not available."))
    app.register_error_handler(413, _err(413, "File too large", "Uploads are limited to 1 MB."))
    app.register_error_handler(429, _err(429, "Too many attempts", "Please wait a minute and try again."))
    app.register_error_handler(500, _err(500, "Server error", "Something went wrong. Nothing sensitive is shown here."))

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        return render_template("error.html", code=400, title="Security check failed",
                               msg="Your form expired or was not submitted from this site. Reload the page and try again."), 400

    with app.app_context():
        db.create_all()

    from . import cli
    cli.register(app)
    return app
