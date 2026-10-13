"""Authentication: bcrypt, lockout, rate limiting, optional TOTP MFA, secure sessions."""
import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
from datetime import timedelta
from urllib.parse import urlparse

import bcrypt
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from . import audit
from .models import User, db, utcnow
from .security import has_perm
from .services import expire_overdue

auth = Blueprint("auth", __name__)
main = Blueprint("main", __name__)

# ---- passwords ------------------------------------------------------------------------------
_COMMON = {"password", "password123", "admin123", "welcome123", "qwerty123", "letmein123", "iloveyou123"}


def _pre(pw: str) -> bytes:
    # bcrypt silently truncates (or, in bcrypt>=5, rejects) inputs over 72 bytes; pre-hash to avoid both.
    return base64.b64encode(hashlib.sha256(pw.encode()).digest())


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(_pre(pw), bcrypt.gensalt(current_app.config["BCRYPT_ROUNDS"])).decode()


def verify_password(hashed: str, pw: str) -> bool:
    try:
        return bcrypt.checkpw(_pre(pw), hashed.encode())
    except ValueError:
        return False


def password_problems(pw: str, username: str = ""):
    p = []
    if len(pw) < 10:
        p.append("at least 10 characters")
    if len(pw) > 128:
        p.append("at most 128 characters")
    if not re.search(r"[a-z]", pw) or not re.search(r"[A-Z]", pw):
        p.append("both upper- and lower-case letters")
    if not re.search(r"\d", pw):
        p.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", pw):
        p.append("a symbol")
    if username and username.lower() in pw.lower():
        p.append("must not contain the username")
    if pw.lower() in _COMMON:
        p.append("must not be a common password")
    return p


# ---- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) -------------------------------------------------

def totp(secret_b32: str, t=None, digits=6, step=30) -> str:
    key = base64.b32decode(secret_b32, casefold=True)
    counter = int((time.time() if t is None else t) // step)
    h = hmac.new(key, struct.pack(">Q", counter), "sha1").digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits
    return str(code).zfill(digits)


def verify_totp(secret_b32: str, code: str, last_counter=0, t=None, window=1):
    """Return the matched counter (for replay protection) or None."""
    code = (code or "").strip()
    now = time.time() if t is None else t
    for delta in range(-window, window + 1):
        ts = now + delta * 30
        counter = int(ts // 30)
        if counter > last_counter and hmac.compare_digest(totp(secret_b32, ts), code):
            return counter
    return None


# ---- helpers --------------------------------------------------------------------------------

def safe_next(target):
    if not target:
        return None
    u = urlparse(target)
    if u.scheme or u.netloc or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return None
    return target


def _dummy_hash():
    ext = current_app.extensions
    if "dummy_hash" not in ext:
        ext["dummy_hash"] = hash_password("dummy-Password-for-timing-1!")
    return ext["dummy_hash"]


def finish_login(user, nxt=None):
    session.clear()  # drop anything the pre-login session carried (fixation)
    user.session_token = secrets.token_hex(16)  # also invalidates all older sessions of this user
    user.failed_attempts, user.locked_until, user.last_login = 0, None, utcnow()
    login_user(user, remember=False)
    session.permanent = True
    session["login_at"] = int(time.time())
    audit.log("LOGIN_OK", "user", user.id, actor=(user.id, user.username, user.role))
    db.session.commit()
    return redirect(safe_next(nxt) or url_for("main.index"))


def _end_session(user):
    user.session_token = secrets.token_hex(16)
    db.session.commit()
    logout_user()
    session.clear()


# ---- request gate ---------------------------------------------------------------------------

@auth.before_app_request
def gate():
    if request.endpoint in (None, "static") or not current_user.is_authenticated:
        return None
    limit = current_app.config["ABSOLUTE_SESSION_HOURS"] * 3600
    if time.time() - session.get("login_at", 0) > limit:
        audit.log("SESSION_EXPIRED", "user", current_user.id)
        _end_session(current_user._get_current_object())
        flash("Your session expired. Please sign in again.", "warn")
        return redirect(url_for("auth.login"))
    if current_user.must_change_password and request.endpoint not in ("auth.account", "auth.change_password", "auth.logout"):
        flash("You must change your password before continuing.", "warn")
        return redirect(url_for("auth.account"))
    expire_overdue()
    return None


# ---- routes ---------------------------------------------------------------------------------

@main.route("/")
@login_required
def index():
    if current_user.role == "student":
        return redirect(url_for("students.detail", sid=current_user.student_id or 0))
    if current_user.role == "recruiter":
        return redirect(url_for("offers.index"))
    return redirect(url_for("admin.dashboard"))


@main.route("/healthz")
def healthz():
    return {"status": "ok"}


@auth.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    nxt = request.values.get("next", "")
    if request.method == "POST":
        cfg = current_app.config
        if not current_app.extensions["login_limiter"].allow(request.remote_addr):
            audit.log("LOGIN_RATE_LIMITED", "ip", request.remote_addr)
            db.session.commit()
            abort(429)
        username = audit.clean(request.form.get("username", "").strip().lower(), 40)
        password = request.form.get("password", "")[:200]
        user = User.query.filter_by(username=username).first()
        now = utcnow()
        locked = bool(user and user.locked_until and user.locked_until > now)
        ok = verify_password(user.password_hash if user else _dummy_hash(), password)  # constant-ish time
        if user and ok and user.active and not locked:
            if user.mfa_enabled:
                session.clear()
                session["mfa_user"], session["mfa_ts"], session["mfa_tries"], session["mfa_next"] = user.id, time.time(), 0, nxt
                return redirect(url_for("auth.login_mfa"))
            return finish_login(user, nxt)
        if user and not locked:
            user.failed_attempts += 1
            if user.failed_attempts >= cfg["LOCKOUT_THRESHOLD"]:
                user.locked_until = now + timedelta(minutes=cfg["LOCKOUT_MINUTES"])
                user.failed_attempts = 0
                audit.log("ACCOUNT_LOCKED", "user", user.id, actor=(user.id, user.username, user.role))
        audit.log("LOGIN_LOCKED_ATTEMPT" if locked else "LOGIN_FAILED", "user", user.id if user else None,
                  new={"username": username}, actor=(user.id if user else None, username or "?", None))
        db.session.commit()
        flash("Invalid credentials, or the account is temporarily locked.", "error")  # same text for every failure
    return render_template("login.html", next=nxt)


@auth.route("/login/mfa", methods=["GET", "POST"])
def login_mfa():
    uid = session.get("mfa_user")
    if not uid or time.time() - session.get("mfa_ts", 0) > 300:
        session.clear()
        return redirect(url_for("auth.login"))
    user = db.session.get(User, uid)
    if request.method == "POST":
        session["mfa_tries"] = session.get("mfa_tries", 0) + 1
        counter = verify_totp(user.mfa_secret, request.form.get("code", ""), user.mfa_last_counter) if user else None
        if counter:
            user.mfa_last_counter = counter
            return finish_login(user, session.get("mfa_next"))
        audit.log("MFA_FAILED", "user", uid, actor=(uid, user.username if user else "?", None))
        db.session.commit()
        if session["mfa_tries"] >= 5:
            session.clear()
            flash("Too many wrong codes. Sign in again.", "error")
            return redirect(url_for("auth.login"))
        flash("Invalid code.", "error")
    return render_template("login_mfa.html")


@auth.post("/logout")
@login_required
def logout():
    user = current_user._get_current_object()
    audit.log("LOGOUT", "user", user.id)
    _end_session(user)  # rotating the token kills any copied cookie
    return redirect(url_for("auth.login"))


@auth.get("/account")
@login_required
def account():
    pending = None
    if not current_user.mfa_enabled:
        pending = session.get("mfa_pending")
        if not pending:
            pending = session["mfa_pending"] = base64.b32encode(secrets.token_bytes(20)).decode()
    uri = f"otpauth://totp/NFSU-Placement:{current_user.username}?secret={pending}&issuer=NFSU-Placement" if pending else None
    return render_template("account.html", mfa_secret=pending, mfa_uri=uri)


@auth.post("/account/password")
@login_required
def change_password():
    user = current_user._get_current_object()
    cur, new = request.form.get("current", ""), request.form.get("new", "")
    if not verify_password(user.password_hash, cur):
        flash("Current password is incorrect.", "error")
    elif cur == new:
        flash("New password must differ from the current one.", "error")
    elif password_problems(new, user.username):
        flash("Password needs: " + ", ".join(password_problems(new, user.username)) + ".", "error")
    else:
        user.password_hash = hash_password(new)
        user.must_change_password = False
        user.session_token = secrets.token_hex(16)  # invalidates every other session
        audit.log("PASSWORD_CHANGED", "user", user.id)
        db.session.commit()
        login_user(user)  # keep *this* session alive with the new token
        flash("Password changed. Other sessions were signed out.", "ok")
    return redirect(url_for("auth.account"))


@auth.post("/account/mfa/enable")
@login_required
def mfa_enable():
    user, secret = current_user._get_current_object(), session.get("mfa_pending")
    counter = verify_totp(secret, request.form.get("code", "")) if secret else None
    if counter:
        user.mfa_secret, user.mfa_enabled, user.mfa_last_counter = secret, True, counter
        session.pop("mfa_pending", None)
        audit.log("MFA_ENABLED", "user", user.id)
        db.session.commit()
        flash("Multi-factor authentication is on.", "ok")
    else:
        flash("That code did not match. Check your authenticator app's clock.", "error")
    return redirect(url_for("auth.account"))


@auth.post("/account/mfa/disable")
@login_required
def mfa_disable():
    user = current_user._get_current_object()
    if not verify_password(user.password_hash, request.form.get("current", "")):
        flash("Password incorrect.", "error")
    else:
        user.mfa_secret, user.mfa_enabled = None, False
        audit.log("MFA_DISABLED", "user", user.id)
        db.session.commit()
        flash("Multi-factor authentication is off.", "ok")
    return redirect(url_for("auth.account"))
