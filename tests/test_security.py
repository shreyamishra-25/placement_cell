"""Attack-scenario tests: authentication, access control, injection, CSRF, sessions, audit integrity."""
import re
import sqlite3

from app import audit
from app.models import AuditLog, Offer, Student, User, db
from conftest import PASSWORD, build_app, login, mk_offer


def sid(app, pid):
    with app.app_context():
        return Student.query.filter_by(placement_id=pid).first().id


# ---------------------------------------------------------------- authentication

def test_wrong_password_and_unknown_user_look_identical(app):
    c = app.test_client()
    a = c.post("/login", data={"username": "admin", "password": "nope"}, follow_redirects=True)
    b = c.post("/login", data={"username": "ghost", "password": "nope"}, follow_redirects=True)
    msg = b"Invalid credentials, or the account is temporarily locked."
    assert msg in a.data and msg in b.data and a.status_code == b.status_code == 200


def test_lockout_after_five_failures_even_for_the_right_password(app):
    c = app.test_client()
    for _ in range(5):
        c.post("/login", data={"username": "officer", "password": "bad"})
    r = c.post("/login", data={"username": "officer", "password": PASSWORD})
    assert r.status_code == 200 and b"Invalid credentials" in r.data   # not redirected: still locked
    with app.app_context():
        assert AuditLog.query.filter_by(action="ACCOUNT_LOCKED").count() == 1


def test_login_rate_limit(tmp_path):
    app = build_app(tmp_path, LOGIN_RATE=(3, 60))
    c = app.test_client()
    codes = [c.post("/login", data={"username": "x", "password": "y"}).status_code for _ in range(5)]
    assert codes[:3] == [200] * 3 and codes[3:] == [429, 429]


def test_password_policy_and_bcrypt_storage(app):
    from app.auth import password_problems
    assert password_problems("short1A!")
    assert password_problems("alllowercase123!")
    assert password_problems("NoDigitsHere!!")
    assert password_problems("admin-Admin1!!", "admin")
    assert not password_problems("Str0ng!Passphrase")
    with app.app_context():
        assert User.query.filter_by(username="admin").first().password_hash.startswith("$2b$")


def test_session_cookie_replay_after_logout_is_rejected(app):
    c = login(app, "officer")
    cookie = c.get_cookie("session").value
    assert c.get("/students").status_code == 200
    c.post("/logout")
    thief = app.test_client()
    thief.set_cookie("session", cookie)
    r = thief.get("/students")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_password_change_signs_out_other_sessions(app):
    a, b = login(app, "officer"), login(app, "officer")   # second login rotates the token: first is dead
    assert a.get("/students").status_code == 302
    r = b.post("/account/password", data={"current": PASSWORD, "new": "An0ther!Passphrase"})
    assert r.status_code == 302 and b.get("/students").status_code == 200


def test_idle_and_absolute_session_limits(app):
    c = login(app, "officer")
    with c.session_transaction() as s:
        s["login_at"] = 0                                  # pretend the login was ages ago
    r = c.get("/students")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() == 900
    assert app.config["SESSION_COOKIE_HTTPONLY"] and app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


def test_forced_password_change(app):
    with app.app_context():
        User.query.filter_by(username="officer").first().must_change_password = True
        db.session.commit()
    c = login(app, "officer")
    r = c.get("/students")
    assert r.status_code == 302 and "/account" in r.headers["Location"]


def test_open_redirect_is_refused(app):
    c = app.test_client()
    r = c.post("/login", data={"username": "officer", "password": PASSWORD, "next": "https://evil.example/"})
    assert r.headers["Location"].endswith("/")
    assert "evil" not in r.headers["Location"]


def test_totp_rfc6238_vector_and_mfa_login_with_replay_protection(app):
    from app.auth import totp, verify_totp
    assert totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", t=59, digits=8) == "94287082"
    secret = "JBSWY3DPEHPK3PXP"
    with app.app_context():
        u = User.query.filter_by(username="officer").first()
        u.mfa_secret, u.mfa_enabled = secret, True
        db.session.commit()
    c = app.test_client()
    r = c.post("/login", data={"username": "officer", "password": PASSWORD})
    assert "/login/mfa" in r.headers["Location"] and c.get("/students").status_code == 302   # not logged in yet
    assert c.post("/login/mfa", data={"code": "000000"}).status_code == 200                    # wrong code
    code = totp(secret)
    assert c.post("/login/mfa", data={"code": code}).status_code == 302
    assert c.get("/students").status_code == 200
    c2 = app.test_client()
    c2.post("/login", data={"username": "officer", "password": PASSWORD})
    assert c2.post("/login/mfa", data={"code": code}).status_code == 200                       # replayed code refused


# ---------------------------------------------------------------- authorization

def test_idor_student_cannot_read_another_students_record(app):
    c = login(app, "stu_a")
    assert c.get(f"/students/{sid(app, 'MTCS-25-001')}").status_code == 200
    for pid in ("MTCS-25-002", "MTCS-25-003", "MSDF-25-001"):
        assert c.get(f"/students/{sid(app, pid)}").status_code == 404
    assert c.get("/students/99999").status_code == 404           # same answer as a real-but-forbidden id
    with app.app_context():
        assert AuditLog.query.filter_by(action="ACCESS_DENIED").count() >= 3


def test_idor_on_offers(app):
    oid = mk_offer(app, "MTCS-25-002", "Praxis", "F", ctc=7)
    assert login(app, "stu_b").get(f"/offers/{oid}").status_code == 200
    assert login(app, "stu_a").get(f"/offers/{oid}").status_code == 404
    assert login(app, "coord_df").get(f"/offers/{oid}").status_code == 404   # another course's coordinator
    assert login(app, "recruiter").get(f"/offers/{oid}").status_code == 404  # another company


def test_coordinator_is_limited_to_their_course(app):
    c = login(app, "coord_cs")
    page = c.get("/students").data.decode()
    assert "MTCS-25-001" in page and "MSDF-25-001" not in page
    assert c.get(f"/students/{sid(app, 'MSDF-25-001')}").status_code == 404


def test_student_cannot_change_own_status_package_or_create_offers(app):
    me = sid(app, "MTCS-25-001")
    c = login(app, "stu_a")
    assert c.post(f"/students/{me}/edit", data={"placement_status": "fte_only", "version": 1}).status_code == 403
    assert c.post(f"/students/{me}/archive", data={"reason": "because"}).status_code == 403
    r = c.post("/offers/new", data={"placement_id": "MTCS-25-001", "company_id": 1, "offer_type": "F", "ctc_lpa": "99"})
    assert r.status_code == 403
    assert c.post("/offers/1/update", data={"acceptance": "accepted"}).status_code == 403
    assert c.get("/users").status_code == 403 and c.get("/audit").status_code == 403
    assert c.get("/students/export").status_code == 403
    with app.app_context():
        assert Student.query.get(me).placement_status == "unplaced" and Offer.query.count() == 0


def test_mass_assignment_is_ignored(app):
    me = sid(app, "MTCS-25-001")
    c = login(app, "officer")
    form = {"name": "Aarav Patel", "mobile": "9876543210", "email": "a@x.example", "course": "MTCS", "batch": "2025-27",
            "cgpa": "8", "backlogs": "0", "registration_status": "registered", "eligibility_status": "eligible",
            "version": "1", "placement_status": "fte_only", "archived": "1", "id": "999", "placement_id": "HACKED-1",
            "version_override": "50", "ctc_lpa": "99"}
    assert c.post(f"/students/{me}/edit", data=form).status_code == 302
    with app.app_context():
        s = Student.query.get(me)
        assert (s.placement_status, s.archived, s.id, s.placement_id, s.version) == ("unplaced", False, me, "MTCS-25-001", 2)


def test_policy_cannot_be_bypassed_by_posting_directly(app):
    mk_offer(app, "MTCS-25-001", "Praxis", "F", ctc=8)              # category B, 12 LPA needed to switch
    c = login(app, "officer")
    r = c.post("/offers/new", data={"placement_id": "MTCS-25-001", "company_id": 3, "offer_type": "F", "ctc_lpa": "9"})
    assert r.status_code == 409 and b"BLOCK" in r.data and b"1.5x" in r.data
    with app.app_context():
        assert Offer.query.count() == 1
        assert AuditLog.query.filter_by(action="OFFER_BLOCKED").count() == 1
    # an officer cannot override, whatever they post
    r = c.post("/offers/new", data={"placement_id": "MTCS-25-001", "company_id": 3, "offer_type": "F", "ctc_lpa": "9",
                                    "override_reason": "pretty please, boss said so"})
    assert r.status_code == 409
    with app.app_context():
        assert Offer.query.count() == 1


def test_admin_override_needs_a_reason_and_is_audited(app):
    mk_offer(app, "MTCS-25-001", "Praxis", "F", ctc=8)
    c = login(app, "admin")
    base = {"placement_id": "MTCS-25-001", "company_id": 3, "offer_type": "F", "ctc_lpa": "9"}
    assert c.post("/offers/new", data={**base, "override_reason": "short"}).status_code == 409
    assert c.post("/offers/new", data={**base, "override_reason": "Dean approved exception, ref 12/2026"}).status_code == 302
    with app.app_context():
        o = Offer.query.order_by(Offer.id.desc()).first()
        assert o.review_status == "overridden" and o.policy_decision == "BLOCK"
        assert audit.verify_chain()[0]


def test_recruiter_sees_only_own_company_and_no_contact_details(app):
    mk_offer(app, "MTCS-25-001", "Zenith", "F", ctc=18)
    mk_offer(app, "MTCS-25-002", "Orbit", "F", ctc=12)
    c = login(app, "recruiter")
    page = c.get("/offers").data.decode()
    assert "Zenith" in page and "Orbit" not in page and "12.00 LPA" not in page
    assert "9876543210" not in page
    assert c.get("/students").status_code == 403 and c.get("/dashboard").status_code == 403


def test_contact_and_salary_masking_by_role(app):
    mk_offer(app, "MTCS-25-001", "Praxis", "F", ctc=7.5)
    me = sid(app, "MTCS-25-001")
    assert b"9876543210" in login(app, "officer").get(f"/students/{me}").data
    coord = login(app, "coord_cs").get(f"/students/{me}").data
    assert b"9876543210" not in coord and b"restricted" in coord and b"7.50 LPA" in coord
    own = login(app, "stu_a").get(f"/students/{me}").data
    assert b"9876543210" in own


# ---------------------------------------------------------------- injection

def test_sql_injection_in_search_and_filters(app):
    c = login(app, "officer")
    row = b'<tr><td class="mono">'
    assert c.get("/students").data.count(row) == 4
    for payload in ("' OR '1'='1", "'; DROP TABLE students;--", '" OR 1=1 --', "%", "_", "a%' UNION SELECT 1,2,3--"):
        for param in ("term", "course", "batch", "eligibility", "placement", "page"):
            r = c.get("/students", query_string={param: payload})
            assert r.status_code == 200, (param, payload)
        r = c.get("/students", query_string={"term": payload})
        assert row not in r.data, payload          # nothing matches a literal payload; wildcards are escaped
    assert c.get("/students").data.count(row) == 4  # table and data are intact
    with app.app_context():
        assert Student.query.count() == 4


def test_sql_injection_in_login(app):
    c = app.test_client()
    r = c.post("/login", data={"username": "admin' --", "password": "x"})
    assert r.status_code == 200 and b"Invalid credentials" in r.data
    r = c.post("/login", data={"username": "' OR 1=1 --", "password": "' OR '1'='1"})
    assert r.status_code == 200


def test_stored_xss_is_escaped_and_markup_names_are_rejected(app):
    c = login(app, "officer")
    me = sid(app, "MTCS-25-003")
    xss = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    form = {"name": "Rohan Mehta", "mobile": "9876543210", "email": "r@x.example", "course": "MTCS", "batch": "2025-27",
            "cgpa": "8", "backlogs": "0", "registration_status": "registered", "eligibility_status": "eligible",
            "version": "1", "remarks": xss}
    assert c.post(f"/students/{me}/edit", data=form).status_code == 302
    page = c.get(f"/students/{me}").data.decode()
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<img src=x" not in page
    bad = c.post("/students/new", data={**form, "placement_id": "XSS-0001", "name": "<script>alert(1)</script>", "version": ""})
    assert bad.status_code == 200 and b"Name must be" in bad.data
    with app.app_context():
        assert Student.query.filter_by(placement_id="XSS-0001").count() == 0


def test_csp_and_security_headers(app):
    r = login(app, "officer").get("/students")
    h = r.headers
    assert "script-src 'self'" in h["Content-Security-Policy"] and "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert "unsafe-inline" not in h["Content-Security-Policy"]
    assert h["X-Frame-Options"] == "DENY" and h["X-Content-Type-Options"] == "nosniff"
    assert h["Cache-Control"] == "no-store" and h["Referrer-Policy"] == "no-referrer"
    assert b"<script" not in r.data and b' style="' not in r.data          # nothing inline for the CSP to block


def test_csrf_blocks_forged_posts_but_allows_real_forms(csrf_app):
    c = csrf_app.test_client()
    page = c.get("/login").data.decode()
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    assert c.post("/login", data={"username": "officer", "password": PASSWORD}).status_code == 400   # forged
    assert c.post("/login", data={"username": "officer", "password": PASSWORD, "csrf_token": "bogus"}).status_code == 400
    assert c.post("/login", data={"username": "officer", "password": PASSWORD, "csrf_token": token}).status_code == 302
    assert c.post("/logout").status_code == 400                                                          # logout needs a token too


def test_csv_formula_injection_is_neutralised():
    from app.validators import csv_safe
    for evil in ("=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(1)", "\t=1"):
        assert csv_safe(evil).startswith("'")
    assert csv_safe("Plain Name") == "Plain Name"


def test_csv_import_is_all_or_nothing_and_validates_every_row(app):
    import io
    c = login(app, "officer")
    head = "placement_id,name,mobile,email,course,batch,cgpa,backlogs\n"
    good = "MTAI-25-010,Meera Nair,9811122233,m@x.example,MTAI,2025-27,8.1,0\n"
    bad = ["MTAI-25-011,=cmd|calc,9811122233,m@x.example,MTAI,2025-27,8.1,0\n",             # formula / invalid name
           "MTAI-25-012,Ok Name,12345,m@x.example,MTAI,2025-27,8.1,0\n",                    # bad mobile
           "MTCS-25-001,Dup Person,9811122233,m@x.example,MTCS,2025-27,8.1,0\n",            # duplicate of existing
           "BTMT-25-013,Wrong Batch,9811122233,m@x.example,BTMT,2025-27,8.1,0\n"]           # 5-year course, 2-year batch
    r = c.post("/students/import", data={"file": (io.BytesIO((head + good + "".join(bad)).encode()), "s.csv")},
               content_type="multipart/form-data")
    assert b"Nothing imported" in r.data and r.data.count(b"<tr><td>") >= 4
    with app.app_context():
        assert Student.query.count() == 4                     # the good row was NOT imported either
    r = c.post("/students/import", data={"file": (io.BytesIO((head + good).encode()), "s.csv")},
               content_type="multipart/form-data")
    assert b"Imported 1 student" in r.data
    r = c.post("/students/import", data={"file": (io.BytesIO(b"MZ\x90\x00 binary"), "evil.exe")},
               content_type="multipart/form-data")
    assert b"Upload a .csv" in r.data
    r = c.post("/students/import", data={"file": (io.BytesIO(b"x" * (1024 * 1024 + 10)), "big.csv")},
               content_type="multipart/form-data")
    assert r.status_code == 413


def test_duplicate_placement_id_is_rejected(app):
    c = login(app, "officer")
    form = {"placement_id": "mtcs-25-001", "name": "Copy Cat", "mobile": "9876543210", "email": "c@x.example",
            "course": "MTCS", "batch": "2025-27", "cgpa": "7", "backlogs": "0", "registration_status": "registered",
            "eligibility_status": "eligible"}
    r = c.post("/students/new", data=form)
    assert r.status_code == 200 and b"already exists" in r.data
    with app.app_context():
        assert Student.query.count() == 4


# ---------------------------------------------------------------- confidentiality at rest, audit integrity

def test_sensitive_fields_are_encrypted_in_the_database_file(app):
    mk_offer(app, "MTCS-25-001", "Praxis", "F", ctc=7.5)
    path = app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")
    con = sqlite3.connect(path)
    mobiles = [r[0] for r in con.execute("SELECT mobile FROM students")]
    ctcs = [r[0] for r in con.execute("SELECT ctc_lpa FROM offers")]
    con.close()
    assert mobiles and all("9876543210" not in m and m.startswith("gAAAA") for m in mobiles)
    assert ctcs and all("7.5" not in c and c.startswith("gAAAA") for c in ctcs)
    raw = open(path, "rb").read()
    assert b"9876543210" not in raw


def test_audit_log_records_changes_with_actor_and_before_after(app):
    me = sid(app, "MTCS-25-001")
    c = login(app, "officer")
    form = {"name": "Aarav Patel", "mobile": "9876543210", "email": "a@x.example", "course": "MTCS", "batch": "2025-27",
            "cgpa": "9.1", "backlogs": "0", "registration_status": "registered", "eligibility_status": "eligible", "version": "1"}
    c.post(f"/students/{me}/edit", data=form)
    with app.app_context():
        row = AuditLog.query.filter_by(action="STUDENT_UPDATE").first()
        assert row.actor_name == "officer" and row.role == "officer" and row.ip and row.ts.endswith("Z")
        assert '"cgpa":8.0' in row.old_value and '"cgpa":9.1' in row.new_value
        assert "9876543210" not in (row.old_value or "") + (row.new_value or "")        # no raw contact data in the log
        assert AuditLog.query.filter_by(action="LOGIN_OK").count() == 1


def test_audit_chain_detects_tampering_and_db_refuses_edits(app):
    for _ in range(3):
        login(app, "officer")
    with app.app_context():
        assert audit.verify_chain()[0]
        n = AuditLog.query.count()
    path = app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")
    con = sqlite3.connect(path)
    for stmt in ("UPDATE audit_log SET actor_name='nobody' WHERE id=2", "DELETE FROM audit_log WHERE id=2"):
        try:
            con.execute(stmt)
            raise AssertionError("append-only trigger did not fire")
        except sqlite3.DatabaseError as e:
            assert "append-only" in str(e)
    # an attacker with file access drops the trigger and edits a row: the hash chain still exposes it
    con.execute("DROP TRIGGER audit_no_update")
    con.execute("UPDATE audit_log SET actor_name='nobody' WHERE id=2")
    con.commit()
    con.close()
    with app.app_context():
        ok, _, bad, _ = audit.verify_chain()
        assert not ok and bad == 2
    con = sqlite3.connect(path)
    con.execute("DROP TRIGGER audit_no_delete")
    con.execute("DELETE FROM audit_log WHERE id=1")                  # deleting an early row also breaks the chain
    con.commit()
    con.close()
    with app.app_context():
        assert not audit.verify_chain()[0]


def test_denied_actions_and_blocked_offers_are_audited(app):
    login(app, "stu_a").get("/audit")
    with app.app_context():
        row = AuditLog.query.filter_by(action="ACCESS_DENIED").first()
        assert row.actor_name == "stu_a" and "audit.view" in row.new_value


def test_log_injection_is_neutralised(app):
    app.test_client().post("/login", data={"username": "evil\r\n2026-01-01 LOGIN_OK admin", "password": "x"})
    with app.app_context():
        row = AuditLog.query.filter_by(action="LOGIN_FAILED").first()
        assert "\n" not in row.actor_name and "\r" not in row.actor_name
