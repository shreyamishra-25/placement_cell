import os
import secrets
import sys

import pytest
from cryptography.fernet import Fernet

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app  # noqa: E402
from app.auth import hash_password  # noqa: E402
from app.models import Company, Student, User, db  # noqa: E402
from app.services import create_offer, recompute_placement  # noqa: E402

KEY = Fernet.generate_key().decode()
PASSWORD = "Passw0rd!Test"


def build_app(tmp_path, name="t.db", **over):
    cfg = {"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/{name}", "SECRET_KEY": "k" * 40, "FIELD_KEYS": KEY,
           "BCRYPT_ROUNDS": 4, "WTF_CSRF_ENABLED": False, "LOGIN_RATE": (1000, 60), "TESTING": False}
    cfg.update(over)
    app = create_app(cfg)
    with app.app_context():
        _world()
    return app


def _user(name, role, **kw):
    u = User(username=name, role=role, password_hash=hash_password(PASSWORD), session_token=secrets.token_hex(16), **kw)
    db.session.add(u)
    return u


def _world():
    for n, cat in (("Zenith", "A+"), ("Orbit", "A"), ("Praxis", "B"), ("Nimbus", "C")):
        db.session.add(Company(name=n, category=cat))
    for pid, name, course, batch in (("MTCS-25-001", "Aarav Patel", "MTCS", "2025-27"),
                                     ("MTCS-25-002", "Diya Shah", "MTCS", "2025-27"),
                                     ("MTCS-25-003", "Rohan Mehta", "MTCS", "2025-27"),
                                     ("MSDF-25-001", "Ishita Joshi", "MSDF", "2025-27")):
        db.session.add(Student(placement_id=pid, name=name, mobile="9876543210", email=f"{pid.lower()}@x.example",
                               course=course, batch=batch, cgpa=8.0, backlogs=0, eligibility_status="eligible"))
    db.session.flush()
    sid = lambda p: Student.query.filter_by(placement_id=p).first().id  # noqa: E731
    _user("admin", "admin")
    _user("officer", "officer")
    _user("coord_cs", "coordinator", course="MTCS")
    _user("coord_df", "coordinator", course="MSDF")
    _user("recruiter", "recruiter", company_id=Company.query.filter_by(name="Zenith").first().id)
    _user("stu_a", "student", student_id=sid("MTCS-25-001"))
    _user("stu_b", "student", student_id=sid("MTCS-25-002"))
    db.session.commit()


@pytest.fixture
def app(tmp_path):
    return build_app(tmp_path)


@pytest.fixture
def csrf_app(tmp_path):
    return build_app(tmp_path, name="csrf.db", WTF_CSRF_ENABLED=True)


def login(app, username, password=PASSWORD):
    c = app.test_client()
    r = c.post("/login", data={"username": username, "password": password})
    assert r.status_code == 302, f"login failed for {username}: {r.status_code}"
    return c


def mk_offer(app, pid, company, otype, ctc=None, stipend=None, accept=True, **extra):
    """Create an offer through the real service (policy engine included)."""
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        form = {"placement_id": pid, "company_id": Company.query.filter_by(name=company).first().id,
                "offer_type": otype, "ctc_lpa": "" if ctc is None else str(ctc),
                "stipend": "" if stipend is None else str(stipend)}
        form.update(extra)
        issued = form.pop("issued_at", None)
        res = create_offer(admin, form, issued_at=issued)
        if res.offer and accept and res.offer.review_status in ("cleared", "overridden"):
            res.offer.acceptance = "accepted"
            recompute_placement(res.offer.student)
            db.session.commit()
        return res.offer.id if res.offer else None
