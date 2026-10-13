"""Authorization: role permissions, object-level scoping, field masking, rate limiting.

Every check happens on the server. Hiding a button is never the control; the route
decorator and the scoped queries are.
"""
import time
from collections import defaultdict, deque
from functools import wraps

from flask import abort, current_app, request
from flask_login import current_user

from . import audit
from .models import Offer, Student, db

PERMS = {
    "admin": {"*"},
    "officer": {
        "student.view", "student.write", "student.archive", "student.import", "student.export",
        "offer.view", "offer.write", "company.view", "company.write", "drive.write",
        "attendance.write", "dashboard.view", "report.compliance", "policy.check",
    },
    "coordinator": {"student.view", "offer.view", "company.view", "dashboard.view"},
    "recruiter": {"offer.view"},
    "student": {"student.view", "offer.view"},
}


def has_perm(user, perm) -> bool:
    if not user or not user.is_authenticated:
        return False
    p = PERMS.get(user.role, set())
    return "*" in p or perm in p


def require(perm):
    def deco(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            if not current_user.is_authenticated:
                return current_app.login_manager.unauthorized()
            if not has_perm(current_user, perm):
                audit.log("ACCESS_DENIED", "route", request.endpoint, new={"perm": perm, "path": request.path[:120]})
                db.session.commit()
                abort(403)
            return fn(*args, **kwargs)
        return inner
    return deco


# ---- object-level scoping (defence against IDOR) -------------------------------------------

def scoped_students(user):
    q = Student.query
    r = user.role
    if r in ("admin", "officer"):
        return q
    q = q.filter(Student.archived.is_(False))
    if r == "coordinator" and user.course:
        return q.filter(Student.course == user.course)
    if r == "student" and user.student_id:
        return q.filter(Student.id == user.student_id)
    return q.filter(db.false())


def scoped_offers(user):
    q = Offer.query
    r = user.role
    if r in ("admin", "officer"):
        return q
    if r == "coordinator" and user.course:
        return q.filter(Offer.student_id.in_(db.session.query(Student.id).filter(Student.course == user.course)))
    if r == "recruiter" and user.company_id:
        return q.filter(Offer.company_id == user.company_id)
    if r == "student" and user.student_id:
        return q.filter(Offer.student_id == user.student_id)
    return q.filter(db.false())


def _not_found(kind, oid, exists):
    if exists:  # someone reached for a record outside their scope - record it
        audit.log("ACCESS_DENIED", kind, oid, new={"reason": "out of scope", "path": request.path[:120]})
        db.session.commit()
    abort(404)  # same answer whether or not the record exists: no enumeration


def student_or_404(sid):
    s = scoped_students(current_user).filter(Student.id == sid).first()
    if s is None:
        _not_found("student", sid, db.session.get(Student, sid) is not None)
    return s


def offer_or_404(oid):
    o = scoped_offers(current_user).filter(Offer.id == oid).first()
    if o is None:
        _not_found("offer", oid, db.session.get(Offer, oid) is not None)
    return o


# ---- field-level visibility -----------------------------------------------------------------

def can_see(user, field, student=None, company_id=None) -> bool:
    if not user or not user.is_authenticated:
        return False
    r = user.role
    own = r == "student" and student is not None and user.student_id == student.id
    if field == "mobile":
        return r in ("admin", "officer") or own
    if field == "email":
        return r in ("admin", "officer", "coordinator") or own
    if field == "comp":  # CTC, stipend
        if r in ("admin", "officer", "coordinator") or own:
            return True
        return r == "recruiter" and company_id is not None and company_id == user.company_id
    return False


# ---- rate limiting --------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, limit, per):
        self.limit, self.per = limit, per
        self.hits = defaultdict(deque)

    def allow(self, key) -> bool:
        now = time.monotonic()
        dq = self.hits[key]
        while dq and dq[0] < now - self.per:
            dq.popleft()
        if len(dq) >= self.limit:
            return False
        dq.append(now)
        return True
