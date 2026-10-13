"""Database schema."""
import sqlite3
from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import DDL, UniqueConstraint, event
from sqlalchemy.engine import Engine

from .crypto import EncFloat, EncText

db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# code -> (display name, programme duration in years)
COURSES = {
    "MTCS": ("M.Tech. Computer Science", 2),
    "MTAI": ("M.Tech. Artificial Intelligence and Data Science", 2),
    "BTMT": ("B.Tech.-M.Tech. Computer Science and Engineering", 5),
    "MSCS": ("M.Sc. Computer Science", 2),
    "MSDF": ("M.Sc. Digital Forensics and Information Security", 2),
}
REGISTRATION = ("registered", "deregistered", "not_registered")
ELIGIBILITY = ("eligible", "ineligible", "pending_verification")
PLACEMENT = ("unplaced", "internship_only", "fte_only", "internship_plus_fte")
OFFER_TYPES = ("I", "F", "I+F")
ACCEPTANCE = ("pending", "accepted", "declined", "expired")
JOINING = ("pending", "joined", "not_joined")
PPO = ("not_applicable", "pending", "offered", "accepted", "declined")
NOC = ("not_applicable", "pending", "obtained")
REVIEW_STATUS = ("cleared", "pending_review", "overridden", "rejected")
ROLES = ("admin", "officer", "coordinator", "recruiter", "student")
CATEGORIES = ("A+", "A", "B", "C")
ACTIVITIES = ("Pre-placement talk", "Presentation", "Test", "Interview", "Other")


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):
    if isinstance(dbapi_conn, sqlite3.Connection):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA secure_delete=ON")
        cur.close()


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    course = db.Column(db.String(8))  # coordinators: the course they own
    company_id = db.Column(db.Integer, db.ForeignKey("companies.id"))  # recruiters
    student_id = db.Column(db.Integer, db.ForeignKey("students.id"))  # student logins
    active = db.Column(db.Boolean, default=True, nullable=False)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime)
    session_token = db.Column(db.String(32), nullable=False)
    mfa_secret = db.Column(EncText)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    mfa_last_counter = db.Column(db.Integer, default=0, nullable=False)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    last_login = db.Column(db.DateTime)

    def get_id(self):
        # Embedding the rotating token means logout / password change
        # invalidates every previously issued session cookie server-side.
        return f"{self.id}:{self.session_token}"

    @property
    def is_active(self):
        return bool(self.active)


class Student(db.Model):
    __tablename__ = "students"
    id = db.Column(db.Integer, primary_key=True)
    placement_id = db.Column(db.String(24), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    mobile = db.Column(EncText)
    email = db.Column(db.String(254))
    course = db.Column(db.String(8), nullable=False, index=True)
    batch = db.Column(db.String(7), nullable=False, index=True)
    cgpa = db.Column(db.Float, default=0.0, nullable=False)
    backlogs = db.Column(db.Integer, default=0, nullable=False)
    registration_status = db.Column(db.String(20), default="registered", nullable=False)
    eligibility_status = db.Column(db.String(24), default="pending_verification", nullable=False)
    placement_status = db.Column(db.String(24), default="unplaced", nullable=False)  # derived, never user-set
    archived = db.Column(db.Boolean, default=False, nullable=False)
    archived_at = db.Column(db.DateTime)
    archive_reason = db.Column(db.String(200))
    anonymised = db.Column(db.Boolean, default=False, nullable=False)
    version = db.Column(db.Integer, default=1, nullable=False)  # optimistic locking
    remarks = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    @property
    def course_name(self):
        return COURSES.get(self.course, (self.course, 0))[0]

    @property
    def batch_end_year(self):
        return 2000 + int(self.batch.split("-")[1])


class Company(db.Model):
    __tablename__ = "companies"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    category = db.Column(db.String(2), nullable=False)  # declared category
    min_cgpa = db.Column(db.Float, default=0.0, nullable=False)
    max_backlogs = db.Column(db.Integer, default=50, nullable=False)
    allowed_courses = db.Column(db.String(60), default="", nullable=False)  # csv of codes; empty = all
    timeline_hours = db.Column(db.Integer)  # company's own acceptance window
    active = db.Column(db.Boolean, default=True, nullable=False)

    @property
    def course_list(self):
        return tuple(c for c in self.allowed_courses.split(",") if c)


class Drive(db.Model):
    __tablename__ = "drives"
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey("companies.id"), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    activity = db.Column(db.String(30), nullable=False)
    drive_date = db.Column(db.Date, nullable=False, index=True)
    company = db.relationship("Company")


class Attendance(db.Model):
    __tablename__ = "attendance"
    __table_args__ = (UniqueConstraint("drive_id", "student_id"),)
    id = db.Column(db.Integer, primary_key=True)
    drive_id = db.Column(db.Integer, db.ForeignKey("drives.id"), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey("students.id"), nullable=False)
    status = db.Column(db.String(10), nullable=False)  # present | absent
    exception_granted = db.Column(db.Boolean, default=False, nullable=False)
    exception_reason = db.Column(db.String(200))
    exception_by = db.Column(db.Integer)
    recorded_by = db.Column(db.Integer)
    drive = db.relationship("Drive")
    student = db.relationship("Student")


class Offer(db.Model):
    """One row per offer event. Rows are never overwritten or deleted, so the
    full placement history is preserved; the student's status is derived."""
    __tablename__ = "offers"
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("students.id"), nullable=False, index=True)
    company_id = db.Column(db.Integer, db.ForeignKey("companies.id"), nullable=False, index=True)
    drive_id = db.Column(db.Integer, db.ForeignKey("drives.id"))
    offer_type = db.Column(db.String(3), nullable=False)
    ctc_lpa = db.Column(EncFloat)  # annual FTE CTC in LPA (F, I+F)
    category = db.Column(db.String(2))
    stipend = db.Column(EncFloat)  # internship stipend (I, I+F)
    stipend_period = db.Column(db.String(10))
    ppo_status = db.Column(db.String(16), default="not_applicable", nullable=False)
    acceptance = db.Column(db.String(10), default="pending", nullable=False)
    joining_status = db.Column(db.String(10), default="pending", nullable=False)
    offer_date = db.Column(db.Date, nullable=False)
    issued_at = db.Column(db.DateTime, nullable=False)
    acceptance_deadline = db.Column(db.DateTime, nullable=False)
    off_campus = db.Column(db.Boolean, default=False, nullable=False)
    noc_status = db.Column(db.String(16), default="not_applicable", nullable=False)
    review_status = db.Column(db.String(16), default="cleared", nullable=False)
    policy_decision = db.Column(db.String(8), nullable=False)
    policy_reasons = db.Column(db.Text)  # JSON list
    override_reason = db.Column(db.String(300))
    remarks = db.Column(db.String(500))
    created_by = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=utcnow)
    student = db.relationship("Student", backref=db.backref("offers", order_by="Offer.id"))
    company = db.relationship("Company")
    drive = db.relationship("Drive")


class AuditLog(db.Model):
    """Append-only, hash-chained audit trail (see audit.py)."""
    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.String(32), nullable=False)
    actor_id = db.Column(db.Integer)
    actor_name = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20))
    action = db.Column(db.String(40), nullable=False, index=True)
    entity = db.Column(db.String(30))
    entity_id = db.Column(db.String(40))
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    ip = db.Column(db.String(45))
    prev_hash = db.Column(db.String(64), nullable=False)
    hash = db.Column(db.String(64), nullable=False, unique=True)


# The database itself refuses to modify or delete audit rows.
for _name, _op in (("audit_no_update", "UPDATE"), ("audit_no_delete", "DELETE")):
    event.listen(
        AuditLog.__table__,
        "after_create",
        DDL(
            f"CREATE TRIGGER IF NOT EXISTS {_name} BEFORE {_op} ON audit_log "
            "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;"
        ).execute_if(dialect="sqlite"),
    )
