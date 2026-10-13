"""Dashboard, reports, companies, drives & attendance, users, audit viewer, retention."""
import secrets
from datetime import date, timedelta

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user

from . import audit, policy
from .auth import hash_password, password_problems
from .models import (ACTIVITIES, CATEGORIES, COURSES, ROLES, Attendance, AuditLog, Company, Drive, Offer, Student,
                     User, db, utcnow)
from .security import require, scoped_students
from .services import (absence_flags, company_report, find_conflicts, grant_exception, held_for, mark_attendance,
                       stats)
from .validators import COMPANY_RE, USERNAME_RE, number, text, to_int

bp = Blueprint("admin", __name__)


# ---- dashboard & reports --------------------------------------------------------------------

@bp.route("/dashboard")
@require("dashboard.view")
def dashboard():
    return render_template("dashboard.html", st=stats(current_user))


@bp.route("/reports/companies")
@require("dashboard.view")
def companies_report():
    return render_template("company_report.html", rows=company_report(current_user))


@bp.route("/reports/compliance")
@require("report.compliance")
def compliance():
    switch = current_app.config["SWITCH_BY_CATEGORY"]
    pending = Offer.query.filter_by(acceptance="pending").order_by(Offer.acceptance_deadline).all()
    joining = [o for o in Offer.query.filter_by(acceptance="accepted", joining_status="pending").all()
               if o.review_status in ("cleared", "overridden")]
    review = Offer.query.filter_by(review_status="pending_review").all()
    eligible = []
    for s in Student.query.filter_by(archived=False, registration_status="registered", eligibility_status="eligible") \
            .order_by(Student.placement_id).all():
        eligible.append((s, policy.next_options(held_for(s.id), switch)))
    return render_template("compliance.html", pending=pending, joining=joining, review=review,
                           conflicts=find_conflicts(), flags=absence_flags(), eligible=eligible)


# ---- companies ------------------------------------------------------------------------------

def _company_from(form):
    e, d = {}, {}
    name = " ".join(text(form.get("name"), 100).split())
    if COMPANY_RE.match(name):
        d["name"] = name
    else:
        e["name"] = "2-100 characters: letters, digits, space and . , & ( ) ' -"
    cat = text(form.get("category"), 2)
    if cat in CATEGORIES:
        d["category"] = cat
    else:
        e["category"] = "Choose A+, A, B or C."
    cg = number(form.get("min_cgpa") or "0", 0, 10)
    if cg is None:
        e["min_cgpa"] = "0-10."
    else:
        d["min_cgpa"] = cg
    mb = to_int(form.get("max_backlogs") or "50", -1)
    if 0 <= mb <= 50:
        d["max_backlogs"] = mb
    else:
        e["max_backlogs"] = "0-50."
    courses = [c for c in form.getlist("allowed_courses") if c in COURSES]
    d["allowed_courses"] = ",".join(courses)
    th = form.get("timeline_hours", "").strip()
    if th:
        v = to_int(th, 0)
        if 1 <= v <= 168:
            d["timeline_hours"] = v
        else:
            e["timeline_hours"] = "1-168 hours."
    else:
        d["timeline_hours"] = None
    d["active"] = form.get("active", "1") in ("1", "on")
    return d, e


@bp.route("/companies")
@require("company.view")
def companies():
    return render_template("companies.html", rows=Company.query.order_by(Company.name).all(), courses=COURSES)


@bp.route("/companies/new", methods=["GET", "POST"])
@bp.route("/companies/<int:cid>/edit", methods=["GET", "POST"])
@require("company.write")
def company_form(cid=None):
    c = db.session.get(Company, cid) if cid else None
    if cid and not c:
        abort(404)
    errors = {}
    if request.method == "POST":
        data, errors = _company_from(request.form)
        dup = Company.query.filter(Company.name == data.get("name")).first() if "name" in data else None
        if dup and (not c or dup.id != c.id):
            errors["name"] = "A company with this name already exists."
        if not errors:
            old = None
            if c is None:
                c = Company(**data)
                db.session.add(c)
                db.session.flush()
                audit.log("COMPANY_CREATE", "company", c.id, new=data)
            else:
                old = {k: getattr(c, k) for k in data}
                for k, v in data.items():
                    setattr(c, k, v)
                audit.log("COMPANY_UPDATE", "company", c.id, old=old, new=data)
            db.session.commit()
            flash("Company saved.", "ok")
            return redirect(url_for("admin.companies"))
    posting = request.method == "POST"
    selected = request.form.getlist("allowed_courses") if posting else (list(c.course_list) if c else [])
    return render_template("company_form.html", c=c, errors=errors, category_opts=[(x, x) for x in CATEGORIES],
                           courses=COURSES, form=request.form if posting else {}, selected=selected)


# ---- drives & attendance --------------------------------------------------------------------

@bp.route("/drives")
@require("company.view")
def drives():
    return render_template("drives.html", rows=Drive.query.order_by(Drive.drive_date.desc()).all(),
                           companies=Company.query.filter_by(active=True).order_by(Company.name).all(),
                           activities=ACTIVITIES, today=date.today().isoformat())


@bp.post("/drives/new")
@require("drive.write")
def drive_new():
    c = db.session.get(Company, to_int(request.form.get("company_id"), 0))
    title, act = text(request.form.get("title"), 100), text(request.form.get("activity"), 30)
    try:
        when = date.fromisoformat(text(request.form.get("drive_date"), 10))
    except ValueError:
        when = None
    if not (c and 2 <= len(title) <= 100 and act in ACTIVITIES and when):
        flash("Choose a company, activity, title (2-100 chars) and a valid date.", "error")
    else:
        d = Drive(company=c, title=title, activity=act, drive_date=when)
        db.session.add(d)
        db.session.flush()
        audit.log("DRIVE_CREATE", "drive", d.id, new={"company": c.name, "title": title, "date": when.isoformat()})
        db.session.commit()
        flash("Drive created.", "ok")
    return redirect(url_for("admin.drives"))


@bp.route("/drives/<int:did>")
@require("company.view")
def drive_detail(did):
    d = db.session.get(Drive, did) or abort(404)
    rows = Attendance.query.filter_by(drive_id=d.id).all()
    return render_template("drive_detail.html", d=d, rows=rows)


@bp.post("/drives/<int:did>/attendance")
@require("attendance.write")
def attendance_mark(did):
    d = db.session.get(Drive, did) or abort(404)
    s = Student.query.filter_by(placement_id=text(request.form.get("placement_id"), 40).upper(), archived=False).first()
    if not s:
        flash("Unknown student.", "error")
    else:
        _, err = mark_attendance(current_user, d, s, text(request.form.get("status"), 10))
        flash(err or "Attendance recorded.", "error" if err else "ok")
    return redirect(url_for("admin.drive_detail", did=d.id))


@bp.post("/attendance/<int:aid>/exception")
@require("attendance.exception")
def attendance_exception(aid):
    a = db.session.get(Attendance, aid) or abort(404)
    err = grant_exception(current_user, a, request.form.get("reason"))
    flash(err or "Emergency exception recorded.", "error" if err else "ok")
    return redirect(url_for("admin.drive_detail", did=a.drive_id))


# ---- users (admin) --------------------------------------------------------------------------

@bp.route("/users")
@require("user.manage")
def users():
    return render_template("users.html", rows=User.query.order_by(User.username).all(), roles=ROLES, courses=COURSES,
                           companies=Company.query.order_by(Company.name).all(), now=utcnow())


@bp.post("/users/new")
@require("user.manage")
def user_new():
    f = request.form
    username, role = text(f.get("username"), 40).lower(), text(f.get("role"), 20)
    password = f.get("password", "")
    err = None
    if not USERNAME_RE.match(username):
        err = "Username: 3-40 chars of a-z 0-9 . _ -"
    elif User.query.filter_by(username=username).first():
        err = "Username already taken."
    elif role not in ROLES:
        err = "Unknown role."
    elif password_problems(password, username):
        err = "Temporary password needs: " + ", ".join(password_problems(password, username)) + "."
    u = User(username=username, role=role, password_hash="x", session_token=secrets.token_hex(16),
             must_change_password=True)
    if not err:
        if role == "coordinator":
            u.course = text(f.get("course"), 8)
            err = None if u.course in COURSES else "Coordinators need a course."
        elif role == "recruiter":
            c = db.session.get(Company, to_int(f.get("company_id"), 0))
            u.company_id = c.id if c else None
            err = None if c else "Recruiters need a company."
        elif role == "student":
            s = Student.query.filter_by(placement_id=text(f.get("placement_id"), 40).upper()).first()
            u.student_id = s.id if s else None
            err = None if s else "Student logins need a valid Placement ID."
    if err:
        flash(err, "error")
    else:
        u.password_hash = hash_password(password)
        db.session.add(u)
        db.session.flush()
        audit.log("USER_CREATE", "user", u.id, new={"username": username, "role": role, "course": u.course,
                                                    "company_id": u.company_id, "student_id": u.student_id})
        db.session.commit()
        flash("User created. They must change the temporary password at first login.", "ok")
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:uid>/action")
@require("user.manage")
def user_action(uid):
    u = db.session.get(User, uid) or abort(404)
    act = request.form.get("action")
    if u.id == current_user.id and act in ("disable", "role"):
        flash("You cannot disable your own account.", "error")
    elif act in ("disable", "enable"):
        u.active = act == "enable"
        u.session_token = secrets.token_hex(16)
        audit.log("USER_" + act.upper(), "user", u.id)
        db.session.commit()
        flash(f"User {act}d.", "ok")
    elif act == "unlock":
        u.locked_until, u.failed_attempts = None, 0
        audit.log("USER_UNLOCK", "user", u.id)
        db.session.commit()
        flash("Account unlocked.", "ok")
    elif act == "reset":
        pw = request.form.get("password", "")
        if password_problems(pw, u.username):
            flash("Temporary password needs: " + ", ".join(password_problems(pw, u.username)) + ".", "error")
        else:
            u.password_hash, u.must_change_password = hash_password(pw), True
            u.session_token, u.locked_until, u.failed_attempts = secrets.token_hex(16), None, 0
            audit.log("USER_PASSWORD_RESET", "user", u.id)
            db.session.commit()
            flash("Password reset; the user must change it at next login.", "ok")
    return redirect(url_for("admin.users"))


# ---- audit viewer ---------------------------------------------------------------------------

@bp.route("/audit")
@require("audit.view")
def audit_view():
    q = AuditLog.query
    action = text(request.args.get("action"), 40)
    actor = text(request.args.get("actor"), 40)
    if action:
        q = q.filter(AuditLog.action == action.upper())
    if actor:
        q = q.filter(AuditLog.actor_name == actor)
    page = max(1, to_int(request.args.get("page"), 1))
    pg = q.order_by(AuditLog.id.desc()).paginate(page=page, per_page=50, error_out=False)
    ok, n, bad, head = audit.verify_chain()
    actions = [a for (a,) in db.session.query(AuditLog.action).distinct().order_by(AuditLog.action)]
    return render_template("audit.html", pg=pg, chain=(ok, n, bad, head), actions=actions, action=action, actor=actor)


# ---- retention ------------------------------------------------------------------------------

def _retention_candidates():
    cutoff = date.today().year - current_app.config["RETENTION_YEARS"]
    return [s for s in Student.query.filter_by(archived=True, anonymised=False).all() if s.batch_end_year <= cutoff]


@bp.route("/admin/retention")
@require("retention.manage")
def retention():
    return render_template("retention.html", rows=_retention_candidates(), years=current_app.config["RETENTION_YEARS"])


@bp.post("/admin/retention/run")
@require("retention.manage")
def retention_run():
    n = 0
    for s in _retention_candidates():
        for u in User.query.filter_by(student_id=s.id).all():
            u.active, u.session_token = False, secrets.token_hex(16)
        s.name, s.mobile, s.email, s.remarks = "ANONYMISED", None, f"anon-{s.id}@redacted.invalid", None
        s.anonymised = True
        n += 1
    audit.log("RETENTION_ANONYMISE", "students", None, new={"records": n})
    db.session.commit()
    flash(f"{n} record(s) anonymised. Aggregate statistics are unaffected.", "ok")
    return redirect(url_for("admin.retention"))
