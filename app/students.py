"""Student database: CRUD, archive/restore, search, CSV import/export."""
import csv
import io
from datetime import datetime

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy.exc import IntegrityError

from . import audit, policy
from .models import COURSES, ELIGIBILITY, PLACEMENT, REGISTRATION, Attendance, Student, db
from .security import has_perm, require, scoped_students, student_or_404
from .services import held_for, recompute_placement, student_snapshot
from .validators import STUDENT_FIELDS, clean_student, csv_safe, text, to_int

bp = Blueprint("students", __name__)
PER_PAGE = 25
IMPORT_COLUMNS = ("placement_id", "name", "mobile", "email", "course", "batch", "cgpa", "backlogs")
MAX_IMPORT_ROWS = 2000


def _like(q):
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@bp.route("/students")
@require("student.view")
def index():
    if current_user.role == "student":
        return redirect(url_for("students.detail", sid=current_user.student_id or 0))
    q = scoped_students(current_user)
    archived = request.args.get("archived") == "1" and has_perm(current_user, "student.archive")
    q = q.filter(Student.archived.is_(archived))
    f = {k: text(request.args.get(k), 40) for k in ("course", "batch", "registration", "eligibility", "placement", "term")}
    if f["course"] in COURSES:
        q = q.filter(Student.course == f["course"])
    if f["batch"]:
        q = q.filter(Student.batch == f["batch"])
    if f["registration"] in REGISTRATION:
        q = q.filter(Student.registration_status == f["registration"])
    if f["eligibility"] in ELIGIBILITY:
        q = q.filter(Student.eligibility_status == f["eligibility"])
    if f["placement"] in PLACEMENT:
        q = q.filter(Student.placement_status == f["placement"])
    if f["term"]:
        pat = _like(f["term"][:50])  # bound parameter + escaped wildcards: no SQL injection, no wildcard abuse
        q = q.filter(db.or_(Student.name.ilike(pat, escape="\\"), Student.placement_id.ilike(pat, escape="\\"),
                            Student.email.ilike(pat, escape="\\")))
    page = max(1, to_int(request.args.get("page"), 1))
    pg = q.order_by(Student.placement_id).paginate(page=page, per_page=PER_PAGE, error_out=False)
    return render_template("students.html", pg=pg, f=f, archived=archived, courses=COURSES)


_DEFAULTS = {"placement_id": "", "name": "", "mobile": "", "email": "", "course": "", "batch": "", "cgpa": "",
             "backlogs": 0, "registration_status": "registered", "eligibility_status": "pending_verification",
             "remarks": ""}


def _form_ctx(s, form, errors):
    """Values shown in the form: what was just posted, else the stored record, else defaults."""
    vals = {}
    for k, default in _DEFAULTS.items():
        if form:
            vals[k] = form.get(k, default)
        elif s is not None:
            vals[k] = getattr(s, k, default) if k != "remarks" else (s.remarks or "")
        else:
            vals[k] = default
    pretty = lambda seq: [(x, x.replace("_", " ")) for x in seq]  # noqa: E731
    return dict(s=s, vals=vals, errors=errors, course_opts=[(c, v[0]) for c, v in COURSES.items()],
                reg_opts=pretty(REGISTRATION), elig_opts=pretty(ELIGIBILITY))


@bp.route("/students/new", methods=["GET", "POST"])
@require("student.write")
def new():
    form, errors = request.form if request.method == "POST" else {}, {}
    if request.method == "POST":
        data, errors = clean_student(form)
        if not errors and Student.query.filter_by(placement_id=data["placement_id"]).first():
            errors["placement_id"] = "This Placement ID already exists."
        if not errors:
            s = Student(**data)
            db.session.add(s)
            try:
                db.session.flush()
            except IntegrityError:  # race with another request; the DB constraint is the real guard
                db.session.rollback()
                errors["placement_id"] = "This Placement ID already exists."
            else:
                audit.log("STUDENT_CREATE", "student", s.id, new=student_snapshot(s))
                db.session.commit()
                flash("Student created.", "ok")
                return redirect(url_for("students.detail", sid=s.id))
    return render_template("student_form.html", **_form_ctx(None, form, errors))


@bp.route("/students/<int:sid>")
@require("student.view")
def detail(sid):
    s = student_or_404(sid)
    opts = policy.next_options(held_for(s.id), current_app.config["SWITCH_BY_CATEGORY"])
    att = Attendance.query.filter_by(student_id=s.id).all()
    return render_template("student_detail.html", s=s, opts=opts, att=att)


@bp.route("/students/<int:sid>/edit", methods=["GET", "POST"])
@require("student.write")
def edit(sid):
    s = student_or_404(sid)
    form, errors = request.form if request.method == "POST" else {}, {}
    if request.method == "POST":
        if to_int(form.get("version")) != s.version:
            flash("Someone else changed this record while you were editing. Reload and retry.", "error")
            return render_template("student_form.html", **_form_ctx(s, form, {})), 409
        data, errors = clean_student(form, existing=s)
        if not errors:
            old = student_snapshot(s)
            for k in STUDENT_FIELDS:  # explicit whitelist: placement_status, archived, version etc. cannot be posted
                setattr(s, k, data[k])
            s.version += 1
            new = student_snapshot(s)
            diff_old = {k: v for k, v in old.items() if new[k] != v}
            audit.log("STUDENT_UPDATE", "student", s.id, old=diff_old, new={k: new[k] for k in diff_old})
            db.session.commit()
            flash("Student updated.", "ok")
            return redirect(url_for("students.detail", sid=s.id))
    return render_template("student_form.html", **_form_ctx(s, form, errors))


@bp.post("/students/<int:sid>/archive")
@require("student.archive")
def archive(sid):
    s = student_or_404(sid)
    reason = text(request.form.get("reason"), 200)
    if len(reason) < 5:
        flash("Give a reason (at least 5 characters) for archiving.", "error")
    elif not s.archived:
        s.archived, s.archived_at, s.archive_reason = True, datetime.utcnow(), reason
        audit.log("STUDENT_ARCHIVE", "student", s.id, new={"reason": reason})
        db.session.commit()
        flash("Student archived. Placement history is retained.", "ok")
    return redirect(url_for("students.detail", sid=s.id))


@bp.post("/students/<int:sid>/restore")
@require("student.restore")
def restore(sid):
    s = student_or_404(sid)
    if s.archived and not s.anonymised:
        s.archived, s.archived_at, s.archive_reason = False, None, None
        audit.log("STUDENT_RESTORE", "student", s.id)
        db.session.commit()
        flash("Student restored.", "ok")
    return redirect(url_for("students.detail", sid=s.id))


# ---- CSV export / import --------------------------------------------------------------------

@bp.route("/students/export")
@require("student.export")
def export():
    sensitive = request.args.get("sensitive") == "1" and current_user.role == "admin"
    cap = current_app.config["EXPORT_ROW_CAP"]
    rows = scoped_students(current_user).filter(Student.archived.is_(False)).order_by(Student.placement_id).limit(cap).all()
    cols = ["placement_id", "name", "email", "course", "batch", "registration_status", "eligibility_status", "placement_status"]
    if sensitive:
        cols += ["mobile", "best_fte_ctc_lpa"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for s in rows:
        row = [getattr(s, c, "") for c in cols if c not in ("mobile", "best_fte_ctc_lpa")]
        if sensitive:
            ctcs = [o.ctc_lpa for o in s.offers if o.acceptance == "accepted" and o.ctc_lpa]
            row += [s.mobile, max(ctcs) if ctcs else ""]
        w.writerow([csv_safe(v) for v in row])
    audit.log("EXPORT_STUDENTS", "export", None, new={"rows": len(rows), "columns": cols, "sensitive": sensitive})
    db.session.commit()
    resp = Response(buf.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = f'attachment; filename="students-{datetime.utcnow():%Y%m%d-%H%M}.csv"'
    return resp


@bp.route("/students/import", methods=["GET", "POST"])
@require("student.import")
def import_csv():
    result = None
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename.lower().endswith(".csv"):
            flash("Upload a .csv file (max 1 MB).", "error")
            return render_template("import.html", result=None, columns=IMPORT_COLUMNS)
        try:
            raw = f.read(1024 * 1024 + 1).decode("utf-8-sig")
        except UnicodeDecodeError:
            flash("File must be UTF-8 text.", "error")
            return render_template("import.html", result=None, columns=IMPORT_COLUMNS)
        reader = csv.DictReader(io.StringIO(raw))
        missing = [c for c in IMPORT_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            flash("Missing columns: " + ", ".join(missing), "error")
            return render_template("import.html", result=None, columns=IMPORT_COLUMNS)
        existing = {p for (p,) in db.session.query(Student.placement_id)}
        seen, good, errs = set(), [], []
        for n, row in enumerate(reader, start=2):
            if n - 1 > MAX_IMPORT_ROWS:
                errs.append((n, "Too many rows (limit 2000)."))
                break
            row = {k: (v or "") for k, v in row.items() if k}
            row.setdefault("registration_status", "registered")
            row.setdefault("eligibility_status", "pending_verification")
            row["registration_status"] = row["registration_status"] or "registered"
            row["eligibility_status"] = row["eligibility_status"] or "pending_verification"
            data, e = clean_student(row)
            if not e:
                pid = data["placement_id"]
                if pid in existing or pid in seen:
                    e["placement_id"] = "Duplicate Placement ID."
                seen.add(pid)
            if e:
                errs.append((n, "; ".join(f"{k}: {v}" for k, v in e.items())))
            else:
                good.append(data)
        if errs:  # all-or-nothing: one bad row means nothing is imported
            result = {"imported": 0, "errors": errs}
            audit.log("IMPORT_REJECTED", "import", None, new={"errors": len(errs)})
        else:
            for d in good:
                db.session.add(Student(**d))
            audit.log("STUDENT_IMPORT", "import", None, new={"rows": len(good)})
            result = {"imported": len(good), "errors": []}
        db.session.commit()
    return render_template("import.html", result=result, columns=IMPORT_COLUMNS)
