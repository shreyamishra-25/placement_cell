"""Server-side input validation. Nothing from a request is trusted until it passes here."""
import re
from decimal import Decimal, InvalidOperation

from .models import COURSES, ELIGIBILITY, REGISTRATION

PID_RE = re.compile(r"^[A-Z0-9][A-Z0-9\-/]{3,23}$")
MOBILE_RE = re.compile(r"^[6-9][0-9]{9}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$")
BATCH_RE = re.compile(r"^(20[0-9]{2})-([0-9]{2})$")
COMPANY_RE = re.compile(r"^[A-Za-z0-9 .,&()'\-]{2,100}$")
USERNAME_RE = re.compile(r"^[a-z0-9._\-]{3,40}$")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

STUDENT_FIELDS = ("name", "mobile", "email", "course", "batch", "cgpa", "backlogs",
                  "registration_status", "eligibility_status", "remarks")


def text(v, n=500):
    return _CTRL.sub("", (v or "").strip())[:n]


def to_int(v, default=None):
    try:
        return int(str(v).strip())
    except (ValueError, TypeError):
        return default


def number(v, lo, hi, places=2):
    try:
        d = Decimal(str(v).strip())
    except (InvalidOperation, ValueError):
        return None
    if not d.is_finite() or d < Decimal(str(lo)) or d > Decimal(str(hi)) or -d.as_tuple().exponent > places:
        return None
    return float(d)


def clean_student(form, existing=None):
    """Validate a student form / CSV row. Only whitelisted fields are ever returned
    (mass-assignment protection); placement_id is accepted on create only."""
    e, d = {}, {}
    if existing is None:
        pid = text(form.get("placement_id"), 40).upper()
        if PID_RE.match(pid):
            d["placement_id"] = pid
        else:
            e["placement_id"] = "Placement ID must be 4-24 characters: A-Z, 0-9, '-' or '/'."

    name = " ".join(text(form.get("name"), 200).split())
    if 2 <= len(name) <= 100 and all(c.isalpha() or c in " .'-" for c in name):
        d["name"] = name
    else:
        e["name"] = "Name must be 2-100 letters (spaces . ' - allowed)."

    mobile = re.sub(r"[ \-]", "", text(form.get("mobile"), 20))
    if mobile.startswith("+91"):
        mobile = mobile[3:]
    if MOBILE_RE.match(mobile):
        d["mobile"] = mobile
    else:
        e["mobile"] = "Enter a valid 10-digit Indian mobile number."

    email = text(form.get("email"), 254).lower()
    if EMAIL_RE.match(email):
        d["email"] = email
    else:
        e["email"] = "Enter a valid email address."

    course = text(form.get("course"), 8)
    if course in COURSES:
        d["course"] = course
    else:
        e["course"] = "Choose one of the five programmes."

    m = BATCH_RE.match(text(form.get("batch"), 7))
    if m and course in COURSES and (int(m.group(1)) + COURSES[course][1]) % 100 == int(m.group(2)):
        d["batch"] = m.group(0)
    else:
        dur = COURSES[course][1] if course in COURSES else "?"
        e["batch"] = f"Batch must look like 2025-27 and match the programme duration ({dur} years)."

    cgpa = number(form.get("cgpa"), 0, 10)
    if cgpa is None:
        e["cgpa"] = "CGPA must be between 0 and 10."
    else:
        d["cgpa"] = cgpa
    back = to_int(form.get("backlogs"), -1)
    if 0 <= back <= 50:
        d["backlogs"] = back
    else:
        e["backlogs"] = "Backlogs must be 0-50."

    reg = text(form.get("registration_status"), 20)
    if reg in REGISTRATION:
        d["registration_status"] = reg
    else:
        e["registration_status"] = "Invalid registration status."
    el = text(form.get("eligibility_status"), 24)
    if el in ELIGIBILITY:
        d["eligibility_status"] = el
    else:
        e["eligibility_status"] = "Invalid eligibility status."

    d["remarks"] = text(form.get("remarks"), 500) or None
    return d, e


def csv_safe(value):
    """Neutralise spreadsheet formula injection in exported/imported cells."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s
