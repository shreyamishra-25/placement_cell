"""Business logic. Views stay thin; the policy engine is enforced HERE, so calling an
endpoint directly cannot skip a switching check."""
import json
import statistics
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Optional

from flask import current_app

from . import audit, policy
from .models import (ACCEPTANCE, COURSES, JOINING, NOC, OFFER_TYPES, PPO, Attendance, Company, Drive, Offer,
                     Student, db, utcnow)
from .security import scoped_offers, scoped_students
from .validators import number, text, to_int


def mask_mobile(m):
    return None if not m else "******" + m[-4:]


def student_snapshot(s):
    return {"placement_id": s.placement_id, "name": s.name, "mobile": mask_mobile(s.mobile), "email": s.email,
            "course": s.course, "batch": s.batch, "cgpa": s.cgpa, "backlogs": s.backlogs,
            "registration_status": s.registration_status, "eligibility_status": s.eligibility_status,
            "remarks": s.remarks, "archived": s.archived}


def offer_snapshot(o):
    return {"student": o.student_id, "company": o.company_id, "type": o.offer_type, "ctc_lpa": o.ctc_lpa,
            "stipend": o.stipend, "stipend_period": o.stipend_period, "category": o.category,
            "ppo_status": o.ppo_status, "acceptance": o.acceptance, "joining_status": o.joining_status,
            "noc_status": o.noc_status, "review_status": o.review_status, "decision": o.policy_decision}


# ---- policy plumbing ------------------------------------------------------------------------

def switch_flag():
    return current_app.config["SWITCH_BY_CATEGORY"]


def active_offers(student_id, exclude_offer_id=None):
    q = Offer.query.filter(Offer.student_id == student_id, Offer.acceptance.in_(("pending", "accepted")),
                           Offer.review_status != "rejected")
    if exclude_offer_id:
        q = q.filter(Offer.id != exclude_offer_id)
    return q.order_by(Offer.id).all()


def to_held(o):
    return policy.Held(o.offer_type, o.ctc_lpa, o.ppo_status == "accepted",
                       f"offer #{o.id} ({o.company.name}, {o.offer_type})")


def held_for(student_id, exclude_offer_id=None):
    return [to_held(o) for o in active_offers(student_id, exclude_offer_id)]


def evaluate_for(student, company, offer_type, ctc, drive=None, exclude_offer_id=None):
    absent = None
    if drive is not None:
        absences = [a.drive.drive_date for a in Attendance.query.filter_by(
            student_id=student.id, status="absent", exception_granted=False)]
        dates = [d.drive_date for d in Drive.query.all()]
        absent = policy.absence_exclusion(absences, dates, drive.drive_date)
    sf = policy.StudentFacts(student.registration_status, student.eligibility_status, student.archived,
                             student.cgpa, student.backlogs, student.course)
    cf = policy.CompanyFacts(company.name, company.min_cgpa, company.max_backlogs, company.course_list)
    prop = policy.Proposed(offer_type, ctc, company.category if policy.has_fte(offer_type) else None)
    return policy.evaluate(sf, cf, prop, held_for(student.id, exclude_offer_id), absent, switch_flag())


def derive_status(offers):
    acc = [o for o in offers if o.acceptance == "accepted" and o.review_status in ("cleared", "overridden")]
    types = {("I+F" if (o.offer_type == "I" and o.ppo_status == "accepted") else o.offer_type) for o in acc}
    if not types:
        return "unplaced"
    if "I+F" in types or ("I" in types and "F" in types):
        return "internship_plus_fte"
    return "fte_only" if "F" in types else "internship_only"


def recompute_placement(student):
    student.placement_status = derive_status(Offer.query.filter_by(student_id=student.id).all())


def expire_overdue(now=None):
    """Offers not accepted before their deadline expire automatically."""
    now = now or utcnow()
    overdue = Offer.query.filter(Offer.acceptance == "pending", Offer.acceptance_deadline < now).all()
    for o in overdue:
        o.acceptance = "expired"
        audit.log("OFFER_EXPIRED", "offer", o.id, old={"acceptance": "pending"}, new={"acceptance": "expired"},
                  actor=(None, "system", "system"))
        recompute_placement(o.student)
    if overdue:
        db.session.commit()
    return len(overdue)


# ---- offers ---------------------------------------------------------------------------------

@dataclass
class OfferResult:
    offer: Optional[Offer] = None
    decision: Optional[policy.Decision] = None
    errors: dict = field(default_factory=dict)
    blocked: bool = False


def create_offer(actor, form, issued_at=None) -> OfferResult:
    errors = {}
    student = None
    pid = text(form.get("placement_id"), 40).upper()
    if pid:
        student = Student.query.filter_by(placement_id=pid).first()
    elif to_int(form.get("student_id")):
        student = db.session.get(Student, to_int(form.get("student_id")))
    if student is None:
        errors["placement_id"] = "Unknown student."
    company = db.session.get(Company, to_int(form.get("company_id"), 0))
    if company is None or not company.active:
        errors["company_id"] = "Choose an active company."
    otype = text(form.get("offer_type"), 3)
    if otype not in OFFER_TYPES:
        errors["offer_type"] = "Offer type must be I, F or I+F."

    ctc = stipend = None
    ctc_raw, st_raw = text(form.get("ctc_lpa"), 12), text(form.get("stipend"), 12)
    if otype in ("F", "I+F"):
        ctc = number(ctc_raw, "0.01", "500")
        if ctc is None:
            errors["ctc_lpa"] = "Annual CTC (LPA, up to 2 decimals) is required for F and I+F offers."
    elif ctc_raw:
        errors["ctc_lpa"] = "Internship-only offers carry a stipend, not an annual CTC."
    period = text(form.get("stipend_period"), 10) or "monthly"
    if otype in ("I", "I+F"):
        if st_raw:
            stipend = number(st_raw, "0.01", "10000000")
            if stipend is None:
                errors["stipend"] = "Stipend must be a positive amount."
        if period not in ("monthly", "total"):
            errors["stipend_period"] = "Period must be monthly or total."
    elif st_raw:
        errors["stipend"] = "FTE-only offers do not carry an internship stipend."

    try:
        offer_date = date.fromisoformat(text(form.get("offer_date"), 10)) if form.get("offer_date") else date.today()
    except ValueError:
        offer_date = None
        errors["offer_date"] = "Use YYYY-MM-DD."
    if offer_date and offer_date > date.today() + timedelta(days=1):
        errors["offer_date"] = "Offer date cannot be in the future."

    off_campus = form.get("off_campus") in ("1", "on", "true")
    noc = text(form.get("noc_status"), 16) if off_campus else "not_applicable"
    if off_campus and noc not in ("pending", "obtained"):
        errors["noc_status"] = "Off-campus offers need an NOC status (pending / obtained)."

    drive = None
    if form.get("drive_id"):
        drive = db.session.get(Drive, to_int(form.get("drive_id"), 0))
        if drive is None or (company and drive.company_id != company.id):
            errors["drive_id"] = "Drive does not belong to this company."
    if errors:
        return OfferResult(errors=errors)

    decision = evaluate_for(student, company, otype, ctc, drive)
    override = text(form.get("override_reason"), 300)
    review_status = {"ALLOW": "cleared", "REVIEW": "pending_review"}.get(decision.decision)
    if decision.decision != policy.ALLOW and actor.role == "admin" and len(override) >= 10:
        review_status = "overridden"
    if review_status is None:  # BLOCK and no valid admin override
        audit.log("OFFER_BLOCKED", "student", student.id, new={
            "company": company.name, "type": otype, "ctc_lpa": ctc, "reasons": decision.reasons}, actor=_actor(actor))
        db.session.commit()
        return OfferResult(decision=decision, blocked=True)

    issued = issued_at or utcnow()
    o = Offer(student=student, company=company, drive=drive, offer_type=otype, ctc_lpa=ctc,
              category=policy.category_for(ctc), stipend=stipend, stipend_period=period if stipend else None,
              ppo_status={"I": "pending", "I+F": "offered"}.get(otype, "not_applicable"),
              offer_date=offer_date, issued_at=issued,
              acceptance_deadline=policy.acceptance_deadline(issued, company.timeline_hours),
              off_campus=off_campus, noc_status=noc, review_status=review_status,
              policy_decision=decision.decision, policy_reasons=json.dumps(decision.reasons),
              override_reason=override or None, remarks=text(form.get("remarks"), 500) or None,
              created_by=actor.id)
    db.session.add(o)
    db.session.flush()
    audit.log("OFFER_CREATE", "offer", o.id, new={**offer_snapshot(o), "reasons": decision.reasons,
              "override_reason": o.override_reason}, actor=_actor(actor))
    recompute_placement(student)
    db.session.commit()
    return OfferResult(offer=o, decision=decision)


def _actor(user):
    return (user.id, user.username, user.role)


def update_offer(actor, offer, form):
    """Officer/admin updates after issue. Returns (changed_fields, errors)."""
    errors, changes = {}, {}
    now = utcnow()
    acc = text(form.get("acceptance"), 10)
    if acc and acc != offer.acceptance:
        if offer.acceptance != "pending" or acc not in ("accepted", "declined"):
            errors["acceptance"] = f"Cannot move an offer from '{offer.acceptance}' to '{acc}'."
        elif acc == "accepted" and offer.review_status not in ("cleared", "overridden"):
            errors["acceptance"] = "Offer is awaiting policy review and cannot be accepted yet."
        elif acc == "accepted" and offer.acceptance_deadline < now:
            errors["acceptance"] = "The acceptance deadline has passed; the offer has expired."
        else:
            changes["acceptance"] = acc
    join = text(form.get("joining_status"), 10)
    if join and join != offer.joining_status:
        effective_acc = changes.get("acceptance", offer.acceptance)
        if join not in JOINING or effective_acc != "accepted" or offer.joining_status != "pending":
            errors["joining_status"] = "Joining can be set only once, on an accepted offer."
        else:
            changes["joining_status"] = join
    ppo = text(form.get("ppo_status"), 16)
    if ppo and ppo != offer.ppo_status:
        if offer.offer_type == "F" or ppo not in PPO:
            errors["ppo_status"] = "PPO status applies only to I and I+F offers."
        elif ppo == "accepted" and changes.get("acceptance", offer.acceptance) != "accepted":
            errors["ppo_status"] = "Accept the offer before accepting the PPO."
        else:
            changes["ppo_status"] = ppo
    noc = text(form.get("noc_status"), 16)
    if noc and noc != offer.noc_status:
        if not offer.off_campus or noc not in ("pending", "obtained"):
            errors["noc_status"] = "NOC applies only to off-campus offers."
        else:
            changes["noc_status"] = noc
    remarks = text(form.get("remarks"), 500)
    if form.get("remarks") is not None and (remarks or None) != offer.remarks:
        changes["remarks"] = remarks or None
    if errors or not changes:
        return {}, errors
    old = {k: getattr(offer, k) for k in changes}
    for k, v in changes.items():
        setattr(offer, k, v)
    recompute_placement(offer.student)
    audit.log("OFFER_UPDATE", "offer", offer.id, old=old, new=changes)
    db.session.commit()
    return changes, errors


def resolve_review(actor, offer, action, note):
    note = text(note, 300)
    if offer.review_status != "pending_review":
        return "This offer is not awaiting review."
    if len(note) < 5:
        return "A note of at least 5 characters is required."
    old = {"review_status": offer.review_status, "acceptance": offer.acceptance}
    if action == "approve":
        offer.review_status = "cleared"
    elif action == "reject":
        offer.review_status = "rejected"
        offer.acceptance = "declined"
    else:
        return "Unknown action."
    offer.override_reason = note
    recompute_placement(offer.student)
    audit.log("OFFER_REVIEW_" + action.upper(), "offer", offer.id, old=old,
              new={"review_status": offer.review_status, "acceptance": offer.acceptance, "note": note})
    db.session.commit()
    return None


# ---- attendance -----------------------------------------------------------------------------

def mark_attendance(actor, drive, student, status):
    if status not in ("present", "absent"):
        return None, "Status must be present or absent."
    a = Attendance.query.filter_by(drive_id=drive.id, student_id=student.id).first()
    old = None
    if a is None:
        a = Attendance(drive=drive, student=student, status=status, recorded_by=actor.id)
        db.session.add(a)
        db.session.flush()
    else:
        old = {"status": a.status}
        a.status, a.recorded_by = status, actor.id
        if status == "present":
            a.exception_granted, a.exception_reason = False, None
    audit.log("ATTENDANCE_MARK", "attendance", a.id, old=old,
              new={"drive": drive.id, "student": student.id, "status": status})
    db.session.commit()
    return a, None


def grant_exception(actor, att, reason):
    reason = text(reason, 200)
    if att.status != "absent":
        return "Only absences can be excused."
    if len(reason) < 10:
        return "Give a reason of at least 10 characters (e.g. the emergency and evidence seen)."
    att.exception_granted, att.exception_reason, att.exception_by = True, reason, actor.id
    audit.log("ATTENDANCE_EXCEPTION", "attendance", att.id, new={"reason": reason})
    db.session.commit()
    return None


def absence_flags():
    """Unexcused absences still inside their exclusion window (relative to today's upcoming drives)."""
    dates = sorted(d.drive_date for d in Drive.query.all())
    out = []
    for a in Attendance.query.filter_by(status="absent", exception_granted=False).all():
        later = [d for d in dates if d > a.drive.drive_date][:policy.ABSENCE_WINDOW]
        out.append({"student": a.student, "drive": a.drive, "attendance": a,
                    "excluded_through": later[-1] if len(later) == policy.ABSENCE_WINDOW else None,
                    "remaining": len(later)})
    return out


# ---- conflicts and reporting ----------------------------------------------------------------

def find_conflicts(students=None):
    """Re-check every student's active offers against each other and flag unresolved violations
    (e.g. a PPO acceptance that turned an internship into I+F while another offer is held)."""
    out = []
    students = students if students is not None else Student.query.filter_by(archived=False).all()
    for s in students:
        offers = active_offers(s.id)
        for j in range(1, len(offers)):
            o = offers[j]
            prop = policy.Proposed(o.offer_type, o.ctc_lpa)
            d = policy.check_switching([to_held(x) for x in offers[:j]], prop, switch_flag())
            if d.decision == policy.BLOCK and o.review_status != "overridden":
                out.append({"student": s, "offer": o, "reasons": [r for r in d.reasons if r.startswith("[BLOCK]")]})
    return out


def _agg(values):
    if not values:
        return {"count": 0, "highest": None, "average": None, "median": None}
    return {"count": len(values), "highest": max(values), "average": round(sum(values) / len(values), 2),
            "median": round(statistics.median(values), 2)}


def _live(o):
    return o.acceptance == "accepted" and o.review_status in ("cleared", "overridden")


def stats(user):
    students = scoped_students(user).filter(Student.archived.is_(False)).all()
    ids = {s.id for s in students}
    offers = [o for o in scoped_offers(user).all() if o.student_id in ids]
    by_student = {}
    for o in offers:
        by_student.setdefault(o.student_id, []).append(o)

    def block(group):
        placed = [s for s in group if s.placement_status != "unplaced"]
        gids = {s.id for s in group}
        return {"total": len(group),
                "registered": sum(s.registration_status == "registered" for s in group),
                "eligible": sum(s.eligibility_status == "eligible" for s in group),
                "placed": len(placed), "unplaced": len(group) - len(placed),
                "I": sum(s.placement_status == "internship_only" for s in group),
                "F": sum(s.placement_status == "fte_only" for s in group),
                "IF": sum(s.placement_status == "internship_plus_fte" for s in group),
                "offers": sum(1 for o in offers if o.student_id in gids)}

    by_course = [dict(code=c, name=COURSES[c][0], **block([s for s in students if s.course == c])) for c in COURSES]
    keys = sorted({(s.course, s.batch) for s in students})
    by_batch = [dict(course=c, batch=b, **block([s for s in students if s.course == c and s.batch == b])) for c, b in keys]

    # one FTE figure per placed student (their best accepted FTE), so nobody is double-counted
    fte_vals = []
    for sid, os_ in by_student.items():
        v = [o.ctc_lpa for o in os_ if _live(o) and o.ctc_lpa is not None]
        if v:
            fte_vals.append(max(v))
    stip_vals = [o.stipend for o in offers if _live(o) and o.stipend is not None and o.stipend_period == "monthly"]

    totals = block(students)
    totals.update(ineligible=sum(s.eligibility_status == "ineligible" for s in students),
                  pending_verification=sum(s.eligibility_status == "pending_verification" for s in students),
                  deregistered=sum(s.registration_status == "deregistered" for s in students),
                  offers_active=sum(1 for o in offers if o.acceptance in ("pending", "accepted")))
    pend = {"acceptance": sum(o.acceptance == "pending" for o in offers),
            "joining": sum(_live(o) and o.joining_status == "pending" for o in offers),
            "review": sum(o.review_status == "pending_review" for o in offers)}
    return {"totals": totals, "by_course": by_course, "by_batch": by_batch, "fte": _agg(fte_vals),
            "stipend": _agg(stip_vals), "pending": pend}


def company_report(user):
    q = Company.query
    if user.role == "recruiter":
        q = q.filter(Company.id == user.company_id)
    offers = scoped_offers(user).all()
    rows = []
    for c in q.order_by(Company.name).all():
        co = [o for o in offers if o.company_id == c.id]
        live = [o for o in co if _live(o)]
        fte = [o.ctc_lpa for o in live if o.ctc_lpa is not None]
        stip = [o.stipend for o in live if o.stipend is not None and o.stipend_period == "monthly"]
        rows.append({"company": c, "offers": len(co), "accepted": len(live),
                     "students": len({o.student_id for o in live}), "fte": _agg(fte), "stipend": _agg(stip),
                     "categories": sorted({o.category for o in co if o.category})})
    return rows
