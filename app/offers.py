"""Recruitment & offer management (I / F / I+F) and the policy explainer."""
import json

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user

from . import policy
from .models import ACCEPTANCE, JOINING, NOC, OFFER_TYPES, PPO, Company, Drive, Offer, Student, db
from .security import offer_or_404, require, scoped_offers
from .services import (create_offer, evaluate_for, held_for, resolve_review, update_offer)
from .validators import text, to_int

bp = Blueprint("offers", __name__)


@bp.route("/offers")
@require("offer.view")
def index():
    q = scoped_offers(current_user)
    f = {k: text(request.args.get(k), 20) for k in ("type", "acceptance", "review", "company")}
    if f["type"] in OFFER_TYPES:
        q = q.filter(Offer.offer_type == f["type"])
    if f["acceptance"] in ACCEPTANCE:
        q = q.filter(Offer.acceptance == f["acceptance"])
    if f["review"] == "pending_review":
        q = q.filter(Offer.review_status == "pending_review")
    if to_int(f["company"]):
        q = q.filter(Offer.company_id == to_int(f["company"]))
    page = max(1, to_int(request.args.get("page"), 1))
    pg = q.order_by(Offer.id.desc()).paginate(page=page, per_page=25, error_out=False)
    return render_template("offers.html", pg=pg, f=f, companies=Company.query.order_by(Company.name).all(),
                           types=OFFER_TYPES, acceptance=ACCEPTANCE)


def _new_ctx(**kw):
    companies = Company.query.filter_by(active=True).order_by(Company.name).all()
    drives = Drive.query.order_by(Drive.drive_date.desc()).all()
    return dict(companies=companies, types=OFFER_TYPES, drives=drives,
                company_opts=[(c.id, f"{c.name} (cat. {c.category})") for c in companies],
                drive_opts=[(d.id, f"{d.drive_date} - {d.title}") for d in drives], **kw)


@bp.route("/offers/new", methods=["GET", "POST"])
@require("offer.write")
def new():
    if request.method == "POST":
        res = create_offer(current_user, request.form)
        if res.offer:
            msg = {"cleared": "Offer recorded.", "pending_review": "Offer recorded but referred for manual policy review.",
                   "overridden": "Offer recorded with an administrator override."}[res.offer.review_status]
            flash(msg, "ok" if res.offer.review_status == "cleared" else "warn")
            return redirect(url_for("offers.detail", oid=res.offer.id))
        if res.blocked:
            flash("Blocked by placement policy - nothing was recorded.", "error")
        return render_template("offer_form.html", **_new_ctx(form=request.form, errors=res.errors, decision=res.decision)), \
            (422 if res.errors else 409 if res.blocked else 200)
    return render_template("offer_form.html", **_new_ctx(form=request.args, errors={}, decision=None))


@bp.route("/offers/<int:oid>")
@require("offer.view")
def detail(oid):
    o = offer_or_404(oid)
    reasons = json.loads(o.policy_reasons or "[]")
    return render_template("offer_detail.html", o=o, reasons_list=reasons, ppo=PPO, joining=JOINING, noc=NOC)


@bp.post("/offers/<int:oid>/update")
@require("offer.write")
def update(oid):
    o = offer_or_404(oid)
    changes, errors = update_offer(current_user, o, request.form)
    for msg in errors.values():
        flash(msg, "error")
    if changes:
        flash("Offer updated.", "ok")
    elif not errors:
        flash("Nothing to change.", "warn")
    return redirect(url_for("offers.detail", oid=o.id))


@bp.route("/reviews")
@require("offer.review")
def reviews():
    pending = Offer.query.filter_by(review_status="pending_review").order_by(Offer.id).all()
    return render_template("reviews.html", pending=[(o, json.loads(o.policy_reasons or "[]")) for o in pending])


@bp.post("/offers/<int:oid>/review")
@require("offer.review")
def review(oid):
    o = offer_or_404(oid)
    err = resolve_review(current_user, o, request.form.get("action"), request.form.get("note"))
    flash(err or "Review recorded.", "error" if err else "ok")
    return redirect(url_for("offers.reviews"))


@bp.route("/policy/check", methods=["GET", "POST"])
@require("policy.check")
def check():
    """Explain why a student would be allowed / blocked / referred BEFORE anything is recorded."""
    out = None
    if request.method == "POST":
        s = Student.query.filter_by(placement_id=text(request.form.get("placement_id"), 40).upper()).first()
        c = db.session.get(Company, to_int(request.form.get("company_id"), 0))
        t = text(request.form.get("offer_type"), 3)
        ctc = request.form.get("ctc_lpa", "").strip()
        try:
            ctc = float(ctc) if ctc else None
        except ValueError:
            ctc = None
        drive = db.session.get(Drive, to_int(request.form.get("drive_id"), 0)) if request.form.get("drive_id") else None
        if not (s and c and t in OFFER_TYPES):
            flash("Choose a valid student, company and offer type.", "error")
        else:
            out = {"student": s, "company": c, "type": t, "decision": evaluate_for(s, c, t, ctc, drive),
                   "options": policy.next_options(held_for(s.id), current_app.config["SWITCH_BY_CATEGORY"])}
    return render_template("policy_check.html", out=out, **_new_ctx(form=request.form, errors={}))
