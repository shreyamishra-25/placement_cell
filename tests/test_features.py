"""Functional tests: offers, policy enforcement through the service, reports, attendance, retention, backup."""
import os
from datetime import date, timedelta

import pytest

from app import audit, backup
from app.models import Attendance, AuditLog, Company, Drive, Offer, Student, User, db, utcnow
from app.services import (create_offer, expire_overdue, find_conflicts, mark_attendance, stats, update_offer)
from conftest import KEY, login, mk_offer


def student(pid):
    return Student.query.filter_by(placement_id=pid).first()


def admin():
    return User.query.filter_by(username="admin").first()


def test_history_is_preserved_and_status_is_derived(app):
    mk_offer(app, "MTCS-25-001", "Nimbus", "I", stipend=20000)
    mk_offer(app, "MTCS-25-001", "Praxis", "F", ctc=8)
    with app.app_context():
        s = student("MTCS-25-001")
        assert len(s.offers) == 2 and s.placement_status == "internship_plus_fte"


def test_unique_placed_students_vs_total_offers(app):
    mk_offer(app, "MTCS-25-001", "Praxis", "F", ctc=7.5)
    mk_offer(app, "MTCS-25-001", "Zenith", "F", ctc=18)               # same student, second offer
    mk_offer(app, "MTCS-25-002", "Nimbus", "I", stipend=25000)
    with app.app_context():
        st = stats(admin())
        t = st["totals"]
        assert t["placed"] == 2 and t["offers"] == 3 and t["unplaced"] == 2
        assert (t["I"], t["F"], t["IF"]) == (1, 1, 0)
        cs = next(r for r in st["by_course"] if r["code"] == "MTCS")
        assert (cs["total"], cs["placed"], cs["offers"]) == (3, 2, 3)


def test_ctc_and_stipend_are_reported_separately(app):
    mk_offer(app, "MTCS-25-001", "Praxis", "F", ctc=7.5)
    mk_offer(app, "MTCS-25-002", "Zenith", "F", ctc=18)
    mk_offer(app, "MTCS-25-003", "Nimbus", "I", stipend=25000)
    with app.app_context():
        st = stats(admin())
        assert st["fte"]["highest"] == 18 and st["fte"]["average"] == 12.75 and st["fte"]["median"] == 12.75
        assert st["stipend"]["highest"] == 25000 and st["stipend"]["count"] == 1


def test_fte_stats_use_one_figure_per_student(app):
    mk_offer(app, "MTCS-25-001", "Praxis", "F", ctc=7.5)
    mk_offer(app, "MTCS-25-001", "Zenith", "F", ctc=18)               # same student: best accepted FTE only
    with app.app_context():
        assert stats(admin())["fte"] == {"count": 1, "highest": 18, "average": 18, "median": 18}


def test_declined_and_expired_offers_release_the_student(app):
    oid = mk_offer(app, "MTCS-25-001", "Zenith", "F", ctc=20, accept=False)         # A+, pending
    with app.app_context():
        res = create_offer(admin(), {"placement_id": "MTCS-25-001", "company_id": Company.query.filter_by(name="Orbit").first().id,
                                     "offer_type": "F", "ctc_lpa": "12"})
        assert res.blocked                                                         # pending A+ already restricts
        update_offer(admin(), db.session.get(Offer, oid), {"acceptance": "declined"})
        res = create_offer(admin(), {"placement_id": "MTCS-25-001", "company_id": Company.query.filter_by(name="Orbit").first().id,
                                     "offer_type": "F", "ctc_lpa": "12"})
        assert res.offer is not None and res.decision.decision == "ALLOW"


def test_offers_expire_after_24_hours_or_company_timeline(app):
    with app.app_context():
        db.session.get(Company, 4).timeline_hours = 6
        db.session.commit()
    a = mk_offer(app, "MTCS-25-001", "Praxis", "F", ctc=8, accept=False)
    b = mk_offer(app, "MTCS-25-002", "Nimbus", "F", ctc=4, accept=False)
    with app.app_context():
        pa, pb = db.session.get(Offer, a), db.session.get(Offer, b)
        assert pa.acceptance_deadline - pa.issued_at == timedelta(hours=24)
        assert pb.acceptance_deadline - pb.issued_at == timedelta(hours=6)       # earlier of the two
        assert expire_overdue(now=utcnow() + timedelta(hours=7)) == 1
        assert db.session.get(Offer, b).acceptance == "expired" and db.session.get(Offer, a).acceptance == "pending"
        assert expire_overdue(now=utcnow() + timedelta(hours=25)) == 1
        assert student("MTCS-25-001").placement_status == "unplaced"
        assert AuditLog.query.filter_by(action="OFFER_EXPIRED").count() == 2


def test_cannot_accept_after_deadline_or_before_review(app):
    with app.app_context():
        old = utcnow() - timedelta(days=2)
        co = Company.query.filter_by(name="Praxis").first().id
        res = create_offer(admin(), {"placement_id": "MTCS-25-001", "company_id": co, "offer_type": "F", "ctc_lpa": "8"}, issued_at=old)
        _, err = update_offer(admin(), res.offer, {"acceptance": "accepted"})
        assert "deadline" in err["acceptance"]
        student("MTCS-25-002").eligibility_status = "pending_verification"
        db.session.commit()
        res2 = create_offer(admin(), {"placement_id": "MTCS-25-002", "company_id": co, "offer_type": "F", "ctc_lpa": "8"})
        assert res2.offer.review_status == "pending_review"
        _, err = update_offer(admin(), res2.offer, {"acceptance": "accepted"})
        assert "review" in err["acceptance"]


def test_review_queue_approve_and_reject(app):
    with app.app_context():
        student("MTCS-25-001").eligibility_status = "pending_verification"
        student("MTCS-25-002").eligibility_status = "pending_verification"
        db.session.commit()
    a = mk_offer(app, "MTCS-25-001", "Praxis", "F", ctc=8, accept=False)
    b = mk_offer(app, "MTCS-25-002", "Praxis", "F", ctc=8, accept=False)
    c = login(app, "admin")
    assert b"Offer #" in c.get("/reviews").data
    assert c.post(f"/offers/{a}/review", data={"action": "approve", "note": "Eligibility verified by registrar"}).status_code == 302
    assert c.post(f"/offers/{b}/review", data={"action": "reject", "note": "Documents not valid"}).status_code == 302
    with app.app_context():
        assert db.session.get(Offer, a).review_status == "cleared"
        ob = db.session.get(Offer, b)
        assert ob.review_status == "rejected" and ob.acceptance == "declined"
    assert login(app, "officer").post(f"/offers/{a}/review", data={"action": "approve", "note": "me too"}).status_code == 403


def test_invalid_offer_values_are_rejected(app):
    with app.app_context():
        co = Company.query.filter_by(name="Praxis").first().id
        base = {"placement_id": "MTCS-25-001", "company_id": co}
        for form in ({**base, "offer_type": "F"},                                         # CTC missing
                     {**base, "offer_type": "F", "ctc_lpa": "-5"}, {**base, "offer_type": "F", "ctc_lpa": "abc"},
                     {**base, "offer_type": "F", "ctc_lpa": "9999"}, {**base, "offer_type": "F", "ctc_lpa": "8", "stipend": "100"},
                     {**base, "offer_type": "I", "stipend": "100", "ctc_lpa": "8"}, {**base, "offer_type": "X"},
                     {**base, "offer_type": "F", "ctc_lpa": "8", "offer_date": "2099-01-01"},
                     {**base, "offer_type": "F", "ctc_lpa": "8", "off_campus": "1", "noc_status": "whatever"},
                     {"placement_id": "NOPE-0000", "company_id": co, "offer_type": "F", "ctc_lpa": "8"}):
            res = create_offer(admin(), form)
            assert res.offer is None and res.errors, form
        assert Offer.query.count() == 0


def test_off_campus_offer_with_noc_is_recorded_and_counts_for_switching(app):
    with app.app_context():
        co = Company.query.filter_by(name="Praxis").first().id
        res = create_offer(admin(), {"placement_id": "MSDF-25-001", "company_id": co, "offer_type": "F", "ctc_lpa": "7",
                                     "off_campus": "1", "noc_status": "pending"})
        o = res.offer
        assert o.off_campus and o.noc_status == "pending"
        update_offer(admin(), o, {"noc_status": "obtained", "acceptance": "accepted"})
        assert o.noc_status == "obtained" and student("MSDF-25-001").placement_status == "fte_only"
        res = create_offer(admin(), {"placement_id": "MSDF-25-001", "company_id": co, "offer_type": "F", "ctc_lpa": "8"})
        assert res.blocked                                                              # 8 < 1.5 x 7


def test_joining_status_rules(app):
    oid = mk_offer(app, "MTCS-25-001", "Praxis", "F", ctc=8, accept=False)
    with app.app_context():
        o = db.session.get(Offer, oid)
        _, err = update_offer(admin(), o, {"joining_status": "joined"})
        assert "joining" in err["joining_status"].lower()                                # cannot join an unaccepted offer
        update_offer(admin(), o, {"acceptance": "accepted", "joining_status": "joined"})
        assert o.joining_status == "joined"
        _, err = update_offer(admin(), o, {"joining_status": "not_joined"})
        assert err                                                                      # joining is final


def test_ppo_acceptance_makes_internship_behave_as_i_plus_f_and_is_flagged(app):
    i = mk_offer(app, "MTCS-25-001", "Nimbus", "I", stipend=20000)
    mk_offer(app, "MTCS-25-001", "Praxis", "F", ctc=8)
    with app.app_context():
        assert find_conflicts() == []
        update_offer(admin(), db.session.get(Offer, i), {"ppo_status": "accepted"})
        conflicts = find_conflicts()
        assert len(conflicts) == 1 and conflicts[0]["student"].placement_id == "MTCS-25-001"
        assert "I+F" in conflicts[0]["reasons"][0]


def test_attendance_absence_flag_exclusion_window_and_emergency_exception(app):
    with app.app_context():
        co = Company.query.filter_by(name="Praxis").first()
        base = date.today() - timedelta(days=30)
        drives = []
        for k in range(5):
            d = Drive(company=co, title=f"Drive {k}", activity="Test", drive_date=base + timedelta(days=k * 3))
            db.session.add(d)
            drives.append(d)
        db.session.commit()
        s = student("MTCS-25-001")
        att, err = mark_attendance(admin(), drives[0], s, "absent")
        assert att.status == "absent" and not err
        att_id, co_id, drive1_id = att.id, co.id, drives[1].id

        def attempt(i):
            return create_offer(admin(), {"placement_id": "MTCS-25-001", "company_id": co.id, "offer_type": "I",
                                          "stipend": "1000", "drive_id": drives[i].id})
        first = attempt(3)                                                              # 3rd drive after the absence
        assert first.offer and first.decision.decision == "REVIEW" and "Unexcused absence" in " ".join(first.decision.reasons)
        first.offer.acceptance = "declined"                                             # release for the next probe
        db.session.commit()
        fourth = attempt(4)                                                             # 4th drive: back in
        assert fourth.offer and fourth.decision.decision == "ALLOW"
        fourth.offer.acceptance = "declined"
        db.session.commit()
        # emergency exception: admin only, needs a real reason, clears the flag
        c = login(app, "admin")
    r = c.post(f"/attendance/{att_id}/exception", data={"reason": "short"})
    assert r.status_code == 302
    with app.app_context():
        assert not db.session.get(Attendance, att_id).exception_granted
    c.post(f"/attendance/{att_id}/exception", data={"reason": "Hospitalised; discharge summary seen"})
    assert login(app, "officer").post(f"/attendance/{att_id}/exception", data={"reason": "officer cannot do this one"}).status_code == 403
    with app.app_context():
        assert db.session.get(Attendance, att_id).exception_granted
        again = create_offer(admin(), {"placement_id": "MTCS-25-001", "company_id": co_id, "offer_type": "I",
                                       "stipend": "1000", "drive_id": drive1_id})
        assert again.decision.decision == "ALLOW"


def test_ineligible_and_deregistered_students_are_blocked_with_reasons(app):
    with app.app_context():
        student("MTCS-25-001").registration_status = "deregistered"
        student("MTCS-25-002").eligibility_status = "ineligible"
        db.session.commit()
        co = Company.query.filter_by(name="Praxis").first().id
        for pid, word in (("MTCS-25-001", "deregistered"), ("MTCS-25-002", "ineligible")):
            res = create_offer(admin(), {"placement_id": pid, "company_id": co, "offer_type": "F", "ctc_lpa": "8"})
            assert res.blocked and word in " ".join(res.decision.reasons)


def test_policy_check_page_explains_without_recording(app):
    mk_offer(app, "MTCS-25-001", "Zenith", "F", ctc=20)
    c = login(app, "officer")
    r = c.post("/policy/check", data={"placement_id": "MTCS-25-001", "company_id": 3, "offer_type": "F", "ctc_lpa": "9"})
    assert r.status_code == 200 and b"BLOCK" in r.data and b"out of the placement process" in r.data
    with app.app_context():
        assert Offer.query.count() == 1


def test_optimistic_locking_rejects_stale_edits(app):
    with app.app_context():
        sid = student("MTCS-25-001").id
    form = {"name": "Aarav Patel", "mobile": "9876543210", "email": "a@x.example", "course": "MTCS", "batch": "2025-27",
            "cgpa": "8", "backlogs": "0", "registration_status": "registered", "eligibility_status": "eligible"}
    c1, c2 = login(app, "officer"), login(app, "admin")
    assert c1.post(f"/students/{sid}/edit", data={**form, "version": "1", "cgpa": "8.5"}).status_code == 302
    r = c2.post(f"/students/{sid}/edit", data={**form, "version": "1", "cgpa": "6.5"})        # still holding version 1
    assert r.status_code == 409 and b"Someone else changed" in r.data
    with app.app_context():
        assert student("MTCS-25-001").cgpa == 8.5


def test_archive_keeps_history_and_restore_is_admin_only(app):
    mk_offer(app, "MTCS-25-003", "Praxis", "F", ctc=7)
    with app.app_context():
        sid = student("MTCS-25-003").id
    off = login(app, "officer")
    assert off.post(f"/students/{sid}/archive", data={"reason": "x"}).status_code == 302
    with app.app_context():
        assert not student("MTCS-25-003").archived                                          # reason too short
    off.post(f"/students/{sid}/archive", data={"reason": "Withdrew from programme"})
    with app.app_context():
        s = student("MTCS-25-003")
        assert s.archived and len(s.offers) == 1                                            # history retained
    assert b"MTCS-25-003" not in off.get("/students").data and b"MTCS-25-003" in off.get("/students?archived=1").data
    assert login(app, "coord_cs").get(f"/students/{sid}").status_code == 404                # hidden from coordinators
    assert off.post(f"/students/{sid}/restore").status_code == 403
    assert login(app, "admin").post(f"/students/{sid}/restore").status_code == 302
    with app.app_context():
        assert not student("MTCS-25-003").archived


def test_export_is_restricted_audited_and_protected(app):
    c = login(app, "officer")
    body = c.get("/students/export").data.decode()
    assert "mobile" not in body.splitlines()[0] and "9876543210" not in body
    assert "9876543210" not in c.get("/students/export?sensitive=1").data.decode()          # officers cannot ask for it
    assert "9876543210" in login(app, "admin").get("/students/export?sensitive=1").data.decode()
    assert login(app, "coord_cs").get("/students/export").status_code == 403
    with app.app_context():
        rows = AuditLog.query.filter_by(action="EXPORT_STUDENTS").all()
        assert len(rows) == 3 and sum('"sensitive":true' in r.new_value for r in rows) == 1


def test_retention_anonymises_old_archived_records_only(app):
    with app.app_context():
        old = student("MTCS-25-001")
        old.batch, old.archived = "2018-20", True
        recent = student("MTCS-25-002")
        recent.archived = True
        db.session.commit()
    c = login(app, "admin")
    assert b"MTCS-25-001" in c.get("/admin/retention").data and b"MTCS-25-002" not in c.get("/admin/retention").data
    c.post("/admin/retention/run")
    with app.app_context():
        o, r = student("MTCS-25-001"), student("MTCS-25-002")
        assert o.anonymised and o.name == "ANONYMISED" and o.mobile is None and "redacted" in o.email
        assert not r.anonymised and r.name == "Diya Shah"
        assert not User.query.filter_by(username="stu_a").first().active                      # linked login disabled
    assert login(app, "officer").post("/admin/retention/run").status_code == 403


def test_user_admin_flow_and_disabled_user_cannot_use_old_session(app):
    c = login(app, "admin")
    r = c.post("/users/new", data={"username": "newcoord", "role": "coordinator", "course": "MSDF", "password": "Temp0rary!Pass"})
    assert r.status_code == 302
    with app.app_context():
        u = User.query.filter_by(username="newcoord").first()
        assert u.must_change_password and u.course == "MSDF" and u.password_hash.startswith("$2")
        uid = u.id
    assert c.post("/users/new", data={"username": "weak", "role": "officer", "password": "weak"}).status_code == 302
    with app.app_context():
        assert User.query.filter_by(username="weak").count() == 0
    victim = login(app, "officer")
    with app.app_context():
        officer_id = User.query.filter_by(username="officer").first().id
    c.post(f"/users/{officer_id}/action", data={"action": "disable"})
    assert victim.get("/students").status_code == 302
    r = app.test_client().post("/login", data={"username": "officer", "password": "Passw0rd!Test"})
    assert r.status_code == 200
    with app.app_context():                                                                 # admins cannot lock themselves out
        admin_id = admin().id
    c.post(f"/users/{admin_id}/action", data={"action": "disable"})
    assert c.get("/users").status_code == 200


def test_backup_restore_roundtrip_and_tamper_detection(app, tmp_path):
    mk_offer(app, "MTCS-25-001", "Praxis", "F", ctc=8)
    db_path = app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")
    path = backup.create_backup(db_path, str(tmp_path / "bk"), KEY)
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    blob = open(path, "rb").read()
    assert b"SQLite format" not in blob and b"Aarav" not in blob                              # encrypted at rest
    ok, msg, tmp = backup.verify_backup(path, KEY)
    os.remove(tmp)
    assert ok and "audit chain intact" in msg
    target = str(tmp_path / "restored.db")
    ok, msg = backup.restore_backup(path, target, KEY)
    assert ok and os.path.exists(target)
    import sqlite3
    assert sqlite3.connect(target).execute("SELECT COUNT(*) FROM offers").fetchone()[0] == 1
    assert not backup.verify_backup(path, "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMTI=")[0]   # wrong key
    corrupt = str(tmp_path / "bad.db.enc")
    open(corrupt, "wb").write(blob[:-20] + b"X" * 20)
    assert not backup.verify_backup(corrupt, KEY)[0]
    # restoring a backup whose audit trail was edited is refused
    con = sqlite3.connect(db_path)
    con.execute("DROP TRIGGER audit_no_update")
    con.execute("UPDATE audit_log SET actor_name='mallory' WHERE id=1")
    con.commit()
    con.close()
    evil = backup.create_backup(db_path, str(tmp_path / "bk2"), KEY)
    ok, msg, tmp = backup.verify_backup(evil, KEY)
    assert not ok and "Audit chain broken" in msg


def test_key_rotation_keeps_data_readable(tmp_path):
    from cryptography.fernet import Fernet
    from app import crypto
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    crypto.init(old)
    token = crypto.encrypt("9876543210")
    crypto.init(f"{new},{old}")                                  # new key first, old key still accepted
    assert crypto.decrypt(token) == "9876543210"
    rotated = crypto.rotate(token)
    crypto.init(new)                                             # old key retired
    assert crypto.decrypt(rotated) == "9876543210"
    crypto.init(KEY)
