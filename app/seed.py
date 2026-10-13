"""Demo data: fake students across all five programmes plus offers that exercise every policy path.
Offers are created through services.create_offer, so the policy engine and audit log are really used."""
import secrets
from datetime import date, timedelta

from . import audit
from .auth import hash_password
from .models import Attendance, Company, Drive, Offer, Student, User, db, utcnow
from .services import create_offer, expire_overdue, mark_attendance, recompute_placement

DEMO_PASSWORDS = {
    "admin": "Admin@Placement1",
    "officer": "Officer@Placement1",
    "coord.mtcs": "Coord@Placement1",
    "coord.mscs": "Coord@Placement1",
    "recruiter.zenith": "Recruit@Placement1",
    "student1": "Student@Placement1",
    "student2": "Student@Placement1",
}

COMPANIES = [  # name, category, min_cgpa, max_backlogs, allowed courses, timeline_hours
    ("Zenith Cyber", "A+", 7.0, 0, "", None),
    ("Orbit Systems", "A", 6.5, 1, "", None),
    ("Aegis InfoSec", "A+", 7.5, 0, "MSDF,MTCS,BTMT,MTAI", 12),
    ("Vertex Secure", "A", 6.0, 2, "", None),
    ("Praxis Analytics", "B", 6.0, 2, "", None),
    ("Kiwi Data", "B", 5.5, 3, "", None),
    ("Nimbus Labs", "C", 5.0, 5, "", None),
    ("TechNova (off-campus)", "B", 0.0, 50, "", None),
]

NAMES = ["Aarav Patel", "Diya Shah", "Rohan Mehta", "Ishita Joshi", "Kabir Singh", "Meera Nair", "Aditya Rao",
         "Sneha Iyer", "Vivaan Desai", "Ananya Gupta", "Arjun Verma", "Kiara Bhatt", "Dev Trivedi", "Riya Chauhan",
         "Yash Parmar", "Pooja Solanki", "Harsh Vyas", "Tanvi Pandya", "Nikhil Thakkar", "Aisha Khan",
         "Manav Kapoor", "Zoya Ansari", "Krish Modi", "Naina Sharma", "Om Raval"]

# course -> (batch, [placement-id numbers])
PLAN = {"MTCS": "2025-27", "MTAI": "2025-27", "BTMT": "2022-27", "MSCS": "2025-27", "MSDF": "2025-27"}


def _form(**kw):
    return {k: str(v) for k, v in kw.items()}


def seed_demo():
    if User.query.filter_by(username="admin").first():
        raise SystemExit("Demo data already present (admin exists). Delete instance/placement.db to reseed.")
    system = (None, "seed", "system")
    admin = User(username="admin", role="admin", password_hash=hash_password(DEMO_PASSWORDS["admin"]),
                 session_token=secrets.token_hex(16))
    db.session.add(admin)
    db.session.flush()

    comps = {}
    for name, cat, cg, bl, courses, tl in COMPANIES:
        c = Company(name=name, category=cat, min_cgpa=cg, max_backlogs=bl, allowed_courses=courses, timeline_hours=tl)
        db.session.add(c)
        comps[name.split()[0]] = c
    db.session.flush()

    students, i = {}, 0
    for code, batch in PLAN.items():
        for n in range(1, 6):
            pid = f"{code}-{batch[2:4]}-{n:03d}"
            s = Student(placement_id=pid, name=NAMES[i], mobile=f"9{8000000 + i * 1117:09d}"[:10],
                        email=f"{NAMES[i].split()[0].lower()}.{pid.lower()}@students.nfsu.example",
                        course=code, batch=batch, cgpa=round(7.2 + (i % 8) * 0.3, 1), backlogs=0,
                        registration_status="registered", eligibility_status="eligible")
            db.session.add(s)
            students[pid] = s
            i += 1
    db.session.flush()
    s = lambda code, n: students[f"{code}-{PLAN[code][2:4]}-{n:03d}"]  # noqa: E731

    # special cases
    s("MSCS", 2).eligibility_status = "pending_verification"
    s("MSDF", 5).registration_status = "deregistered"
    s("BTMT", 5).eligibility_status = "ineligible"
    s("MSDF", 4).cgpa = 6.1  # below most company cut-offs
    s("MSCS", 4).backlogs = 2
    for username, stu in (("student1", s("MTCS", 1)), ("student2", s("MTCS", 2))):
        db.session.add(User(username=username, role="student", student_id=stu.id,
                            password_hash=hash_password(DEMO_PASSWORDS[username]), session_token=secrets.token_hex(16)))
    db.session.add(User(username="officer", role="officer", password_hash=hash_password(DEMO_PASSWORDS["officer"]),
                        session_token=secrets.token_hex(16)))
    for username, course in (("coord.mtcs", "MTCS"), ("coord.mscs", "MSCS")):
        db.session.add(User(username=username, role="coordinator", course=course,
                            password_hash=hash_password(DEMO_PASSWORDS[username]), session_token=secrets.token_hex(16)))
    db.session.add(User(username="recruiter.zenith", role="recruiter", company_id=comps["Zenith"].id,
                        password_hash=hash_password(DEMO_PASSWORDS["recruiter.zenith"]), session_token=secrets.token_hex(16)))
    audit.log("SEED", "system", None, new={"students": len(students), "companies": len(comps)}, actor=system)
    db.session.commit()

    def offer(stu, company, otype, ctc=None, stipend=None, accept=True, **extra):
        form = _form(placement_id=stu.placement_id, company_id=comps[company].id, offer_type=otype,
                     ctc_lpa=ctc if ctc is not None else "", stipend=stipend if stipend is not None else "", **extra)
        res = create_offer(admin, form, issued_at=extra.pop("issued_at", None))
        if res.offer and accept and res.offer.review_status == "cleared":
            res.offer.acceptance = "accepted"
            audit.log("OFFER_UPDATE", "offer", res.offer.id, old={"acceptance": "pending"}, new={"acceptance": "accepted"},
                      actor=system)
            recompute_placement(stu)
            db.session.commit()
        return res

    # --- offers that exercise every rule ---
    offer(s("MTCS", 1), "Praxis", "F", ctc=7.5)                       # B
    offer(s("MTCS", 1), "Zenith", "F", ctc=18)                        # B -> A+ needs >= 11.25: ALLOWED, then out of process
    offer(s("MTCS", 2), "Nimbus", "I", stipend=25000)                 # internship only
    offer(s("MTCS", 2), "Orbit", "F", ctc=12)                         # I then F: ALLOWED  => internship + FTE
    offer(s("MTCS", 3), "Nimbus", "F", ctc=4.5)                       # C
    offer(s("MTCS", 3), "Kiwi", "F", ctc=5.0)                         # C -> C: BLOCKED (logged, not stored)
    offer(s("MTAI", 1), "Aegis", "I+F", ctc=20, stipend=40000)        # I+F A+: out of process
    offer(s("MTAI", 1), "Nimbus", "I", stipend=20000)                 # BLOCKED
    r = offer(s("MTAI", 2), "Vertex", "F", ctc=11, accept=False)      # A offer left unaccepted ...
    if r.offer:
        r.offer.issued_at = utcnow() - timedelta(days=3)              # ... 3 days ago: will expire
        r.offer.acceptance_deadline = utcnow() - timedelta(days=2)
        db.session.commit()
    offer(s("MTAI", 3), "Kiwi", "F", ctc=8)                           # B
    offer(s("MTAI", 3), "Praxis", "F", ctc=9)                         # B: 9 < 1.5 x 8 = 12 -> BLOCKED
    offer(s("MTAI", 3), "Zenith", "F", ctc=17, accept=False)          # B -> A+: ALLOWED, left pending
    offer(s("BTMT", 1), "Praxis", "I", stipend=30000)                 # internship
    offer(s("BTMT", 1), "Nimbus", "I", stipend=15000)                 # I after I: BLOCKED
    offer(s("BTMT", 2), "Orbit", "F", ctc=14)                         # A
    offer(s("BTMT", 2), "Praxis", "F", ctc=7)                         # A -> B: BLOCKED
    offer(s("BTMT", 3), "Vertex", "F", ctc=10, accept=False)          # exactly 10 LPA = category A, pending
    offer(s("MSCS", 1), "Nimbus", "I", stipend=20000)
    offer(s("MSCS", 2), "Kiwi", "F", ctc=6.0)                         # eligibility pending -> REVIEW queue
    offer(s("MSDF", 1), "Zenith", "F", ctc=16.0)                      # exactly 16 LPA = A+
    r = offer(s("MSDF", 3), "TechNova", "F", ctc=9.0, off_campus="on", noc_status="pending")  # off-campus, NOC pending

    # --- drives & attendance: unexcused absence -> excluded from the next three drives ---
    d0 = date.today() - timedelta(days=40)
    drives = []
    for k, (co, act) in enumerate([("Praxis", "Pre-placement talk"), ("Orbit", "Test"), ("Kiwi", "Interview"),
                                   ("Nimbus", "Pre-placement talk"), ("Vertex", "Test")]):
        d = Drive(company=comps[co], title=f"{co} {act}", activity=act, drive_date=d0 + timedelta(days=8 * k))
        db.session.add(d)
        drives.append(d)
    db.session.flush()
    mark_attendance(admin, drives[0], s("MSDF", 2), "absent")
    mark_attendance(admin, drives[1], s("MSDF", 2), "present")
    mark_attendance(admin, drives[0], s("MSCS", 3), "absent")
    att = Attendance.query.filter_by(drive_id=drives[0].id, student_id=s("MSCS", 3).id).first()
    att.exception_granted, att.exception_reason, att.exception_by = True, "Hospitalised; discharge summary verified", admin.id
    audit.log("ATTENDANCE_EXCEPTION", "attendance", att.id, new={"reason": att.exception_reason}, actor=system)
    db.session.commit()
    # an offer for the excluded student at a later drive -> referred to manual review
    create_offer(admin, _form(placement_id=s("MSDF", 2).placement_id, company_id=comps["Kiwi"].id, offer_type="F",
                              ctc_lpa="7", drive_id=drives[2].id))
    expire_overdue()
