# Secure, Policy-Driven Student Placement Management System
NFSU Placement Cell - session 2026-27 · Flask + SQLite prototype

Maintains course-wise placement records for the five programmes (M.Tech CS, M.Tech AIDS, B.Tech-M.Tech CS, M.Sc CS, M.Sc DFIS),
enforces the offer-category / offer-type / switching policy on the server, explains every decision, and protects personal and
salary data with role-based access, field-level encryption and a tamper-evident audit trail.

## Run it (2 minutes)
```bash
pip install -r requirements.txt
python3 -m flask --app run seed        # demo data: 25 students, 8 companies, 17 offers, 5 blocked attempts, drives
python3 run.py                         # http://127.0.0.1:5000        (python3 run.py --https for TLS with a self-signed cert)
python3 -m pytest -q                   # 110 tests, ~10 s
```
Starting without demo data: `python3 -m flask --app run create-admin --username <you>` and add everything through the UI.

### Demo logins (demo data only - change or delete before real use)
| Username | Password | Role | Sees |
|---|---|---|---|
| `admin` | `Admin@Placement1` | Placement Administrator | everything, overrides, users, audit, retention |
| `officer` | `Officer@Placement1` | Placement Officer | students, offers, companies, drives, reports (no user mgmt / overrides) |
| `coord.mtcs` / `coord.mscs` | `Coord@Placement1` | Course Coordinator | read-only, **own course only**, mobile masked |
| `recruiter.zenith` | `Recruit@Placement1` | Company / Recruiter | read-only, **own company's offers only**, no contact data |
| `student1` / `student2` | `Student@Placement1` | Student | own record only, read-only |

**Logo:** save the official NFSU logo as `app/static/img/nfsu-logo.png` (or .svg/.jpg/.webp) and refresh - it replaces the placeholder badge in the header.

## What to demo (3 minutes)
1. **Policy engine** - *Policy check*: pick a student who holds a B-category FTE (see Offers) → Praxis 9 LPA is **BLOCK** (needs ≥ 12 = 1.5×); Zenith 17 LPA is **ALLOW**. `MTAI-25-001` (I+F A+) is blocked from everything. Every answer lists the reasons.
2. **Referral** - *Reviews*: `MSCS-25-002` (eligibility pending) and `MSDF-25-002` (unexcused absence, next-3-drives rule) are referred, not decided. Admin approves/rejects with a note.
3. **Dashboard** - unique placed students vs total offers; CTC and stipend shown separately; course- and batch-wise tables.
4. **Compliance** - pending acceptance, joining pending, conflicts, absentee flags, and what each student may still attempt.
5. **Security** - log in as `student1`, change `/students/<id>` in the URL → 404 (and an `ACCESS_DENIED` audit row). Audit page shows the hash-chain status.

## Policy as implemented (assumptions - all in `app/policy.py`)
The attached *Student Placement Guidelines 2026-27* were not available, so the rules follow the problem statement. Decisions where it is silent:

| Topic | Decision |
|---|---|
| Category | From the offer's CTC: A+ ≥ 16, A ≥ 10 and < 16, B ≥ 6 and < 10, C < 6 LPA (lower bound inclusive). Internship-only offers have no category. |
| Active offer | Pending or accepted. Declined, expired and review-rejected offers release the student. |
| I+F / accepted PPO | Closes the student out of all further drives. An internship whose PPO is accepted is treated as I+F. |
| A+ | Out of the process entirely (no switching). |
| FTE → FTE or I+F | **The switching table decides** (A → A+ only; B → ≥ 1.5×; C → higher category). Config flag `SWITCH_BY_CATEGORY=False` instead applies the plain "FTE-only cannot take another FTE-only" rule. **Please confirm this reading against the guidelines.** |
| FTE → internship | Always allowed ("may apply for an internship role") unless A+. |
| I → F or I+F | Allowed; I → I blocked. |
| Cannot decide | **REVIEW**: missing CTC, eligibility pending verification, unexcused absence. Strictest outcome wins: BLOCK > REVIEW > ALLOW. |
| Acceptance deadline | issue time + min(24 h, company's stated window); offers auto-expire. |
| Absenteeism | Unexcused absence excludes the student from the next 3 drives *by date* (the target drive counts as one); only an admin can grant an emergency exception, with a reason. |
| Off-campus offers | Recorded with NOC status; they count for switching exactly like on-campus offers. |
| Eligibility | Fields on the student (CGPA, backlogs, registration, eligibility) and per-company criteria (min CGPA, max backlogs, courses). |
| Batch | `YYYY-YY`, validated against programme length (2 years; 5 for B.Tech-M.Tech). |
| Retention | Archived records are anonymised 5 years after the graduation year (`RETENTION_YEARS`). |
| Admin override | Admin may record a BLOCKED/REVIEW offer with a ≥ 10-char reason; stored as `overridden` and audited. Final decisions stay with the Placement Cell. |

## Layout
```
app/policy.py      pure rule engine (no DB / Flask)       app/audit.py     hash-chained audit log
app/services.py    offers, expiry, attendance, stats       app/security.py  RBAC, scoping, masking, rate limit
app/auth.py        login, lockout, MFA, sessions           app/crypto.py    field encryption (Fernet)
app/students.py    CRUD, archive, import/export            app/backup.py    encrypted backup + verified restore
app/offers.py      offers, reviews, policy check           app/admin.py     dashboard, reports, users, audit, retention
app/models.py      schema                                  app/validators.py server-side validation
tests/             110 tests (policy, attacks, features)   docs/TECHNICAL.md schema, controls, threat model, limits
```
Operations: `flask --app run backup | restore <file> [--verify-only] | audit-verify | rotate-keys | create-admin`.
Full documentation: **docs/TECHNICAL.md** · dependency scan: **docs/pip-audit.txt**.

## Known limitations (details in docs/TECHNICAL.md §9)
SQLite single-writer (audit chain assumes one process) · field-level, not whole-file, encryption · key files live in `instance/` by default (use a secret manager) · in-memory login rate limiter (per process) · TLS is terminated by a proxy in production · recruiters are read-only · no e-mail/SMS reminders · zero-days cannot be prevented, only contained and detected.
