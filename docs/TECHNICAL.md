# Technical documentation

## 1. Architecture
```
Browser ──HTTPS (reverse proxy in prod / --https in dev)──► Flask app
   │                                                          ├─ auth.py        login, lockout, TOTP, session gate
   │                                                          ├─ security.py    RBAC decorator, scoped queries, field masking
   │                                                          ├─ students/offers/admin views  (thin: validate → service → render)
   │                                                          ├─ services.py    business rules; calls policy.py; writes audit rows
   │                                                          ├─ policy.py      PURE rule engine (unit-tested without DB)
   │                                                          ├─ audit.py       SHA-256 hash chain, same transaction as the change
   │                                                          └─ crypto.py      Fernet column types (mobile, CTC, stipend, MFA secret)
   └──────────────────────────────────────────────────────────► SQLite (parameterised ORM queries only)
```
Design rules: (1) every control runs on the server, never only in the UI; (2) the policy engine is enforced inside the service
that creates an offer, so calling an endpoint directly cannot skip it; (3) an action and its audit row commit atomically.

## 2. Database schema (SQLite)
| Table | Key columns | Notes |
|---|---|---|
| `students` | `placement_id` **UNIQUE**, name, `mobile` 🔒, email, course, batch, cgpa, backlogs, registration_status, eligibility_status, `placement_status` (derived), archived/archived_at/archive_reason, anonymised, `version`, remarks | 🔒 = encrypted column. `placement_status` is recomputed from offers; no form can set it. `version` = optimistic lock. Never hard-deleted. |
| `offers` | student_id, company_id, drive_id, offer_type (I/F/I+F), `ctc_lpa` 🔒, category, `stipend` 🔒, stipend_period, ppo_status, acceptance, joining_status, offer_date, issued_at, acceptance_deadline, off_campus, noc_status, review_status, policy_decision, policy_reasons (JSON), override_reason | One row per offer event → history is preserved. CTC and stipend are separate columns, so they can never be mixed in a report. |
| `companies` | name UNIQUE, declared category, min_cgpa, max_backlogs, allowed_courses, timeline_hours, active | |
| `drives`, `attendance` | drive date/activity; (drive, student) UNIQUE, status, exception_granted/reason/by | Drives the "next three drives" rule. |
| `users` | username UNIQUE, bcrypt hash, role, course / company_id / student_id scope, failed_attempts, locked_until, rotating `session_token`, `mfa_secret` 🔒, mfa_enabled, mfa_last_counter, must_change_password | |
| `audit_log` | ts, actor_id/name/role, action, entity, entity_id, old_value, new_value, ip, `prev_hash`, `hash` UNIQUE | **Append-only**: SQLite triggers abort UPDATE/DELETE; hash chain exposes edits made outside the app. |

Offer-type × category rules live in `app/policy.py` (see README for the interpretation table). `Offer.review_status`:
`cleared` (ALLOW) · `pending_review` (REVIEW) · `overridden` (admin, with reason) · `rejected`.

## 3. Role-based access control
| Permission | Admin | Officer | Coordinator | Recruiter | Student |
|---|:-:|:-:|:-:|:-:|:-:|
| View students | all | all | own course | - | **self** |
| Create / edit / archive / import / export students | ✔ | ✔ | - | - | - |
| Restore archived, retention, users, audit viewer | ✔ | - | - | - | - |
| View offers | all | all | own course | **own company** | **own** |
| Record / update offers, attendance, drives, companies | ✔ | ✔ | - | - | - |
| Review queue, override BLOCK/REVIEW, attendance exceptions | ✔ | - | - | - | - |
| Dashboard / company report | ✔ | ✔ | own course | - | - |
| Mobile number | ✔ | ✔ | masked | - | own |
| Email | ✔ | ✔ | ✔ | - | own |
| CTC / stipend | ✔ | ✔ | ✔ | own company | own |
| Export with contact & CTC | ✔ | - | - | - | - |

Two layers: `@require(permission)` on every route (403 + audit row) and **object scoping** in `security.py` - every student/offer query
passes through `scoped_students()` / `scoped_offers()`, so an out-of-scope ID returns the *same* 404 as a missing one (no enumeration)
and the attempt is audited. Field masking is decided server-side by `can_see()`.

## 4. Security controls vs. the problem statement
| Requirement | Implementation | Verified by |
|---|---|---|
| Authentication | bcrypt (cost 12, SHA-256 pre-hash so long passwords are not truncated), 10+ char complexity policy, uniform failure message, dummy-hash timing equalisation, lockout after 5 failures / 15 min, 10 attempts/min/IP limit, optional TOTP MFA (RFC 6238, replay-protected) | `test_wrong_password…`, `test_lockout…`, `test_login_rate_limit`, `test_totp_rfc6238…` |
| RBAC | §3 | `test_idor_*`, `test_coordinator_is_limited…`, `test_recruiter_sees_only_own…`, `test_contact_and_salary_masking…` |
| Confidentiality | TLS (`--https` or reverse proxy; HSTS + Secure cookies when `PLACEMENT_HTTPS=1`); Fernet field encryption for mobile, CTC, stipend, MFA secret with key rotation; encrypted backups; `secure_delete`; `Cache-Control: no-store` | `test_sensitive_fields_are_encrypted…`, `test_key_rotation…`, `test_backup_restore…` |
| Input & query security | server-side validation of every field (`validators.py`); SQLAlchemy bound parameters only; LIKE wildcards escaped; Jinja autoescape, no `|safe`, strict CSP without `unsafe-inline`; CSRF token on every POST incl. logout | `test_sql_injection_*`, `test_stored_xss…`, `test_csp_and_security_headers`, `test_csrf_blocks…` |
| Audit logging | actor, UTC time, action, entity, IP, before/after (mobile masked); logins, denials, blocked offers, overrides, exports, imports, user changes, backups | `test_audit_log_records…`, `test_denied_actions…` |
| Integrity | UNIQUE Placement ID (+ pre-check), validators, optimistic locking, hash-chained audit, DB triggers refusing audit edits, derived (non-editable) placement status | `test_duplicate_placement_id…`, `test_audit_chain_detects…`, `test_optimistic_locking…`, `test_mass_assignment…` |
| Session security | HttpOnly + SameSite=Lax (+Secure in prod) cookies; 15 min idle, 8 h absolute timeout; session cleared and token rotated at login; logout and password change **invalidate copied cookies server-side** | `test_session_cookie_replay…`, `test_password_change_signs_out…`, `test_idle_and_absolute…` |
| Backup & recovery | `flask backup` (SQLite online backup → Fernet, mode 0600); `flask restore` decrypts, runs `PRAGMA integrity_check`, **re-verifies the audit chain**, keeps `.pre-restore`; `--verify-only` for drills | `test_backup_restore_roundtrip_and_tamper_detection` |
| Export security | permission-gated, row-capped (5000), CSV formula injection neutralised, contact/CTC only for admin on explicit request, every export audited | `test_export_is_restricted…`, `test_csv_formula_injection…` |
| Privacy & retention | only necessary fields; archive (not delete); anonymisation 5 years after graduation, linked login disabled, aggregates unaffected | `test_retention_anonymises…` |
| **Security challenge** (student cannot change own status/package, bypass switching, or read others) | Students have read-only permissions; status is derived; policy runs in the service; scoped queries | `test_student_cannot_change_own_status…`, `test_policy_cannot_be_bypassed…`, `test_idor_*` |

## 5. Threat model - attacks considered
| Attack | Where | Defence | Test |
|---|---|---|---|
| SQL injection | search, filters, login | ORM bound params; wildcard escaping | `test_sql_injection_*` |
| Stored / reflected XSS | name, remarks, company | strict validation, autoescape, CSP | `test_stored_xss…` |
| CSRF | every state change | Flask-WTF tokens, SameSite=Lax | `test_csrf_blocks…` |
| IDOR / forced browsing | `/students/<id>`, `/offers/<id>` | scoped queries, uniform 404, audit | `test_idor_*` |
| Privilege escalation | role-restricted routes | `@require`, 403 + audit | `test_student_cannot…` |
| Mass assignment | edit forms | explicit field whitelist; derived fields never bound | `test_mass_assignment_is_ignored` |
| Policy bypass | direct POST to `/offers/new` | engine inside `create_offer` | `test_policy_cannot_be_bypassed…` |
| Credential stuffing / brute force | `/login` | lockout, rate limit, MFA | `test_lockout…`, `test_login_rate_limit` |
| Session hijack / fixation / replay | cookies | flags, rotation, server-side invalidation, timeouts | `test_session_*` |
| Open redirect | `next=` | relative-path allow-list | `test_open_redirect_is_refused` |
| CSV injection / malicious upload | import & export | extension + size + UTF-8 check, per-row validation, all-or-nothing, cell prefixing | `test_csv_*` |
| Audit tampering | DB file | append-only triggers + hash chain | `test_audit_chain_detects…` |
| Log injection | login username | control characters stripped | `test_log_injection…` |
| Data theft from disk / backup | file system | field encryption, encrypted backups, 0600 key files | `test_sensitive_fields…` |
| Insider misuse (mass export) | export | permission, row cap, audit | `test_export_is_restricted…` |
| Concurrent edit / lost update | student edit | optimistic locking → 409 | `test_optimistic_locking…` |
| Clickjacking, MIME sniffing, caching of PII | all pages | X-Frame-Options, CSP `frame-ancestors`, nosniff, no-store | `test_csp_and_security_headers` |

**Zero-day attacks.** An unknown flaw in Flask, Werkzeug, SQLite or a dependency cannot be blocked by name, so the design *limits damage and
speeds detection*: least-privilege roles and scoped queries (a bug rarely exposes everything), defence in depth (validation → ORM → field encryption →
RBAC), tiny attack surface (no debug routes, few dependencies), `pip-audit` clean at build time (`docs/pip-audit.txt`; re-run in CI), tamper-evident audit
plus `audit-verify` for detection, encrypted verified backups for recovery. Production additions: non-root service user, WAF/reverse-proxy rate limits, alerting on
`LOGIN_FAILED` / `EXPORT_*` / `ACCESS_DENIED` bursts, and a written incident-response plan (rotate `SECRET_KEY` + `FIELD_KEYS`, restore from backup).

## 6. Testing
`python3 -m pytest -q` → **110 tests**: `test_policy.py` (pure rule engine: boundaries, every category/type pair, strictest-wins, absence window, deadlines,
and a consistency check that `next_options` never advertises something the evaluator would BLOCK), `test_security.py` (attack scenarios above),
`test_features.py` (offers, expiry, review queue, reports, attendance, retention, backup, key rotation).
The suite was mutation-checked: deliberately breaking scope checks, policy enforcement, CSRF, encryption, role permissions and the 1.5× rule each makes tests fail.

## 7. Reporting rules honoured
Unique placed students are counted once (`COUNT` of students with an accepted offer) and shown next to *total offers received*; internship stipend (monthly) and
annual FTE CTC are separate columns and separate statistics; highest/average/median FTE use one figure per placed student (their best accepted FTE).

## 8. Deployment checklist (production)
Terminate TLS at a reverse proxy and set `PLACEMENT_HTTPS=1` · run behind gunicorn with **one worker** (audit chain) or move to PostgreSQL with an advisory lock ·
supply `SECRET_KEY` and `FIELD_KEYS` from a secret manager, not `instance/` · put backups on separate storage from their key · change/delete demo accounts ·
add `ProxyFix` so rate limits see real client IPs · run `pip-audit` and `flask audit-verify` on a schedule and store the audit head hash off-system.

## 9. Limitations
- **Interpretation risk:** policy rules follow the problem statement; the guidelines document was not available. The FTE→FTE reading (§README) is configurable.
- **SQLite:** single writer; the audit chain serialises with a process lock (`threaded=False`). Deleting only the *newest* audit rows is undetectable without an off-system head-hash copy.
- **Encryption scope:** mobile, CTC, stipend and MFA secrets are encrypted per field; names, e-mails, CGPA and IDs are not (they are searchable). Whole-file encryption would need SQLCipher / disk encryption.
- **Keys** default to files in `instance/` (mode 0600). Backups use the same key - store it separately.
- **Rate limiter and lockout counters** are per-process / per-IP; behind a proxy without `ProxyFix` the IP is the proxy's.
- **MFA** is optional TOTP shown as a key/URI (no QR image); no recovery codes - an admin resets by disabling/re-enrolling.
- **Roles:** recruiters are read-only (they cannot self-submit selections); students cannot edit anything, including their own contact details.
- **Not built:** e-mail/SMS deadline reminders, PPO auto-conversion workflow, per-company approval of exports, CAPTCHA, PDF reports.
- Stats are computed in Python over scoped rows - fine for thousands of students, not millions.
