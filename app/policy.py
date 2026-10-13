"""Pure, database-free placement policy engine (NFSU Student Placement Guidelines 2026-27).

Nothing in this module touches Flask or the database, so every rule can be unit-tested
directly. Outcomes are ALLOW < REVIEW < BLOCK and the stricter outcome always wins.
Every decision carries human-readable reasons so staff can see *why*.

Interpretation notes (documented in the README, change them here in one place):
  * Category from CTC: A+ >= 16, A >= 10 and < 16, B >= 6 and < 10, C < 6 (LPA, lower bound inclusive).
  * Only offers with a CTC (F, I+F) have a category; internship-only offers have none.
  * Active offers = pending or accepted. Declined / expired / rejected offers release the student.
  * I+F (or an internship whose PPO was accepted) closes the student out of every further drive.
  * An A+ FTE closes the student out of every further drive.
  * An FTE holder may always take an internship role (policy: "may apply for an internship role").
  * FTE -> FTE/I+F is governed by the switching table (SWITCH_BY_CATEGORY=True, the default).
    With the flag off, the plain offer-type rule applies instead (F after F is blocked).
  * When the policy cannot decide (missing CTC, unverified eligibility, absenteeism) -> REVIEW.
"""
from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal
from typing import Optional, Sequence

ALLOW, REVIEW, BLOCK = "ALLOW", "REVIEW", "BLOCK"
_RANK = {ALLOW: 0, REVIEW: 1, BLOCK: 2}
CAT_RANK = {"C": 0, "B": 1, "A": 2, "A+": 3}
A_PLUS_MIN, A_MIN, B_MIN = Decimal("16"), Decimal("10"), Decimal("6")
B_FACTOR = Decimal("1.5")
ABSENCE_WINDOW = 3  # absent -> excluded from the next three drives
MAX_ACCEPT_HOURS = 24


def D(x):
    return None if x is None else Decimal(str(x))


def category_for(ctc) -> Optional[str]:
    c = D(ctc)
    if c is None:
        return None
    if c >= A_PLUS_MIN:
        return "A+"
    if c >= A_MIN:
        return "A"
    if c >= B_MIN:
        return "B"
    return "C"


def has_fte(offer_type: str) -> bool:
    return offer_type in ("F", "I+F")


@dataclass(frozen=True)
class Held:
    """An offer the student already holds (pending or accepted)."""
    offer_type: str
    ctc: Optional[float] = None
    ppo_accepted: bool = False
    ref: str = ""


@dataclass(frozen=True)
class Proposed:
    offer_type: str
    ctc: Optional[float] = None
    category: Optional[str] = None  # company's declared category, used when CTC is not known yet


@dataclass(frozen=True)
class StudentFacts:
    registration: str = "registered"
    eligibility: str = "eligible"
    archived: bool = False
    cgpa: float = 10.0
    backlogs: int = 0
    course: str = ""


@dataclass(frozen=True)
class CompanyFacts:
    name: str = ""
    min_cgpa: float = 0.0
    max_backlogs: int = 99
    allowed_courses: tuple = ()


@dataclass
class Decision:
    decision: str = ALLOW
    reasons: list = field(default_factory=list)

    def add(self, level: str, msg: str):
        if _RANK[level] > _RANK[self.decision]:
            self.decision = level
        self.reasons.append(f"[{level}] {msg}")

    def merge(self, other: "Decision"):
        if _RANK[other.decision] > _RANK[self.decision]:
            self.decision = other.decision
        self.reasons.extend(other.reasons)


def effective_type(h: Held) -> str:
    return "I+F" if (h.offer_type == "I" and h.ppo_accepted) else h.offer_type


def check_switching(held: Sequence[Held], proposed: Proposed, switch_by_category: bool = True) -> Decision:
    d = Decision()
    for h in held:
        ht = effective_type(h)
        ref = h.ref or "existing offer"
        if ht == "I+F":
            d.add(BLOCK, f"{ref}: I+F selection - the student cannot participate in other I, F or I+F roles.")
            continue
        hcat = category_for(h.ctc) if ht == "F" else None
        if hcat == "A+":
            d.add(BLOCK, f"{ref}: A+ offer ({h.ctc} LPA) - no switching; the student is out of the placement process.")
            continue
        if ht == "I":
            if proposed.offer_type == "I":
                d.add(BLOCK, f"{ref}: after an internship-only selection the student cannot apply for another internship-only role.")
            else:
                d.add(ALLOW, f"{ref}: internship-only holders may apply for FTE or I+F roles.")
            continue

        # existing offer is FTE-only (F)
        if proposed.offer_type == "I":
            d.add(ALLOW, f"{ref}: FTE holders may apply for an internship role.")
            continue
        if not switch_by_category:
            if proposed.offer_type == "F":
                d.add(BLOCK, f"{ref}: after an FTE-only selection the student cannot apply for another FTE-only role.")
            else:
                d.add(REVIEW, f"{ref}: I+F carries an FTE component; policy only names internship roles after FTE - manual review.")
            continue
        if hcat is None:
            d.add(REVIEW, f"{ref}: existing FTE offer has no CTC recorded, so the switching rule cannot be applied.")
            continue

        ncat = category_for(proposed.ctc) or proposed.category
        if hcat == "A":
            if ncat == "A+":
                d.add(ALLOW, f"{ref}: category A may switch to A+ (new offer is A+).")
            elif ncat is None:
                d.add(REVIEW, f"{ref}: category A may switch only to A+, but the new offer's category is unknown.")
            else:
                d.add(BLOCK, f"{ref}: category A ({h.ctc} LPA) may switch only to A+; the new offer is category {ncat}.")
        elif hcat == "B":
            need = B_FACTOR * D(h.ctc)
            if proposed.ctc is not None:
                if D(proposed.ctc) >= need:
                    d.add(ALLOW, f"{ref}: category B - new CTC {proposed.ctc} LPA is at least 1.5x the existing {h.ctc} LPA (needs >= {need}).")
                else:
                    d.add(BLOCK, f"{ref}: category B - new CTC {proposed.ctc} LPA is below 1.5x the existing {h.ctc} LPA (needs >= {need}).")
            elif ncat == "A+":
                d.add(ALLOW, f"{ref}: category B - an A+ package (>= 16 LPA) always exceeds 1.5x the existing package.")
            elif ncat == "C":
                d.add(BLOCK, f"{ref}: category B - a category C package cannot reach 1.5x the existing package.")
            else:
                d.add(REVIEW, f"{ref}: category B needs the exact new CTC to test the 1.5x rule (needs >= {need}).")
        else:  # C
            if ncat is None:
                d.add(REVIEW, f"{ref}: category C may move only to a higher category, but the new category is unknown.")
            elif CAT_RANK[ncat] > CAT_RANK["C"]:
                d.add(ALLOW, f"{ref}: category C may move to a higher category (new offer is {ncat}).")
            else:
                d.add(BLOCK, f"{ref}: category C may move only to a higher category; the new offer is also C.")
    return d


def absence_exclusion(unexcused_absences: Sequence, drive_dates: Sequence, target, window: int = ABSENCE_WINDOW):
    """Return the date of the absence that excludes the student from `target`, else None.

    A student absent (without an approved exception) from a drive is excluded from the next
    `window` drives, counted by drive date; the target drive counts as one of them."""
    for a in sorted(unexcused_absences):
        if a >= target:
            continue
        between = sum(1 for d in drive_dates if a < d <= target)
        if between <= window:
            return a
    return None


def acceptance_deadline(issued_at, company_hours: Optional[int]):
    """24 hours or the company's stated timeline, whichever is earlier."""
    hours = min(MAX_ACCEPT_HOURS, company_hours) if company_hours else MAX_ACCEPT_HOURS
    return issued_at + timedelta(hours=hours)


def evaluate(student: StudentFacts, company: CompanyFacts, proposed: Proposed, held: Sequence[Held],
             absent_since=None, switch_by_category: bool = True) -> Decision:
    d = Decision()
    if student.archived:
        d.add(BLOCK, "Student record is archived.")
    if student.registration != "registered":
        d.add(BLOCK, f"Placement registration status is '{student.registration}'.")
    if student.eligibility == "ineligible":
        d.add(BLOCK, "Student is marked ineligible.")
    elif student.eligibility == "pending_verification":
        d.add(REVIEW, "Eligibility is still pending verification.")
    if company.allowed_courses and student.course not in company.allowed_courses:
        d.add(BLOCK, f"{company.name or 'Company'} does not recruit from course {student.course}.")
    if student.cgpa < company.min_cgpa:
        d.add(BLOCK, f"CGPA {student.cgpa} is below the company minimum {company.min_cgpa}.")
    if student.backlogs > company.max_backlogs:
        d.add(BLOCK, f"{student.backlogs} backlog(s) exceeds the company limit of {company.max_backlogs}.")
    if absent_since is not None:
        d.add(REVIEW, f"Unexcused absence on {absent_since}: excluded from the next {ABSENCE_WINDOW} drives unless an exception is approved.")

    if held:
        d.merge(check_switching(held, proposed, switch_by_category))
    else:
        d.add(ALLOW, "No active offers - no switching restrictions apply.")
    if d.decision == ALLOW:
        d.reasons.append("[ALLOW] All policy checks passed.")
    return d


def next_options(held: Sequence[Held], switch_by_category: bool = True) -> dict:
    """What the student may still attempt (used for 'eligible for subsequent drives')."""
    types = ["I", "F", "I+F"]
    min_ctc = None
    notes = []

    def closed(msg):
        return {"status": "closed", "types": [], "min_ctc": None, "notes": [msg]}

    for h in held:
        ht = effective_type(h)
        ref = h.ref or "existing offer"
        if ht == "I+F":
            return closed(f"{ref}: I+F selection - out of further drives.")
        if ht == "I":
            if "I" in types:
                types.remove("I")
            notes.append(f"{ref}: no further internship-only roles.")
            continue
        cat = category_for(h.ctc)
        if cat == "A+":
            return closed(f"{ref}: A+ offer - out of the placement process.")
        if not switch_by_category:
            types = [t for t in types if t == "I"]
            notes.append(f"{ref}: only internship roles allowed after FTE.")
            continue
        if cat is None:
            notes.append(f"{ref}: CTC missing - FTE switching needs manual review.")
            continue
        need = {"A": A_PLUS_MIN, "B": B_FACTOR * D(h.ctc), "C": B_MIN}[cat]
        min_ctc = need if min_ctc is None else max(min_ctc, need)
        notes.append(f"{ref}: category {cat} - next FTE/I+F must pay >= {need} LPA.")
    if not types:
        return closed("No role types remain open.")
    status = "open" if not held else "restricted"
    return {"status": status, "types": types, "min_ctc": float(min_ctc) if min_ctc is not None else None,
            "notes": notes or ["No active offers - open to all categories and offer types."]}
