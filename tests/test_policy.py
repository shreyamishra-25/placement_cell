"""Unit tests for the pure policy engine - no Flask, no database."""
from datetime import date, datetime, timedelta

import pytest

from app import policy as p
from app.policy import ALLOW, BLOCK, REVIEW, CompanyFacts, Held, Proposed, StudentFacts

OK_STUDENT = StudentFacts()
ANY_CO = CompanyFacts("Acme")


def sw(held, new, **kw):
    return p.check_switching(held, new, **kw).decision


@pytest.mark.parametrize("ctc,cat", [(0.5, "C"), (5.99, "C"), (6, "B"), (9.99, "B"), (10, "A"), (15.99, "A"),
                                      (16, "A+"), (40, "A+"), (None, None)])
def test_category_boundaries(ctc, cat):
    assert p.category_for(ctc) == cat


def test_no_active_offers_is_allowed():
    d = p.evaluate(OK_STUDENT, ANY_CO, Proposed("F", 12), [])
    assert d.decision == ALLOW and d.reasons


def test_a_plus_closes_the_student_out():
    held = [Held("F", 16)]
    for t, ctc in (("I", None), ("F", 30), ("I+F", 30)):
        assert sw(held, Proposed(t, ctc)) == BLOCK


def test_category_a_may_switch_only_to_a_plus():
    held = [Held("F", 12)]
    assert sw(held, Proposed("F", 16)) == ALLOW
    assert sw(held, Proposed("F", 15.99)) == BLOCK
    assert sw(held, Proposed("F", 7)) == BLOCK
    assert sw(held, Proposed("F", None, "A+")) == ALLOW
    assert sw(held, Proposed("F", None, None)) == REVIEW


def test_category_b_needs_one_and_a_half_times():
    held = [Held("F", 6)]
    assert sw(held, Proposed("F", 9)) == ALLOW          # exactly 1.5x
    assert sw(held, Proposed("F", 8.99)) == BLOCK
    held = [Held("F", 7.3)]                              # decimal arithmetic, not float drift
    assert sw(held, Proposed("F", 10.95)) == ALLOW
    assert sw(held, Proposed("F", 10.94)) == BLOCK
    assert sw(held, Proposed("F", None, "A+")) == ALLOW
    assert sw(held, Proposed("F", None, "C")) == BLOCK
    assert sw(held, Proposed("F", None, "A")) == REVIEW


def test_category_c_moves_only_higher():
    held = [Held("F", 4)]
    assert sw(held, Proposed("F", 6)) == ALLOW
    assert sw(held, Proposed("F", 5.5)) == BLOCK
    assert sw(held, Proposed("F", None, None)) == REVIEW


def test_internship_only_holder():
    held = [Held("I")]
    assert sw(held, Proposed("I")) == BLOCK
    assert sw(held, Proposed("F", 5)) == ALLOW
    assert sw(held, Proposed("I+F", 5)) == ALLOW


def test_fte_holder_may_take_an_internship_in_every_category_but_a_plus():
    for ctc in (4, 7, 12):
        assert sw([Held("F", ctc)], Proposed("I")) == ALLOW
    assert sw([Held("F", 20)], Proposed("I")) == BLOCK


def test_i_plus_f_blocks_everything():
    for t in ("I", "F", "I+F"):
        assert sw([Held("I+F", 8)], Proposed(t, 50 if t != "I" else None)) == BLOCK


def test_accepted_ppo_turns_an_internship_into_i_plus_f():
    assert sw([Held("I", ppo_accepted=True)], Proposed("F", 20)) == BLOCK
    assert sw([Held("I", ppo_accepted=False)], Proposed("F", 20)) == ALLOW


def test_strict_offer_type_mode_when_category_switching_is_off():
    assert sw([Held("F", 6)], Proposed("F", 30), switch_by_category=False) == BLOCK
    assert sw([Held("F", 6)], Proposed("I+F", 30), switch_by_category=False) == REVIEW
    assert sw([Held("F", 6)], Proposed("I"), switch_by_category=False) == ALLOW


def test_fte_holder_without_a_recorded_ctc_goes_to_review():
    assert sw([Held("F", None)], Proposed("F", 20)) == REVIEW


def test_strictest_result_wins_across_several_held_offers():
    held = [Held("I"), Held("F", 12)]       # I allows F; but A holder allows only A+
    assert sw(held, Proposed("F", 11)) == BLOCK
    assert sw(held, Proposed("F", 16)) == ALLOW


def test_reasons_explain_the_decision():
    d = p.check_switching([Held("F", 8, ref="offer #3 (Kiwi)")], Proposed("F", 9))
    assert d.decision == BLOCK
    assert any("offer #3" in r and "1.5x" in r and "12.0" in r for r in d.reasons)


@pytest.mark.parametrize("kw,expected", [
    (dict(registration="deregistered"), BLOCK), (dict(registration="not_registered"), BLOCK),
    (dict(eligibility="ineligible"), BLOCK), (dict(eligibility="pending_verification"), REVIEW),
    (dict(archived=True), BLOCK), (dict(cgpa=5.0), BLOCK), (dict(backlogs=3), BLOCK), (dict(course="MSCS"), BLOCK),
])
def test_student_and_company_eligibility(kw, expected):
    s = StudentFacts(**{**dict(cgpa=8, backlogs=0, course="MTCS"), **kw})
    co = CompanyFacts("Acme", min_cgpa=6.5, max_backlogs=1, allowed_courses=("MTCS", "MTAI"))
    assert p.evaluate(s, co, Proposed("F", 8), []).decision == expected


def test_review_does_not_hide_a_block():
    s = StudentFacts(eligibility="pending_verification")
    d = p.evaluate(s, ANY_CO, Proposed("I"), [Held("I")])
    assert d.decision == BLOCK


def test_absence_excludes_the_next_three_drives_only():
    drives = [date(2026, 9, k) for k in (1, 5, 9, 13, 17, 21)]
    absent = [drives[0]]
    assert p.absence_exclusion(absent, drives, drives[1]) == drives[0]
    assert p.absence_exclusion(absent, drives, drives[3]) == drives[0]      # 3rd drive after
    assert p.absence_exclusion(absent, drives, drives[4]) is None           # 4th: cleared
    assert p.absence_exclusion(absent, drives, drives[0]) is None           # the drive itself
    assert p.absence_exclusion([], drives, drives[1]) is None


def test_absence_flag_raises_review():
    d = p.evaluate(OK_STUDENT, ANY_CO, Proposed("I"), [], absent_since=date(2026, 9, 1))
    assert d.decision == REVIEW


def test_acceptance_deadline_is_24h_or_company_timeline_whichever_is_earlier():
    t = datetime(2026, 9, 1, 10, 0)
    assert p.acceptance_deadline(t, None) == t + timedelta(hours=24)
    assert p.acceptance_deadline(t, 12) == t + timedelta(hours=12)
    assert p.acceptance_deadline(t, 72) == t + timedelta(hours=24)


@pytest.mark.parametrize("held", [
    [], [Held("I")], [Held("F", 4)], [Held("F", 7)], [Held("F", 12)], [Held("F", 20)], [Held("I+F", 9)],
    [Held("I"), Held("F", 7)], [Held("I"), Held("F", 12)], [Held("I", ppo_accepted=True)], [Held("F", None)],
])
@pytest.mark.parametrize("switch", [True, False])
def test_next_options_agrees_with_the_evaluator(held, switch):
    """Whatever next_options advertises as open must never be BLOCKed by the rule engine."""
    o = p.next_options(held, switch)
    if o["status"] == "closed":
        for t, ctc in (("I", None), ("F", 50), ("I+F", 50)):
            assert sw(held, Proposed(t, ctc), switch_by_category=switch) in (BLOCK, REVIEW) or not held
        return
    for t in o["types"]:
        ctc = (o["min_ctc"] or 1) if p.has_fte(t) else None
        d = sw(held, Proposed(t, ctc), switch_by_category=switch)
        assert d != BLOCK or (held and any(x.ctc is None for x in held)), (held, t, ctc, o)
