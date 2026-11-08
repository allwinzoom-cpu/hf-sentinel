"""Replication promotion gate (plan / LSCAN-084): Candidate -> Ready needs live-model confirmation + controls, never
paper ASR / fixtures / imported code / a canary surrogate alone."""
import pytest

from engines import promotion as pr


def _dossier(**kw):
    base = {"method": "PAIR", "paper": "arxiv:2310.08419", "code_url": "gh/pair", "pinned_version": "v1",
            "access_assumptions": "chat", "variant_tag": "faithful-replication", "query_budget": "100 calls",
            "controls": ("benign-control",), "target_route": "hf-provider", "oracle_calibration": "kappa 0.7"}
    return pr.Dossier(**{**base, **kw})


def test_promotion_needs_live_confirmation_controls_and_real_evidence():
    ok = _dossier(live_confirmed=True, evidence=("live_replay", "paper_asr"))
    assert pr.can_promote(ok, "ready") and pr.promotion_blocked_reason(ok, "ready") == ""


def test_paper_asr_or_fixtures_alone_cannot_promote():
    paper_only = _dossier(live_confirmed=True, controls=("c",), evidence=("paper_asr", "fixture_success"))
    assert not pr.can_promote(paper_only, "ready")
    assert "insufficient evidence" in pr.promotion_blocked_reason(paper_only, "ready")
    no_live = _dossier(live_confirmed=False, evidence=("live_replay",))
    assert not pr.can_promote(no_live, "conditional") and "no live-model confirmation" in pr.promotion_blocked_reason(no_live, "conditional")
    no_ctrl = _dossier(live_confirmed=True, controls=(), evidence=("live_replay",))
    assert "no matched controls" in pr.promotion_blocked_reason(no_ctrl, "ready")


def test_variation_tag_is_validated():
    with pytest.raises(ValueError, match="variant_tag"):
        _dossier(variant_tag="whatever")
    assert not pr.can_promote(_dossier(live_confirmed=True, evidence=("live_replay",)), "candidate")  # not a promotion
