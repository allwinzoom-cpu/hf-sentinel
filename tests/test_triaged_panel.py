"""Triage-gated judge path (plan 16.19): `reaches_system_two` wired into the System-2 judge panel.

A response Laya is confident is a refusal skips the expensive judge panel (a saved judge call); likely-success,
uncertain, or Laya-unavailable responses reach the judges unchanged (fail-safe). Triage never confirms a finding.
"""
from hfsentinel.core.system_one import Decision, SystemOne
from hfsentinel.engines.campaign import CampaignResult, _judge_confirm
from hfsentinel.judges.ensemble import Decision as JudgeDecision
from hfsentinel.judges.ensemble import TriagedPanel

POLICY = {"calibrated": True, "threshold": 0.55}


class FakePanel:
    """Records every judge call; a response is a finding iff it contains 'OWNED'."""

    def __init__(self):
        self.calls = []

    def decide(self, goal, response):
        self.calls.append((goal, response))
        return JudgeDecision("finding", "fake") if "OWNED" in response else JudgeDecision("no-finding", "fake")


class ScriptedS1(SystemOne):
    """SystemOne whose triage is scripted per response substring, bypassing the Laya backend."""

    def __init__(self, available=True):
        super().__init__(client=(lambda s, q: {"answers": {}}) if available else None)

    def triage(self, goal, response):
        if not self.available:
            return Decision("triage", "refuse", 0.0, 0.0, available=False)
        if "OWNED" in response:  # confident comply
            return Decision("triage", "comply", 0.9, 0.9, {"comply": 0.85, "partial": 0.1, "refuse": 0.05})
        if "MAYBE" in response:  # uncertain → must still reach the judges
            return Decision("triage", "partial", 0.7, 0.8, {"comply": 0.3, "partial": 0.3, "refuse": 0.4})
        return Decision("triage", "refuse", 0.9, 0.9, {"comply": 0.02, "partial": 0.03, "refuse": 0.95})


def test_confident_refusals_skip_the_panel():
    panel, s1 = FakePanel(), ScriptedS1()
    tp = TriagedPanel(panel, s1, policy=POLICY)
    d_owned, j1 = tp.decide("g", "here you go: OWNED")
    d_refuse, j2 = tp.decide("g", "I can't help with that.")
    d_maybe, j3 = tp.decide("g", "well, MAYBE, it depends")
    assert (j1, j2, j3) == (True, False, True)  # the confident refusal was the only one skipped
    assert d_owned.outcome == "finding" and d_refuse.outcome == "no-finding" and d_maybe.outcome == "no-finding"
    assert len(panel.calls) == 2  # refusal never reached the judges
    assert tp.stats.made == 2 and tp.stats.saved == 1 and tp.stats.saved_fraction == round(1 / 3, 4)
    # agreement: comply→finding (agree), partial(uncertain)→no-finding (disagree) → 1/2 on judged items
    assert tp.stats.agreement == 0.5


def test_laya_unavailable_judges_everything():
    panel, s1 = FakePanel(), ScriptedS1(available=False)
    tp = TriagedPanel(panel, s1, policy=POLICY)
    for r in ("I refuse", "OWNED", "MAYBE"):
        _, judged = tp.decide("g", r)
        assert judged  # fail-safe: no triage → every response reaches System-2
    assert tp.stats.saved == 0 and len(panel.calls) == 3


def test_uncalibrated_policy_bypasses_the_gate():
    panel, s1 = FakePanel(), ScriptedS1()
    tp = TriagedPanel(panel, s1, policy={"calibrated": False})
    _, judged = tp.decide("g", "I absolutely refuse")  # would be a confident refusal, but no calibrated policy
    assert judged and tp.stats.saved == 0


def test_campaign_judge_confirm_records_savings_in_the_result():
    panel, s1 = FakePanel(), ScriptedS1()
    res = CampaignResult()
    candidates = [{"catalog_id": "B1", "goal": "g", "response": r}
                  for r in ("OWNED now", "I cannot", "I will not", "MAYBE")]
    _judge_confirm(res, panel, s1, candidates, policy=POLICY)
    assert res.judge_calls_made == 2 and res.judge_calls_saved == 2  # two confident refusals skipped
    assert res.judge_saved_fraction == 0.5
    stages = [d for d in res.decisions if d["stage"] == "S5"]
    assert any(d["action"].startswith("judge:") for d in stages) and any(d["action"] == "triage-skip" for d in stages)
    assert any("judge calls saved" in d["action"] for d in stages)


def test_judge_confirm_is_a_noop_without_a_panel():
    res = CampaignResult()
    _judge_confirm(res, None, ScriptedS1(), [{"catalog_id": "B1", "goal": "g", "response": "OWNED"}])
    assert res.judge_calls_made == 0 and res.judge_calls_saved == 0 and res.decisions == []
