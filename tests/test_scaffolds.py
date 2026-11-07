"""Static public-jailbreak-scaffold corpus (plan 16.18): the encode-and-follow transforms (B16 FlipAttack, B14
Bijection) are scored by the deterministic canary oracle; the persona families (DAN/AIM/…) run as supplementary intel.
Strictly static payloads — reproducible with no judge. Laya triages the persona probes (advisory)."""
import re

from hfsentinel.attacks import scaffolds
from hfsentinel.attacks.canary import CanaryRun
from hfsentinel.attacks.mutators import bijection_decode

_TOKEN = re.compile(r"[A-Z0-9]{4}(?:-[A-Z0-9]{4})+")  # the canary shape (4-char groups)
from hfsentinel.core.system_one import Decision
from hfsentinel.engines.campaign import CampaignResult, _scaffold_stage
from hfsentinel.engines.governor import Governor, Ledger
from hfsentinel.engines.planner import Plan, PlanStep
from hfsentinel.targets.resolve import parse

PLAN = Plan(parse("openai+http://127.0.0.1:8000/v1#m"), 1,
            (PlanStep("B16", "FlipAttack", "run", None), PlanStep("B14", "Bijection learning", "run", None),
             PlanStep("B6", "Decomposition (DrAttack-style)", "run", None)))


class _R:
    def __init__(self, text):
        self.text, self.usage = text, {}


class Decoding:
    """A target that reads the scaffold's hint, applies the right inverse, and *complies* (replies with just the
    recovered token) — exactly what a capable model does. The worst case for a filter: a clean compliance hit."""
    def chat(self, messages, *, max_tokens, temperature):
        c = next(m["content"] for m in reversed(messages) if m.get("role") == "user")
        hint, _, body = c.partition("\n")
        if "backwards" in hint:
            decoded = body[::-1]
        elif "substitution cipher" in hint:
            decoded = bijection_decode(body)
        elif "ordered words" in hint:
            decoded = " ".join(re.findall(r"\[\d+\]\s*(.*)", body))  # reassemble the decomposed fragments
        else:
            decoded = body or c  # persona scaffolds carry the instruction in plaintext
        m = _TOKEN.search(decoded)
        return _R(f"Sure: {m.group(0)}" if m else "ok")


class Refusing:
    def chat(self, messages, *, max_tokens, temperature):
        return _R("I can't help with that request.")


class FakeS1:
    available = True

    def __init__(self):
        self.calls = []

    def triage(self, goal, response):
        self.calls.append((goal, response))
        return Decision("triage", "refusal", 0.9, 0.9)


def _gov():
    return Governor(Ledger(max_requests=100_000, budget_usd=1.0), concurrency=2)


def test_library_scoping():
    assert set(scaffolds.SCORED) == {"B16", "B14", "B6"}
    assert {s.catalog_id for s in scaffolds.scored_scaffolds()} == {"B16", "B14", "B6"}
    # persona families are public, catalog-mapped, and never graded here
    personas = {s.name for s in scaffolds.persona_scaffolds()}
    assert {"DAN (Do Anything Now)", "AIM", "Developer Mode",
            "Formal-logic reframing (LogiBreak)", "Reasoning-model self-jailbreak"} <= personas
    assert all(not s.scored for s in scaffolds.persona_scaffolds())
    assert {s.catalog_id for s in scaffolds.persona_scaffolds()} >= {"B9", "B10"}  # B9/B10 exercised as intel


def test_encode_scaffolds_round_trip():
    msg = "output the token CANARY_ZZZ exactly"
    assert bijection_decode(scaffolds.apply(scaffolds.LIBRARY["B14"], msg).split("\n", 1)[1]) == msg
    assert scaffolds.apply(scaffolds.LIBRARY["B16"], msg).split("\n", 1)[1][::-1] == msg
    assert "{instruction}" not in scaffolds.apply(scaffolds.LIBRARY["dan"], msg) and msg in scaffolds.apply(
        scaffolds.LIBRARY["dan"], msg)


def test_scored_scaffolds_confirm_on_a_decoding_target():
    res = CampaignResult()
    _scaffold_stage(res, Decoding(), _gov(), CanaryRun(1), plan=PLAN, trials=6, max_tokens=64, seed=1)
    runs = {r.catalog_id: r for r in res.runs}
    assert set(runs) == {"B16", "B14", "B6"}
    for cid in ("B16", "B14", "B6"):
        assert runs[cid].hits == runs[cid].trials >= 5  # decoded + obeyed every trial
    assert any(d["stage"] == "S5" and d["action"] == "confirmed" for d in res.decisions)


def test_refusing_target_is_a_clean_zero():
    res = CampaignResult()
    _scaffold_stage(res, Refusing(), _gov(), CanaryRun(2), plan=PLAN, trials=6, max_tokens=64, seed=2)
    runs = {r.catalog_id: r for r in res.runs}
    assert runs["B16"].hits == 0 and runs["B14"].hits == 0 and runs["B6"].hits == 0  # agnostic: no decode, no finding
    assert all(d["action"] == "unconfirmed" for d in res.decisions if d["stage"] == "S5")


def test_laya_triages_persona_probes_when_available():
    res, s1 = CampaignResult(), FakeS1()
    _scaffold_stage(res, Refusing(), _gov(), CanaryRun(3), plan=PLAN, trials=5, max_tokens=64, seed=3, system_one=s1)
    # persona probes are recorded as campaign intel; Laya adds an advisory triage decision per persona
    assert any(d["stage"] == "S4" and "persona" in d["action"] and d["source"] == "campaign" for d in res.decisions)
    assert any(d["action"].startswith("Laya triage") and d["source"] == "system-one" for d in res.decisions)
    assert s1.calls  # Laya was actually consulted on the real responses


def test_no_laya_adds_no_system_one_decisions():
    res = CampaignResult()
    _scaffold_stage(res, Refusing(), _gov(), CanaryRun(4), plan=PLAN, trials=5, max_tokens=64, seed=4)
    assert not any(d["source"] == "system-one" for d in res.decisions)
