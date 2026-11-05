"""Strategy library (plan §6.2, campaign S7) + planner priors: learned priors shrink toward 0.5, persist per target
bucket, reorder the plan, and keep aggregates only (D-015)."""
from dataclasses import dataclass

from hfsentinel.engines.planner import DEFAULT_PRIOR_ASR, build_plan
from hfsentinel.engines.strategy_library import NEUTRAL_PRIOR, Outcome, StrategyLibrary, bucket
from hfsentinel.targets.resolve import parse


@dataclass
class FakeProfile:
    refusal_style: str = "none"
    _kf: bool | None = None

    def has(self, name):
        return self._kf if name == "keyword_filter" else None


def test_bucket_is_stable_and_coarse():
    assert bucket(FakeProfile("templated", True)) == "templated/kf=y"
    assert bucket(FakeProfile("none", False)) == "none/kf=n"
    assert bucket(FakeProfile("none", None)) == "none/kf=?"
    assert bucket(None) == "unknown"


def test_prior_shrinks_toward_half_then_moves_with_evidence(tmp_path):
    lib = StrategyLibrary(tmp_path / "lib.json")
    prof = FakeProfile("none", False)
    assert lib.prior("C2", prof) == NEUTRAL_PRIOR  # nothing learned yet
    lib.record("C2", "C", prof, Outcome(trials=10, successes=9))
    p1 = lib.prior("C2", prof)
    assert 0.5 < p1 < 0.9  # 10 trials, shrunk by PRIOR_STRENGTH=10 → ~0.7
    for _ in range(9):
        lib.record("C2", "C", prof, Outcome(trials=10, successes=9))
    p2 = lib.prior("C2", prof)
    assert p2 > p1 and p2 > 0.8  # 100 trials: prior approaches the observed 0.9


def test_prior_is_bucket_specific_with_pooled_fallback(tmp_path):
    lib = StrategyLibrary(tmp_path / "lib.json")
    weak, hard = FakeProfile("none", False), FakeProfile("templated", True)
    lib.record("B1", "B", weak, Outcome(40, 36))  # succeeds on undefended targets
    assert lib.prior("B1", weak) > 0.7
    # unseen bucket falls back to the pooled estimate, not a blind 0.5
    assert lib.prior("B1", hard) > 0.5


def test_effectiveness_label(tmp_path):
    lib = StrategyLibrary(tmp_path / "lib.json")
    prof = FakeProfile()
    assert lib.effectiveness("A1", prof) == "unknown"
    lib.record("A1", "A", prof, Outcome(4, 4))
    assert lib.effectiveness("A1", prof) == "unknown"  # below MIN_TRIALS_EFFECTIVE
    lib.record("A1", "A", prof, Outcome(20, 1))
    assert lib.effectiveness("A1", prof) == "ineffective"  # 5/24 < 0.3


def test_persistence_and_merge(tmp_path):
    path = tmp_path / "lib.json"
    StrategyLibrary(path).record("C2", "C", FakeProfile(), Outcome(10, 8))
    again = StrategyLibrary(path)  # reloads from disk
    assert again.prior("C2", FakeProfile()) != NEUTRAL_PRIOR
    again.record("C2", "C", FakeProfile(), Outcome(10, 8))
    assert again._load()["strategies"]["C2"]["asr_seen"]["none/kf=?"]["trials"] == 20


def test_stores_aggregates_only_no_text(tmp_path):
    path = tmp_path / "lib.json"
    lib = StrategyLibrary(path)
    lib.record("C2", "C", FakeProfile(), Outcome(10, 7))
    blob = path.read_text()
    assert "trials" in blob and "successes" in blob
    rec = lib._load()["strategies"]["C2"]
    assert set(rec) == {"id", "category", "description", "detector", "applicable_targets", "source", "asr_seen"}
    assert set(rec["asr_seen"]["none/kf=?"]) == {"trials", "successes", "runs"}  # counts, not prompts/responses


def test_read_only_location_degrades(tmp_path):
    lib = StrategyLibrary(tmp_path / "nope" / "sub")  # a path we then make unwritable by using a file as the dir
    (tmp_path / "nope").write_text("not a dir")
    lib.record("C2", "C", FakeProfile(), Outcome(10, 8))
    assert lib.write_failed and lib.prior("C2", FakeProfile()) != NEUTRAL_PRIOR  # in-memory prior still works


def test_planner_uses_learned_priors_to_reorder(tmp_path):
    lib = StrategyLibrary(tmp_path / "lib.json")
    prof = FakeProfile("none", False)
    # teach the library that A2 works and A1 does not, on this bucket
    lib.record("A1", "A", prof, Outcome(40, 1))
    lib.record("A2", "A", prof, Outcome(40, 38))
    target = parse("openai+http://127.0.0.1:9/v1#m")
    base = {s.catalog_id: s.score for s in build_plan(target, selected=["A1", "A2"], profile=prof).steps}
    learned = {s.catalog_id: s for s in build_plan(target, selected=["A1", "A2"], profile=prof, library=lib).steps}
    assert base["A1"] == base["A2"]  # same severity/effort → equal without learning
    assert learned["A2"].score > learned["A1"].score  # learning favours A2
    assert "learned prior" in learned["A2"].rationale


def test_default_prior_constant_unchanged():
    assert DEFAULT_PRIOR_ASR == 0.5
