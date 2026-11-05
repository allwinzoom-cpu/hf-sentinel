"""Strategy library (plan §6.2, campaign S7 "learn"): the durable record of which techniques work on which kinds of
target, so the planner ranks by learned priors instead of a flat 0.5 and the campaign improves over runs.

Each record follows the §6.2 schema (id, category, description, detector, applicable_targets, source, asr_seen) and
keeps **aggregates only** — trials, successes and a timestamp per target bucket, never prompts or responses (D-015). A
bucket is a coarse fingerprint of the target (refusal style + keyword-filter signal) so a prior is drawn from
similar targets. Priors shrink toward 0.5 until enough trials accumulate (Bayesian: a Beta(1,1)-equivalent prior), so
one lucky run cannot dominate ranking. Strategies that stop working are marked ineffective, not deleted (§6.2 step 7).

The file is versioned JSON written atomically; concurrent writers merge on read-modify-write.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = 1
PRIOR_STRENGTH = 10.0  # pseudo-trials of a 0.5 prior; a bucket needs ~this many real trials to move the prior
NEUTRAL_PRIOR = 0.5
MIN_TRIALS_EFFECTIVE = 10  # below this a technique is neither "effective" nor "ineffective" for a bucket


def default_path() -> Path:
    return Path(os.environ.get("HFS_STRATEGY_LIB") or Path.home() / ".cache" / "hfsentinel" / "strategy_library.json")


def bucket(profile) -> str:
    """Coarse, stable target fingerprint for prior lookup. `profile` is a recon TargetProfile or None."""
    if profile is None:
        return "unknown"
    style = getattr(profile, "refusal_style", "unknown") or "unknown"
    kf = profile.has("keyword_filter") if hasattr(profile, "has") else None
    return f"{style}/kf={'y' if kf else 'n' if kf is False else '?'}"


@dataclass
class Outcome:
    trials: int
    successes: int


class StrategyLibrary:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path is not None else default_path()
        self.write_failed = False
        self._data = self._load()

    def _load(self) -> dict:
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(d, dict) and d.get("schema_version") == SCHEMA_VERSION:
                return d
        except (OSError, ValueError):
            pass
        return {"schema_version": SCHEMA_VERSION, "strategies": {}}

    def prior(self, technique_id: str, profile) -> float:
        """Learned success prior for a technique on this kind of target, shrunk toward 0.5 by PRIOR_STRENGTH."""
        rec = self._data["strategies"].get(technique_id)
        if not rec:
            return NEUTRAL_PRIOR
        agg = rec["asr_seen"].get(bucket(profile)) or _pooled(rec["asr_seen"])
        if not agg or agg["trials"] == 0:
            return NEUTRAL_PRIOR
        s = PRIOR_STRENGTH
        return round((agg["successes"] + s * NEUTRAL_PRIOR) / (agg["trials"] + s), 4)

    def effectiveness(self, technique_id: str, profile) -> str:
        rec = self._data["strategies"].get(technique_id)
        agg = rec["asr_seen"].get(bucket(profile)) if rec else None
        if not agg or agg["trials"] < MIN_TRIALS_EFFECTIVE:
            return "unknown"
        return "effective" if agg["successes"] / agg["trials"] >= 0.3 else "ineffective"

    def record(self, technique_id: str, category: str, profile, outcome: Outcome, *, description: str = "",
               detector: str = "", source: str = "campaign") -> None:
        """Write back one campaign outcome (aggregates only). Re-reads the file first so parallel runs merge."""
        self._data = self._load()
        strat = self._data["strategies"].setdefault(technique_id, {
            "id": technique_id, "category": category, "description": description, "detector": detector,
            "applicable_targets": [], "source": source, "asr_seen": {}})
        b = bucket(profile)
        agg = strat["asr_seen"].setdefault(b, {"trials": 0, "successes": 0, "runs": 0})
        agg["trials"] += outcome.trials
        agg["successes"] += outcome.successes
        agg["runs"] += 1
        if b not in strat["applicable_targets"]:
            strat["applicable_targets"].append(b)
        self._flush()

    def _flush(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=1, sort_keys=True)
            os.replace(tmp, self.path)
        except OSError:
            self.write_failed = True  # read-only location: priors still work in-memory, nothing persists


def _pooled(asr_seen: dict) -> dict | None:
    """Fallback prior from all buckets when the target's own bucket is unseen."""
    if not asr_seen:
        return None
    return {"trials": sum(a["trials"] for a in asr_seen.values()),
            "successes": sum(a["successes"] for a in asr_seen.values())}
