"""Conditional membership-inference research lane (plan / LSCAN-053).

Membership inference asks whether a given text was in a model's training data. We keep it strictly a RESEARCH lane with
hard guardrails, because the failure mode — asserting an individual-level training-membership finding without ground
truth — is both unscientific and privacy-hostile:

  * Two method families are evaluated SEPARATELY and never pooled: `text-sampling` (quiz / sampling methods that use only
    generated text) and `logprob` (methods that use API-exposed token logprobs). API logprobs do NOT imply weight or
    gradient access — a logprob result is still black-box.
  * Scoring needs operator-supplied ground truth (known members / nonmembers) drawn from a MATCHED distribution. Without
    it, the result is `inconclusive` / experimental — never an individual membership claim.
  * Performance is reported at a PRESPECIFIED false-positive rate: the decision threshold is calibrated on the
    nonmembers to hit that FPR, then TPR is read off the members, with a Wilson interval (uncertainty always shown).
  * A model-free baseline (TPR == FPR, i.e. chance) is reported alongside; a method that does not clear chance by its
    interval is not evidence of anything.

This is the offline statistical core — the method scores are produced elsewhere; here we only calibrate, measure and
gate. See [[store-only-proven-findings]] and [[agnostic-assessment]].
"""
from __future__ import annotations

from dataclasses import dataclass

from hfsentinel.scoring.stats import wilson

LANES = ("text-sampling", "logprob")


@dataclass(frozen=True)
class Scored:
    """One operator-labeled item: a method score (higher == more member-like) and its true membership."""
    score: float
    is_member: bool


def threshold_at_fpr(nonmember_scores: list[float], fpr: float) -> float:
    """The score threshold that admits at most `fpr` of the NONMEMBERS as (false) members. Calibrated only on
    nonmembers so the operating point is fixed before members are scored (no peeking). An empty nonmember set or an
    out-of-range fpr is a usage error."""
    if not 0.0 < fpr < 1.0:
        raise ValueError("fpr must be in (0, 1)")
    if not nonmember_scores:
        raise ValueError("need nonmember scores to calibrate a threshold")
    ranked = sorted(nonmember_scores, reverse=True)       # most member-like first
    # Allow floor(fpr * n) false positives; the threshold sits just above the (k+1)-th highest nonmember score. The
    # +1e-9 guards against float truncation — e.g. 0.29*100 == 28.9999…, which bare int() would floor to 28, not 29.
    k = int(fpr * len(ranked) + 1e-9)
    if k == 0:
        return ranked[0] + 1e-9                           # admit none: threshold above the top nonmember
    return ranked[k - 1]                                  # admit exactly the k most member-like nonmembers


@dataclass
class MembershipResult:
    lane: str
    n_members: int
    n_nonmembers: int
    fpr_target: float
    tpr: float = 0.0                      # true-positive rate at the calibrated threshold
    tpr_lo: float = 0.0                   # Wilson lower/upper bound on the TPR (uncertainty)
    tpr_hi: float = 0.0
    threshold: float = 0.0
    holdout_split: str = ""               # how members/nonmembers were split (operator-recorded)
    contamination_note: str = ""          # recorded contamination risk (e.g. benchmark overlap)
    conclusive: bool = True               # False -> experimental/inconclusive, no membership claim

    @property
    def baseline_tpr(self) -> float:
        """Model-free baseline: at a prespecified FPR, a chance detector achieves TPR == FPR."""
        return self.fpr_target

    @property
    def beats_chance(self) -> bool:
        """True only if the TPR's Wilson LOWER bound clears the chance baseline — the one defensible read."""
        return self.conclusive and self.tpr_lo > self.baseline_tpr

    @property
    def verdict(self) -> str:
        if not self.conclusive:
            return "inconclusive: no membership ground truth — experimental, not an individual-membership finding"
        band = f"TPR {self.tpr:.2f} (95% CI {self.tpr_lo:.2f}-{self.tpr_hi:.2f}) at FPR {self.fpr_target:.2f}"
        if self.beats_chance:
            return f"above chance: {band} vs baseline {self.baseline_tpr:.2f} [{self.lane}]"
        return f"not above chance: {band} vs baseline {self.baseline_tpr:.2f} [{self.lane}]"


def evaluate(lane: str, scored: list[Scored], *, fpr_target: float = 0.05, holdout_split: str = "",
             contamination_note: str = "") -> MembershipResult:
    """Evaluate one method family (LSCAN-053). Calibrates the threshold on nonmembers to the prespecified FPR, reads the
    TPR on members with a Wilson interval, and compares to the chance baseline. Returns an `inconclusive` result (never a
    membership claim) when either class is missing — the ground-truth guardrail."""
    if lane not in LANES:
        raise ValueError(f"unknown lane {lane!r}; expected one of {LANES}")
    members = [s.score for s in scored if s.is_member]
    nonmembers = [s.score for s in scored if not s.is_member]
    if not members or not nonmembers:
        return MembershipResult(lane=lane, n_members=len(members), n_nonmembers=len(nonmembers),
                                fpr_target=fpr_target, holdout_split=holdout_split,
                                contamination_note=contamination_note, conclusive=False)
    threshold = threshold_at_fpr(nonmembers, fpr_target)
    hits = sum(1 for s in members if s >= threshold)
    lo, hi = wilson(hits, len(members))
    return MembershipResult(lane=lane, n_members=len(members), n_nonmembers=len(nonmembers), fpr_target=fpr_target,
                            tpr=hits / len(members), tpr_lo=lo, tpr_hi=hi, threshold=threshold,
                            holdout_split=holdout_split, contamination_note=contamination_note)
