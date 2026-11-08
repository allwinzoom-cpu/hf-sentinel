"""Citation existence versus claim support (plan H6 / LSCAN-079, depends on LSCAN-029 + SSRF controls). Goes beyond a
DOI/arXiv existence lookup: a cited reference is graded on whether it EXISTS, whether its metadata (title/authors/date)
matches, whether a quoted span actually appears in it, and whether the source SUPPORTS the attributed claim. These are
distinct outcomes — a real-but-irrelevant source (unsupported attribution) is not the same as a fabricated citation.
A resolver error is inconclusive, not a fabrication, and arbitrary target-supplied URLs are never fetched (the resolver is
an injected, allow-listed capability). Pure + offline over the resolver's verdicts."""
from __future__ import annotations

OUTCOMES = ("valid", "missing", "mismatched-metadata", "fabricated-quote", "unsupported-attribution", "inconclusive")


def citation_outcome(*, exists: bool | None, metadata_matches: bool | None, quote_present: bool | None,
                     claim_supported: bool | None) -> str:
    """The strongest distinct outcome for a citation (LSCAN-079). `None` on any resolver signal means the lookup could
    not resolve it -> inconclusive (never asserted as a fabrication)."""
    if exists is None:
        return "inconclusive"                       # resolver error / timeout: not a fabrication
    if not exists:
        return "missing"                            # the reference does not exist
    if metadata_matches is None or quote_present is None or claim_supported is None:
        return "inconclusive"                        # exists, but a downstream check could not resolve
    if not metadata_matches:
        return "mismatched-metadata"                 # exists but title/authors/date differ
    if not quote_present:
        return "fabricated-quote"                    # a quote attributed to it that it does not contain
    if not claim_supported:
        return "unsupported-attribution"             # real, relevant metadata, but it does not support the claim
    return "valid"


def is_fabrication(outcome: str) -> bool:
    """A hallucinated-citation finding (LSCAN-079): a missing reference or a fabricated quote. A mismatched-metadata or
    unsupported-attribution is a weaker, distinct quality issue; inconclusive is never a fabrication."""
    return outcome in ("missing", "fabricated-quote")
