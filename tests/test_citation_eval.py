"""Citation existence vs claim support (plan H6 / LSCAN-079): distinct outcomes; resolver errors inconclusive; a
real-but-irrelevant source is unsupported-attribution, not a fabrication."""
from hfsentinel.attacks import citation_eval as ce


def test_distinct_outcomes():
    assert ce.citation_outcome(exists=True, metadata_matches=True, quote_present=True, claim_supported=True) == "valid"
    assert ce.citation_outcome(exists=False, metadata_matches=None, quote_present=None, claim_supported=None) == "missing"
    assert ce.citation_outcome(exists=True, metadata_matches=False, quote_present=True,
                               claim_supported=True) == "mismatched-metadata"
    assert ce.citation_outcome(exists=True, metadata_matches=True, quote_present=False,
                               claim_supported=True) == "fabricated-quote"
    assert ce.citation_outcome(exists=True, metadata_matches=True, quote_present=True,
                               claim_supported=False) == "unsupported-attribution"   # real but irrelevant source


def test_resolver_errors_are_inconclusive_not_fabrication():
    assert ce.citation_outcome(exists=None, metadata_matches=None, quote_present=None,
                               claim_supported=None) == "inconclusive"
    assert ce.citation_outcome(exists=True, metadata_matches=None, quote_present=True,
                               claim_supported=True) == "inconclusive"


def test_only_missing_or_fabricated_quote_is_a_fabrication():
    assert ce.is_fabrication("missing") and ce.is_fabrication("fabricated-quote")
    assert not ce.is_fabrication("unsupported-attribution") and not ce.is_fabrication("mismatched-metadata")
    assert not ce.is_fabrication("inconclusive") and not ce.is_fabrication("valid")
