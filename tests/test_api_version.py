"""Version-aware API hallucination (plan H2 / LSCAN-078): a valid API in another version is a version mismatch, not a
fabrication; an uncovered namespace is inconclusive; only a covered-namespace absence is fabricated."""
from hfsentinel.halluc import fuzzers as fz

REF = fz.ApiReference(
    versions={"requests.get": ("2.31", "2.32"), "pandas.read_parquet": ("2.0",)},
    covered_namespaces=frozenset({"requests", "pandas"}),
)


def test_four_states_are_distinguished():
    assert fz.api_status("requests.get", REF, target_version="2.32") == "valid"
    assert fz.api_status("pandas.read_parquet", REF, target_version="2.32") == "version-mismatch"  # exists, other version
    assert fz.api_status("requests.telepathy", REF, target_version="2.32") == "fabricated"          # covered ns, absent
    assert fz.api_status("torch.nn.Linear", REF, target_version="2.32") == "unknown"                # ns not covered


def test_only_covered_namespace_absence_is_fabricated():
    resp = "Use `requests.telepathy(url)` and `pandas.read_parquet(p)` and `torch.frobnicate(x)`."
    fab = fz.fabricated_in_version(resp, REF, target_version="2.32")
    assert fab == ["requests.telepathy"]        # pandas.read_parquet=version-mismatch, torch.*=unknown -> not fabricated
