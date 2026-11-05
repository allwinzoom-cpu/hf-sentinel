"""Calibration labels + Cohen's kappa."""
import json

import pytest

from hfsentinel.judges import calibration as cal

H = "a" * 64


def test_kappa_known_values():
    # Textbook example: 50 items, p_o = 0.7, p_e = 0.5 -> kappa = 0.4
    a = ["y"] * 25 + ["n"] * 25
    b = ["y"] * 20 + ["n"] * 5 + ["y"] * 10 + ["n"] * 15
    assert cal.cohens_kappa(a, b) == pytest.approx(0.4)
    assert cal.cohens_kappa(["y", "n"], ["y", "n"]) == 1.0
    assert cal.cohens_kappa(["y", "n"], ["n", "y"]) == pytest.approx(-1.0)
    assert cal.cohens_kappa(["y", "y"], ["y", "y"]) == 1.0
    with pytest.raises(ValueError):
        cal.cohens_kappa(["y"], [])


def _write(tmp_path, cat, rows):
    (tmp_path / f"{cat}.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def _rows(cat, n, disagree=0):
    rows = []
    for i in range(n):
        lab = "success" if i % 2 else "fail"
        other = ("fail" if lab == "success" else "success") if i < disagree else lab
        for ann, value in (("ann1", lab), ("ann2", other)):
            rows.append({"item_id": f"{cat}-{i}", "catalog_id": f"{cat}1", "annotator": ann,
                         "label": value, "response_sha256": H})
    return rows


def test_gate_passes_with_enough_agreeing_items(tmp_path):
    for c in cal.CATEGORIES:
        _write(tmp_path, c, _rows(c, 50, disagree=5))
    report = cal.agreement_report(cal.load_labels(tmp_path))
    assert all(r["pass"] for r in report.values())
    assert report["A"]["kappa"] == pytest.approx(0.8)


def test_gate_fails_on_too_few_items_or_low_kappa(tmp_path):
    _write(tmp_path, "A", _rows("A", 49))
    _write(tmp_path, "B", _rows("B", 50, disagree=20))
    report = cal.agreement_report(cal.load_labels(tmp_path))
    assert not report["A"]["pass"] and report["A"]["items"] == 49
    assert not report["B"]["pass"] and report["B"]["kappa"] < cal.MIN_KAPPA
    assert not report["H"]["pass"] and report["H"]["kappa"] is None


def test_rejects_bad_or_duplicate_labels(tmp_path):
    _write(tmp_path, "A", [{"item_id": "x", "catalog_id": "A1", "annotator": "a", "label": "maybe",
                            "response_sha256": H}])
    with pytest.raises(ValueError, match="A.jsonl:1"):
        cal.load_labels(tmp_path)
    dup = _rows("C", 1) + _rows("C", 1)[:1]
    _write(tmp_path, "A", dup)
    with pytest.raises(ValueError, match="duplicate"):
        cal.agreement_report(cal.load_labels(tmp_path))
