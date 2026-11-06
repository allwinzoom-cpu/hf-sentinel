"""Upstream release tracker (plan 679): detects when a pinned pypi engine has a newer release, so a bump can re-run the
coverage matrix. No network: `check` takes an injected fetch returning canned PyPI JSON. Also guards the SSRF surface
(only pypi.org, package names validated) and checks the scheduled workflow wires the checker + the matrix re-run."""
from __future__ import annotations

from pathlib import Path

import pytest

from engines import upstream

ROOT = Path(__file__).resolve().parents[1]


def _fake_fetch(versions: dict):
    def fetch(url: str) -> dict:
        assert url.startswith("https://pypi.org/pypi/")
        pkg = url.split("/pypi/")[1].split("/json")[0]
        return {"info": {"version": versions[pkg]}}
    return fetch


def test_latest_pypi_parses_version():
    assert upstream.latest_pypi("garak", _fake_fetch({"garak": "0.18.0"})) == "0.18.0"


def test_latest_pypi_rejects_bad_name():
    with pytest.raises(upstream.UpstreamError, match="invalid package name"):
        upstream.latest_pypi("../evil", _fake_fetch({}))


def test_fetch_refuses_non_pypi_host():
    with pytest.raises(upstream.UpstreamError, match="non-PyPI"):
        upstream._fetch_json("https://evil.example.com/pypi/garak/json")


@pytest.mark.parametrize(("latest", "pinned", "expected"), [
    ("0.18.0", "0.17.1", True),
    ("0.17.1", "0.17.1", False),
    ("1.0.0", "1.0.0", False),
    ("1.2.10", "1.2.9", True),
    ("1.0.0", "1.0.1", False),       # latest older than pin -> not a bump
    ("1.0.3", "1.0.3rc1", True),     # same release nums, different string -> surface as drift
])
def test_newer(latest, pinned, expected):
    assert upstream.newer(latest, pinned) is expected


def test_check_reports_only_drifted_engines():
    # every pinned pypi engine returns its exact pinned version except garak, which has a newer release
    pins = {name: e for name, e in upstream.load_engines().items()}
    versions = {e["package"]: e["version"] for e in pins.values() if e.get("source") == "pypi" and e.get("package")}
    versions["garak"] = "0.18.0"  # a bump
    drift = upstream.check(_fake_fetch(versions))
    assert [d["engine"] for d in drift] == ["garak"]
    assert drift[0]["pinned"] != drift[0]["latest"] and drift[0]["bump"] is True


def test_check_clean_when_all_current():
    versions = {e["package"]: e["version"] for e in upstream.load_engines().values()
                if e.get("source") == "pypi" and e.get("package")}
    assert upstream.check(_fake_fetch(versions)) == []


def test_main_exit_codes(monkeypatch, capsys):
    monkeypatch.setattr(upstream, "check", lambda fetch=None: [])
    assert upstream.main(["--check"]) == 0
    monkeypatch.setattr(upstream, "check",
                        lambda fetch=None: [{"engine": "garak", "package": "garak", "pinned": "0.17.1",
                                             "latest": "0.18.0", "alias": "probe-suite", "bump": True}])
    assert upstream.main(["--check"]) == upstream.DRIFT_EXIT
    assert "0.17.1 -> 0.18.0" in capsys.readouterr().out
    assert upstream.main([]) == 2  # usage


def test_workflow_wires_checker_and_matrix():
    wf = (ROOT / ".github" / "workflows" / "upstream.yml").read_text(encoding="utf-8")
    assert "schedule:" in wf and "cron:" in wf          # runs on a schedule (done-when: CI-triggered)
    assert "engines/upstream.py --check" in wf          # the drift checker
    assert "engines/coverage_matrix.py" in wf           # re-runs the coverage matrix on bump
