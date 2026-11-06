"""Space UI (plan 663/664): a Gradio app over the same engine. run_scan reuses the CLI campaign path, so a UI scan
matches the equivalent CLI run; owner-gated; over-budget aborts cleanly. gradio is lazily imported, so these tests do not
need it installed."""
import pytest

from hfsentinel.space.app import authorized, run_scan
from hfsentinel.testing import vuln_target


def _flags(**kw):
    return {"trials": 6, "temperature": 0.0, "max_tokens": 128, **kw}


def test_run_scan_matches_a_direct_campaign_report():
    from hfsentinel import cli
    from hfsentinel.controls import resolve_controls
    from hfsentinel.scope import authorize
    from hfsentinel.targets.resolve import parse, resolve

    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        uri = f"openai+{base}#{vuln_target.MODEL_ID}"
        ui = run_scan(uri, _flags())                                   # the UI path
        t = resolve(parse(uri))
        cli_report = cli._campaign_report(t, resolve_controls(_flags()).controls,
                                          authorize(None, t, resolved=True), ref=uri)
        assert ui.grade["overall"] == cli_report.grade["overall"] == "F"   # same engine → same grade
        assert ui.findings and {f.catalog_id[0] for f in ui.findings} & {"A", "C", "E"}
    finally:
        srv.shutdown()


def test_scan_is_owner_gated():
    assert authorized("owner-tok", ("owner-tok",))
    assert not authorized("wrong", ("owner-tok",))
    assert authorized(None, ())                                        # no owners configured → open (local use)
    with pytest.raises(PermissionError):                              # non-owner is refused before any network call
        run_scan("openai+http://127.0.0.1:1/v1#m", _flags(), owners=("owner-tok",), token="wrong")


def test_over_budget_scan_aborts_cleanly():
    srv, base = vuln_target.serve(profile=vuln_target.ALWAYS, seed=0)
    try:
        uri = f"openai+{base}#{vuln_target.MODEL_ID}"
        report = run_scan(uri, _flags(trials=50, max_requests=3))      # tiny request cap
        assert report is not None and report.grade                    # returns a report, no crash (stopped at the cap)
    finally:
        srv.shutdown()
