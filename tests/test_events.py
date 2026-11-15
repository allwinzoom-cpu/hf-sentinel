"""Scan progress events: the event helper shape, and that sdk.scan streams scan_started → technique_done* →
scan_completed with enriched per-technique data, while a failing subscriber never disturbs the scan."""
from hfsentinel import events, sdk
from hfsentinel.testing import vuln_target


def test_scan_event_shape_and_emit_is_safe():
    e = events.scan_event("technique_done", catalog_id="A1", asr=None, hits=3)
    assert e["type"] == "technique_done" and e["catalog_id"] == "A1" and e["hits"] == 3
    assert "asr" not in e and e["ts"].endswith("+00:00")        # None fields dropped; timestamp is UTC ISO
    events.emit(None, "x")                                       # no callback -> no-op, no error
    events.emit(lambda _ev: (_ for _ in ()).throw(RuntimeError("boom")), "x")  # subscriber error is swallowed


def test_scan_streams_progress_events():
    srv, url = vuln_target.serve(profile="high", seed=5)
    seen: list[dict] = []
    try:
        uri = f"openai+{url}#{vuln_target.MODEL_ID}"
        result = sdk.scan(uri, profile="quick", trials=3, max_tokens=32, seed=1, progress=seen.append)
    finally:
        srv.shutdown()

    kinds = [e["type"] for e in seen]
    assert kinds[0] == "scan_started" and kinds[-1] == "scan_completed"
    start = seen[0]
    assert start["run_id"] == result.run_id and start["total"] >= 1 and start["profile"] == "quick"

    techs = [e for e in seen if e["type"] == "technique_done"]
    assert techs, "expected at least one per-technique event"
    for e in techs:
        assert e["catalog_id"] and e["category"]
        assert e["outcome"] in ("confirmed", "hit", "no-hit")
        assert e.get("asr") is None or 0.0 <= e["asr"] <= 1.0
        assert e["requests"] >= 0 and e["cost_usd"] >= 0.0
    # requests are cumulative across the stream (monotonic non-decreasing)
    req = [e["requests"] for e in techs]
    assert req == sorted(req)

    done = seen[-1]
    result_grade = result.grade.get("overall") if isinstance(result.grade, dict) else result.grade.overall
    assert done["run_id"] == result.run_id and done["grade"] == result_grade
    assert done["confirmed"] == result.confirmed


def test_failing_subscriber_never_sinks_the_scan():
    srv, url = vuln_target.serve(seed=6)
    try:
        uri = f"openai+{url}#{vuln_target.MODEL_ID}"
        result = sdk.scan(uri, profile="quick", trials=2, max_tokens=32, seed=1,
                          progress=lambda _ev: (_ for _ in ()).throw(RuntimeError("boom")))
    finally:
        srv.shutdown()
    assert result.run_id and result.report is not None  # scan completed despite every emit raising
