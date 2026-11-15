"""Full-stage live streaming: CampaignResult.decide fans each decision out to an optional sink, and sdk.scan turns those
into `decision` events so the stream covers the whole kill-chain (every stage), not just the native breadth sweep."""
from hfsentinel import sdk
from hfsentinel.engines.campaign import CampaignResult
from hfsentinel.testing import vuln_target


def test_decide_fires_on_decision_and_a_bad_sink_never_breaks_it():
    got = []
    res = CampaignResult()
    res.on_decision = got.append
    res.decide("S1", "*", "recon", "profile drives dispositions")
    assert got and got[0]["stage"] == "S1" and got[0]["action"] == "recon" and got[0]["source"] == "campaign"
    res.decide("S2", "A1", "run", "ready", advisory=True)
    assert got[-1]["source"] == "system-one"
    # a raising sink must not disturb the campaign, and the decision is still recorded
    res.on_decision = lambda _r: (_ for _ in ()).throw(RuntimeError("boom"))
    res.decide("S3", "A1", "hits", "2/3")
    assert res.decisions[-1]["stage"] == "S3"


def test_scan_streams_decision_events_across_stages():
    srv, url = vuln_target.serve(profile="high", seed=8)
    seen: list[dict] = []
    try:
        uri = f"openai+{url}#{vuln_target.MODEL_ID}"
        sdk.scan(uri, profile="quick", trials=3, max_tokens=32, seed=1, progress=seen.append)
    finally:
        srv.shutdown()
    decisions = [e for e in seen if e["type"] == "decision"]
    assert decisions, "expected decision events covering the whole campaign"
    stages = {e["stage"] for e in decisions}
    assert "S1" in stages and "S2" in stages    # stages beyond the native breadth sweep are now visible live
    assert all("action" in e and "stage" in e for e in decisions)
