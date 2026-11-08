"""Persistent / non-HTTP transport contracts (plan / LSCAN-019): correlation resolves out-of-order + duplicate events, a
dropped connection is inconclusive (never a fabricated completion), and an HTTP adapter cannot claim browser coverage."""
import pytest

from engines import transports as tp


def test_transport_name_is_validated_and_persistence_known():
    ws = tp.TransportContract("websocket", supports_sessions=True, supports_cancel=True)
    assert ws.is_persistent
    assert not tp.TransportContract("http", supports_sessions=False, supports_cancel=False).is_persistent
    with pytest.raises(ValueError, match="unknown transport"):
        tp.TransportContract("carrier-pigeon", supports_sessions=False, supports_cancel=False)


def test_correlation_orders_by_seq_regardless_of_wire_order():
    events = [tp.Event("req-1", 2, "b"), tp.Event("req-2", 0, "x"), tp.Event("req-1", 0, "a"),
              tp.Event("req-1", 1, "mid")]
    assert [e.payload for e in tp.correlate(events, "req-1")] == ["a", "mid", "b"]


def test_duplicate_callbacks_are_collapsed():
    events = [tp.Event("r", 0, "a"), tp.Event("r", 0, "a-dup"), tp.Event("r", 1, "b")]
    assert [e.payload for e in tp.dedupe(events)] == ["a", "b"]


def test_stale_session_detected_after_epoch_advance():
    assert tp.is_stale(session_epoch=1, current_epoch=2)
    assert not tp.is_stale(session_epoch=2, current_epoch=2)


def test_dropped_connection_is_inconclusive_never_completed():
    assert "inconclusive" in tp.completion_evidence("dropped", observed_effect=True)   # even with a prior effect
    assert "completed" in tp.completion_evidence("open", observed_effect=True)
    assert "no completion" in tp.completion_evidence("open", observed_effect=False)
    assert "no completion" in tp.completion_evidence("cancelled", observed_effect=True)
    with pytest.raises(ValueError, match="unknown session state"):
        tp.completion_evidence("zombie", observed_effect=False)


def test_http_adapter_cannot_claim_browser_coverage():
    http = tp.TransportContract("http", supports_sessions=False, supports_cancel=False)
    ws = tp.TransportContract("websocket", supports_sessions=True, supports_cancel=True)
    assert "cannot claim browser coverage" in tp.coverage_claim(http, surface="browser", has_operator_bridge=False)
    # even a persistent transport needs the operator bridge for a browser surface
    assert "inconclusive" in tp.coverage_claim(ws, surface="browser", has_operator_bridge=False)
    assert "covered" in tp.coverage_claim(ws, surface="browser", has_operator_bridge=True)
    assert "covered" in tp.coverage_claim(http, surface="api", has_operator_bridge=False)
