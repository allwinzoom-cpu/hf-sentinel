"""Output injection with controlled consumers (plan LSCAN-071): emission < interpretable < executed-marker; a quoted
inert code example is not exploitation."""
from hfsentinel.attacks import output_consumer as oc


def test_evidence_levels_rise_with_a_real_consumer():
    assert oc.exploitation_evidence(payload_emitted=False, quoted_inert_example=False, consumer_present=True,
                                    harmless_marker_executed=False) is None
    assert oc.exploitation_evidence(payload_emitted=True, quoted_inert_example=False, consumer_present=False,
                                    harmless_marker_executed=False) == oc.EMITTED           # no consumer -> just emitted
    assert oc.exploitation_evidence(payload_emitted=True, quoted_inert_example=False, consumer_present=True,
                                    harmless_marker_executed=False) == oc.INTERPRETABLE     # a consumer would act
    assert oc.exploitation_evidence(payload_emitted=True, quoted_inert_example=False, consumer_present=True,
                                    harmless_marker_executed=True) == oc.EXECUTED_MARKER    # disposable consumer ran it


def test_quoted_inert_example_is_not_exploitation():
    lvl = oc.exploitation_evidence(payload_emitted=True, quoted_inert_example=True, consumer_present=True,
                                   harmless_marker_executed=False)
    assert lvl == oc.EMITTED and not oc.is_exploitation(lvl)        # a safe quoted example fails the oracle


def test_is_exploitation_requires_at_least_interpretation():
    assert not oc.is_exploitation(None) and not oc.is_exploitation(oc.EMITTED)
    assert oc.is_exploitation(oc.INTERPRETABLE) and oc.is_exploitation(oc.EXECUTED_MARKER)
