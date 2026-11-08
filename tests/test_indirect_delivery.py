"""Indirect-injection delivery surfaces (plan LSCAN-061): only a lower-trust, ingested surface that crosses into the
instruction path counts; trusted channels and un-ingested surfaces do not."""
from hfsentinel.attacks import indirect_delivery as idl


def test_trust_levels_and_unknown_is_lower_trust():
    assert idl.surface_trust("user_turn") == "trusted" and idl.surface_trust("retrieved_document") == "lower-trust"
    assert idl.surface_trust("some_new_surface") == "lower-trust"          # unknown -> lower-trust (fail-safe)


def test_indirect_injection_requires_lower_trust_ingested_and_crossed():
    assert idl.is_indirect_injection("email", ingested=True, crossed_to_instructions=True)
    assert not idl.is_indirect_injection("user_turn", ingested=True, crossed_to_instructions=True)  # trusted channel
    assert not idl.is_indirect_injection("web_page", ingested=False, crossed_to_instructions=True)  # not ingested
    assert not idl.is_indirect_injection("web_page", ingested=True, crossed_to_instructions=False)  # never crossed


def test_applicability_requires_a_real_consumer():
    assert idl.applicability("retrieved_document", target_ingests=True) == "applicable"
    assert "N/A" in idl.applicability("retrieved_document", target_ingests=False)
