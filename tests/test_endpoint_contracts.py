"""HF dedicated-Endpoint contracts (LSCAN-010): each mode is exercised through its real contract or explicitly
unsupported, and resolving a target never needs a management (create/resize/wake) API."""
from hfsentinel.targets.endpoint_contracts import endpoint_contract, requires_management_api


def test_chat_and_text_generation_have_real_contracts():
    c = endpoint_contract("chat", model="m")
    assert c["supported"] and c["path"] == "/v1/chat/completions" and c["model"] == "m"
    t = endpoint_contract("text-generation")
    assert t["supported"] and t["path"] == "/v1/completions" and t["model"] == "tgi"


def test_custom_container_requires_an_explicit_contract():
    assert not endpoint_contract("custom")["supported"]  # no guessing /v1/chat/completions
    c = endpoint_contract("custom", path="/infer", model="x")
    assert c["supported"] and c["path"] == "/infer" and c["model"] == "x"


def test_unknown_mode_is_unsupported():
    assert not endpoint_contract("websocket")["supported"]


def test_resolution_never_requires_a_management_api():
    assert all(requires_management_api(m) is False for m in ("chat", "text-generation", "custom"))
