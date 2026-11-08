"""Origin-bound credential handles (plan LSCAN-020): a secret is sent only to its bound origin, never forwarded to a new
one, never shown in a repr, and redactable from logs/errors."""
from hfsentinel.targets import credentials as cr


def test_credential_is_sent_only_to_its_bound_origin():
    c = cr.Credential.for_url("sk-secret", "https://api.example.com/v1/x", header="x-api-key", scheme="")
    assert cr.auth_for(c, "https://api.example.com/v1/other") == {"x-api-key": "sk-secret"}   # same origin -> sent
    assert cr.auth_for(c, "https://evil.example.com/v1/x") == {}                               # different host -> withheld
    assert cr.auth_for(c, "http://api.example.com/v1/x") == {}                                 # different scheme -> withheld


def test_bearer_scheme_and_empty_value():
    c = cr.Credential.for_url("tok", "https://h/v1", header="authorization", scheme="Bearer")
    assert cr.auth_for(c, "https://h/v1") == {"authorization": "Bearer tok"}
    empty = cr.Credential.for_url("", "https://h/v1")
    assert cr.auth_for(empty, "https://h/v1") == {}                                            # no value -> nothing sent


def test_value_is_not_in_repr_and_is_redacted():
    c = cr.Credential.for_url("hf_SECRETTOKEN", "https://huggingface.co/v1")
    assert "hf_SECRETTOKEN" not in repr(c)                                                     # secret hidden in repr
    assert cr.redact("error: used hf_SECRETTOKEN here", c) == "error: used [REDACTED] here"


def test_origin_of_normalizes_default_ports():
    assert cr.origin_of("https://H.example.com/path") == "https://h.example.com:443"
    assert cr.origin_of("not-a-url") == ""
