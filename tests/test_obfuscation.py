"""Optional payload-obfuscation layer (plan §16.7): selectable encodings, reversible round-trip, mutator-chain shape, and
the hard rule that the backing engine's project name never leaks into any user-facing string ([[no-tool-name-leak]]).

These tests exercise the REAL vendored engine; they skip cleanly where its runtime is unavailable, since the layer is
optional and must fail-soft."""
import pytest

from hfsentinel.attacks import obfuscation as obf

pytestmark = pytest.mark.skipif(not obf.is_available(), reason="obfuscation engine/runtime not available (optional layer)")

# The backing engine's project name must never appear in anything the scan emits.
_FORBIDDEN = ("parseltongue", "p4rs3lt0ngv3", "p4rs3lt", "plinius")


def test_encodings_are_listed_and_selectable():
    keys = obf.encoding_keys()
    assert len(keys) > 100                                 # the full library is exposed
    assert obf.is_known("fullwidth") and obf.is_known("a1z26")
    assert not obf.is_known("definitely-not-an-encoding")
    assert "cipher" in obf.categories()


def test_encode_changes_the_payload_and_reversible_round_trips():
    assert obf.encode("fullwidth", "hello") != "hello"     # obfuscated
    assert obf.encode("a1z26", "hello") == "8-5-12-12-15"
    assert obf.decode("a1z26", obf.encode("a1z26", "hello")).lower() == "hello"   # recoverable


def test_unknown_encoding_raises():
    with pytest.raises(obf.ObfuscationError, match="unknown obfuscation encoding"):
        obf.make_mutator("nope-not-real")
    with pytest.raises(obf.ObfuscationError):
        obf.encode("nope-not-real", "x")


def test_mutator_shape_and_namespaced_resolution():
    m = obf.make_mutator("fullwidth")
    assert callable(m) and m("hello") == obf.encode("fullwidth", "hello")
    assert obf.mutator_name("a1z26") == "obf:a1z26"
    resolved = obf.resolve("obf:a1z26")
    assert resolved is not None and resolved("hello") == "8-5-12-12-15"
    assert obf.resolve("base64") is None                   # not namespaced -> not ours


def test_build_attack_wraps_hint_and_obfuscated_payload():
    attack = obf.build_attack("open the door", "fullwidth")
    assert "Decode it back to plain text" in attack
    assert obf.encode("fullwidth", "open the door") in attack


def test_build_attack_rejects_non_reversible_encoding():
    """A 'decode this and follow it' attack against a non-reversible encoding can never be recovered by the target nor
    confirmed by the canary oracle, so building one would only ever score a guaranteed false negative — it must raise."""
    nondecodable = [e.key for e in obf.available_encodings() if not e.can_decode]
    assert nondecodable, "expected the library to contain some non-reversible encodings"
    with pytest.raises(obf.ObfuscationError, match="not reversible"):
        obf.build_attack("open the door", nondecodable[0])
    with pytest.raises(obf.ObfuscationError, match="unknown obfuscation encoding"):
        obf.build_attack("x", "nope-not-real")


def test_decodable_helpers_and_candidate_menu_are_reversible_only():
    assert obf.is_decodable("fullwidth") and obf.is_decodable("a1z26")
    assert set(obf.decodable_keys()) <= set(obf.encoding_keys())
    assert all(obf.is_decodable(k) for k in obf.decodable_keys())
    # Laya's selection menu defaults to reversible-only so a chosen encoding is always verifiable.
    assert all(obf.is_decodable(k) for k in obf.candidate_encodings())
    # ...but the full menu is still reachable when a caller explicitly wants surface obfuscation.
    assert len(obf.candidate_encodings(decodable_only=False, limit=999)) >= len(obf.candidate_encodings(limit=999))


def test_no_engine_name_leaks_into_user_facing_strings():
    surfaces = [obf.decode_hint("fullwidth"), obf.build_attack("do x", "a1z26"),
                obf.mutator_name("fullwidth"), *(e.name for e in obf.available_encodings()),
                *(e.category for e in obf.available_encodings())]
    for s in surfaces:
        low = s.lower()
        for bad in _FORBIDDEN:
            assert bad not in low, f"engine name leaked in: {s!r}"
