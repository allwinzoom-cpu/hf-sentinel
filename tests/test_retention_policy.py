"""Reproducibility-compatible evidence retention (plan / LSCAN-033): minimal safe artifacts, replay-level derived from
what's kept, explicit limitation when exact replay is absent, redaction preserves the attack."""
from engines import retention as rt


def test_unconfirmed_keeps_only_the_request_hash():
    r = rt.plan_retention(confirmed=False, transcript_opt_in=True, request_hash="sha256:ab",
                          excerpt="harmful...", mutator_chain=("base64",))
    assert r.request_hash == "sha256:ab" and r.redacted_excerpt == "" and not r.mutator_chain
    assert not r.transcript_encrypted                           # nothing sensitive persisted for an unconfirmed finding


def test_confirmed_keeps_script_and_transcript_only_on_opt_in():
    no_opt = rt.plan_retention(confirmed=True, transcript_opt_in=False, request_hash="h", excerpt="x" * 300,
                               mutator_chain=("leet", "base64"))
    assert no_opt.mutator_chain == ("leet", "base64") and len(no_opt.redacted_excerpt) <= 200
    assert not no_opt.transcript_encrypted and rt.replay_level(no_opt) == "full-script"
    opted = rt.plan_retention(confirmed=True, transcript_opt_in=True, request_hash="h", excerpt="x",
                              mutator_chain=("base64",))
    assert opted.transcript_encrypted and rt.replay_level(opted) == "exact-transcript"


def test_replay_level_and_limitation_and_redaction():
    payload_only = rt.Retained(request_hash="h")
    assert rt.replay_level(payload_only) == "payload-only" and "unavailable" in rt.reproducibility_limitation(payload_only)
    exact = rt.Retained(request_hash="h", transcript_encrypted=True)
    assert rt.reproducibility_limitation(exact) == ""          # exact transcript kept -> no limitation
    assert rt.redaction_preserves_attack("h", payload_only) and not rt.redaction_preserves_attack("other", payload_only)
