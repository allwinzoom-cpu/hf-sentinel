"""Feature negotiation (plan LSCAN-022): a strict baseline probe classifies each generation control by OBSERVED support
— verified / ignored / rejected / unknown — and never guesses support for a control it cannot send or observe."""
from hfsentinel.targets.feature_probe import IGNORED, REJECTED, UNKNOWN, UNPROBED, VERIFIED, negotiate
from hfsentinel.targets.openai_compat import ChatResult, TargetError


class Mock:
    """A target that honours (or ignores/rejects) specific controls, so the probe's classification can be checked."""
    def __init__(self, honor=(), reject=(), error=False):
        self.honor, self.reject, self.error, self.n = set(honor), set(reject), error, 0

    def chat(self, messages, *, max_tokens=256, temperature=0.7, extra=None):
        if self.error:
            raise TargetError("boom")
        extra = extra or {}
        if self.reject & set(extra):
            raise ValueError("refused")
        text, usage = "alpha bravo charlie delta echo", {}
        if "max_tokens" in self.honor:
            usage = {"completion_tokens": 1 if max_tokens <= 1 else 12}
            if max_tokens <= 1:
                text = "alpha"
        if "stop" in extra and "stop" in self.honor:
            for s in extra["stop"]:
                text = text.split(s)[0].strip() if s in text else text
        if "seed" in extra:
            self.n += 1
            text = f"seeded-{extra['seed']}" if "seed" in self.honor else f"rand-{self.n}"
        if extra.get("response_format"):
            text = '{"ok": true}' if "response_format" in self.honor else "no json for you"
        return ChatResult(text=text, model="m", usage=usage)


def test_all_controls_verified_when_honoured():
    r = negotiate(Mock(honor={"max_tokens", "stop", "seed", "response_format"}))
    assert all(r[name]["state"] == VERIFIED for name in ("max_tokens", "stop", "seed", "response_format"))
    assert all(r[name]["probed"] for name in ("max_tokens", "stop", "seed", "response_format"))


def test_silently_ignored_controls_are_detected_not_assumed_supported():
    r = negotiate(Mock(honor=set()))  # accepts every field but honours none
    assert {r[n]["state"] for n in ("max_tokens", "stop", "seed", "response_format")} == {IGNORED}


def test_a_refused_field_is_rejected_not_ignored():
    r = negotiate(Mock(honor={"max_tokens"}, reject={"seed"}))
    assert r["seed"]["state"] == REJECTED and r["max_tokens"]["state"] == VERIFIED


def test_target_error_is_unknown_never_a_false_claim():
    r = negotiate(Mock(error=True))
    assert all(r[name]["state"] == UNKNOWN for name in ("max_tokens", "stop", "seed", "response_format"))


def test_unprobed_controls_are_unknown_with_a_reason_never_guessed():
    r = negotiate(Mock(honor={"max_tokens", "stop", "seed", "response_format"}))
    for name in UNPROBED:
        assert r[name] == {"state": UNKNOWN, "probed": False, "reason": "not negotiated in this build"}
