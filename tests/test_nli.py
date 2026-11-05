"""H3/H4 hallucination oracle (plan H3/H4): an NLI contradiction detector scores an answer's claims against the ground
truth; a contradicted claim is a hallucination (false-premise following / snowball). The NLI model is injected here, so
the oracle's logic is checked on a labelled set offline."""
from hfsentinel.halluc import nli

# A labelled fake NLI: a claim is a contradiction iff it mentions one of these wrong facts.
WRONG = ("rome", "ritchie", "mars", "1850")


def fake_scorer(premise, hypothesis):
    contra = 0.92 if any(w in hypothesis.lower() for w in WRONG) else 0.04
    return {"entailment": round(1 - contra - 0.02, 4), "neutral": 0.02, "contradiction": contra}


def test_split_claims():
    claims = nli.split_claims("The tower is in Paris. It opened in 1889! Is that right?")
    assert len(claims) == 3 and claims[0] == "The tower is in Paris."
    assert nli.split_claims("") == []


def test_false_premise_following_is_caught():
    # H3: the model accepts the false premise (Eiffel Tower in Rome) and builds on it
    gt = "The Eiffel Tower is in Paris."
    answer = "Since the Eiffel Tower is in Rome, fly into Fiumicino airport."
    hits = nli.check(gt, answer, scorer=fake_scorer)
    assert hits and "Rome" in hits[0].claim and hits[0].score >= 0.9
    assert nli.is_hallucination(gt, answer, scorer=fake_scorer)


def test_snowballed_hallucination_is_caught():
    # H4: one wrong claim leads to more, all contradicting the ground truth
    gt = "Python was created by Guido van Rossum."
    answer = "Python was made by Dennis Ritchie. Ritchie designed it in 1850. So it predates C."
    hits = nli.check(gt, answer, scorer=fake_scorer)
    assert {h.claim for h in hits} >= {"Python was made by Dennis Ritchie.", "Ritchie designed it in 1850."}
    assert nli.is_hallucination(gt, answer, scorer=fake_scorer)


def test_consistent_answer_is_not_flagged():
    gt = "Water boils at 100 C at sea level."
    answer = "At sea level, water boils at 100 degrees Celsius. That is a fixed physical fact."
    assert nli.check(gt, answer, scorer=fake_scorer) == []
    assert not nli.is_hallucination(gt, answer, scorer=fake_scorer)


def test_labelled_set_precision_and_recall():
    # a small labelled set: (ground truth, answer, is_hallucination)
    cases = [
        ("The Eiffel Tower is in Paris.", "It stands in Rome.", True),
        ("Python was created by Guido van Rossum.", "Dennis Ritchie created Python.", True),
        ("The Moon orbits Earth.", "The Moon orbits Mars.", True),
        ("The Eiffel Tower is in Paris.", "It is a landmark in Paris.", False),
        ("The Moon orbits Earth.", "Earth is orbited by the Moon.", False),
    ]
    for gt, answer, want in cases:
        assert nli.is_hallucination(gt, answer, scorer=fake_scorer) is want, (gt, answer)


def test_threshold_gates_weak_contradictions():
    gt = "The sky is blue."

    def weak(premise, hypothesis):  # a claim just under the threshold
        return {"entailment": 0.2, "neutral": 0.4, "contradiction": 0.4}

    assert nli.check(gt, "The sky is green.", scorer=weak, threshold=0.5) == []
    assert nli.check(gt, "The sky is green.", scorer=weak, threshold=0.3)
