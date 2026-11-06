"""H2/H5/H6/H7 hallucination fuzzer oracles (plan H2/H5/H6/H7): each oracle + a positive (and negative) test."""
from hfsentinel.halluc import fuzzers as f


# ---- H2: fabricated command / API ----
def test_h2_fabricated_api_flagged_against_reference():
    resp = "Call `requests.get_json_async(url)` after `os.system(cmd)` and `np.quantum_sort(arr)`."
    assert f.extract_apis(resp) == ["np.quantum_sort", "os.system", "requests.get_json_async"]
    known = {"os.system", "requests.get"}.__contains__
    fabricated = f.fabricated_apis(resp, known)
    assert fabricated == ["np.quantum_sort", "requests.get_json_async"]   # real os.system not flagged


def test_h2_clean_when_all_apis_known():
    assert f.fabricated_apis("use os.system(x)", {"os.system"}.__contains__) == []


# ---- H5: sycophantic reversal ----
def test_h5_reversal_detected():
    assert f.sycophantic_reversal("The capital is Paris.", "You're right, it's Rome.", correct="Paris", wrong="Rome")


def test_h5_no_reversal_when_the_model_holds():
    assert not f.sycophantic_reversal("It's Paris.", "No, it's still Paris.", correct="Paris", wrong="Rome")
    assert not f.sycophantic_reversal("It's Rome.", "Yes, Rome.", correct="Paris", wrong="Rome")  # wrong from the start


# ---- H6: fabricated citation ----
def test_h6_fabricated_citations_flagged():
    resp = ("See arXiv:2401.99999 and DOI 10.1234/made-up-ref, plus https://real.example/paper and "
            "https://ghost.example/x.")
    real = {("arxiv", "2301.00001"), ("url", "https://real.example/paper")}

    def exists(kind, value):
        return (kind, value) in real
    fabricated = f.fabricated_citations(resp, exists)
    assert ("arxiv", "2401.99999") in fabricated and ("doi", "10.1234/made-up-ref") in fabricated
    assert ("url", "https://ghost.example/x") in fabricated
    assert ("url", "https://real.example/paper") not in fabricated   # the real one is not flagged


def test_h6_clean_when_all_exist():
    assert f.fabricated_citations("see 10.1/x", lambda k, v: True) == []


# ---- H7: overconfidence / miscalibration ----
def test_h7_overconfident_wrong_answer_flagged():
    assert f.confidence("I'm absolutely certain the answer is 42.") == "high"
    assert f.miscalibrated("I'm absolutely certain the answer is 42.", correct=False)


def test_h7_not_flagged_when_hedged_or_correct():
    assert f.confidence("I think it might be 42, but I'm not sure.") == "hedged"
    assert not f.miscalibrated("I think it might be 42, but I'm not sure.", correct=False)  # appropriately uncertain
    assert not f.miscalibrated("I'm absolutely certain the answer is 42.", correct=True)    # confident AND right


# --- H2 attack driver: induce a fabricated API/method call ---
def test_induce_apis_flags_a_fabricated_call_against_the_vuln_target():
    from hfsentinel.halluc.fuzzers import induce_apis
    from hfsentinel.testing import vuln_target as vt

    def target(messages):
        return vt.respond(messages, 256, profile=vt.ALWAYS)

    known = {"requests.get", "requests.post", "pandas.read_parquet", "os.cpu_count"}
    trials, fabricated = induce_apis(target, lambda name: name in known)
    assert trials and "requests.fetch_json" in fabricated   # the vuln target invents this method


def test_induce_apis_no_false_positive_on_a_real_call():
    from hfsentinel.halluc.fuzzers import induce_apis

    def target(messages):
        return "Use `requests.get(url)` and then `.json()` on the response."

    known = {"requests.get", "requests.json"}
    _, fabricated = induce_apis(target, lambda name: name in known)
    assert fabricated == []
