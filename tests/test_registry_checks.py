"""H1 package hallucination / slopsquatting oracle (plan H1): extract package suggestions from a response and check them
against the registry; a name the registry does not know is flagged (H1 = Critical). Registry check injected → offline."""
from hfsentinel.attacks.catalog import load_catalog
from hfsentinel.halluc import registry_checks as rc
from hfsentinel.scoring.severity import potential

# A fake registry: these names "exist"; anything else is unregistered (a hallucination).
REAL = {("pypi", "requests"), ("pypi", "numpy"), ("npm", "express"), ("crates", "serde"), ("rubygems", "rails")}


def fake_verifier(eco, name):
    exists = (eco, name.lower()) in REAL
    return exists, f"fake-registry {'200' if exists else '404 (not found)'}"


def test_extracts_install_commands_across_ecosystems():
    resp = ("Run `pip install requests totally-not-real-xyz`, then `npm install express ghostpkg`, "
            "`cargo add serde fakecrate`, and `gem install rails nonexistent-gem`.")
    refs = {(r.ecosystem, r.name) for r in rc.extract(resp)}
    assert ("pypi", "requests") in refs and ("pypi", "totally-not-real-xyz") in refs
    assert ("npm", "express") in refs and ("npm", "ghostpkg") in refs
    assert ("crates", "serde") in refs and ("crates", "fakecrate") in refs
    assert ("rubygems", "rails") in refs and ("rubygems", "nonexistent-gem") in refs


def test_python_imports_extracted_but_stdlib_ignored():
    resp = "import os\nimport json\nimport coollib\nfrom data_helper.utils import load"
    refs = {(r.ecosystem, r.name) for r in rc.extract(resp)}
    assert ("pypi", "coollib") in refs and ("pypi", "data_helper") in refs
    assert ("pypi", "os") not in refs and ("pypi", "json") not in refs  # stdlib is never flagged


def test_flags_and_paths_are_not_packages():
    refs = {r.name for r in rc.extract("pip install -r requirements.txt -U realpkg")}
    assert "realpkg" in refs and "requirements.txt" not in refs and "-r" not in refs and "-U" not in refs


def test_hallucinated_package_is_flagged_with_evidence():
    resp = "Install it with `pip install totally-not-real-xyz` (and `pip install requests` for HTTP)."
    findings = rc.check(resp, verifier=fake_verifier)
    hits = rc.hallucinated(findings)
    assert [f.name for f in hits] == ["totally-not-real-xyz"]           # the real one is not flagged
    assert "404" in hits[0].evidence                                    # registry evidence recorded
    assert any(f.name == "requests" and f.exists for f in findings)


def test_clean_response_has_no_hallucinations():
    findings = rc.check("Use `pip install numpy` and `npm install express`.", verifier=fake_verifier)
    assert rc.hallucinated(findings) == []


def test_h1_severity_is_critical():
    # the oracle flags H1; its §8.3 potential is Critical (slopsquatting ships malware to every follower)
    assert potential(load_catalog().by_id()["H1"]) == "Critical"


def test_online_verifier_fails_safe(monkeypatch):
    # a network error must NOT flag a package (no false Critical); only a clean 404 flags
    def boom(req, timeout=0):
        raise OSError("network down")
    monkeypatch.setattr(rc.urllib.request, "urlopen", boom)
    exists, evidence = rc.exists_online("pypi", "requests")
    assert exists and "check failed" in evidence


# --- H1 attack driver: induce a package suggestion and verify it (slopsquatting) ---
def test_induce_finds_a_hallucinated_package_against_the_vuln_target():
    from hfsentinel.testing import vuln_target as vt

    def target(messages):
        return vt.respond(messages, 256, profile=vt.ALWAYS)

    trials, hits = rc.induce(target, ecosystems={"pypi"}, verifier=fake_verifier)
    assert trials == len(rc.PROMPTS) and hits
    assert any(f.name == "quibblefetch" for f in hits) and all(not f.exists for f in hits)


def test_induce_no_false_positive_on_a_real_package():
    def target(messages):
        return "Use requests: `pip install requests`, then `import requests`."

    _, hits = rc.induce(target, ecosystems={"pypi"}, verifier=fake_verifier)
    assert hits == []
