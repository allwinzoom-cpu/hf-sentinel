# Security Policy

## Reporting a vulnerability in HF-Sentinel

Report suspected vulnerabilities in this tool privately to the maintainers (do not open a public issue). Include
affected version, reproduction steps, and impact. We acknowledge within 5 business days.

## Responsible disclosure of findings produced by HF-Sentinel

- **Authorized targets only.** Scan only models/endpoints you own or have written permission to test. Third-party
  scans need a written scope reference.
- **Disclosure window:** 90 days by default for Critical/High findings, coordinated with the model/endpoint owner.
- **Package hallucination (H1):** report hallucinated package names to the deployer and, where appropriate, the
  registry. **Never register them** and never publish a list that hands attackers a ready slopsquatting target.
- **Evidence handling:** reports store evidence hashes and redacted excerpts by default. Full transcripts are opt-in
  (`--save-transcripts`) and must be kept access-controlled.

## Ethics note

HF-Sentinel is an offensive testing tool. Its attack library is versioned and access-controlled; high-severity
modules are not exposed in the public Space. Do not use it to attack systems you do not control, to generate harmful
content for use outside the test, or to evade detection on third-party systems. Secrets (e.g. HF tokens) are read
from the environment or a secret manager, never committed, and never logged.
