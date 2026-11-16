"""Per-category remediation guidance for confirmed findings.

A scanner that only says *what* broke is half a product; an operator needs *what to do about it*. This maps each catalog
category to concise, standards-grounded mitigation guidance (OWASP GenAI LLM Top 10, 2025) — surfaced in the SARIF
``rule.help``/``helpUri`` (so GitHub code scanning shows it on the alert) and in the console finding drill-down.

The guidance is defensive, general, and self-contained: it names no scanning tool (no-tool-name-leak) and prescribes
controls on the *defender's* system, never attack instructions. It is keyed by the single-letter catalog category, which
every ``catalog_id`` begins with, so a finding maps to its remediation by ``catalog_id[0]``.
"""
from __future__ import annotations

_OWASP = "https://genai.owasp.org/llm-top-10/"

# category letter -> remediation. `owasp` is the primary OWASP LLM Top 10 risk the category maps to; `steps` are concrete
# defender-side controls; `reference` is the stable OWASP GenAI Top 10 page.
REMEDIATION: dict[str, dict] = {
    "A": {
        "title": "Prompt Injection",
        "owasp": "LLM01",
        "summary": ("Untrusted content (user input, retrieved documents, tool results) was able to steer the model's "
                    "behaviour as if it were a trusted instruction."),
        "steps": [
            ("Treat all user-supplied and retrieved content as untrusted data, never as instructions; keep a clear "
             "privilege boundary between the trusted system prompt and everything else."),
            "Constrain and validate the output: enforce an expected format/schema and reject responses that deviate.",
            ("Block data exfiltration from output — strip or deny outbound links, markdown images and auto-rendered "
             "content pointing at untrusted hosts, and allowlist any host the client will fetch."),
            ("Add independent input/output guardrails (e.g. an injection classifier) rather than relying on the model "
             "to police itself, and decode obfuscated or hidden-Unicode input before inspection."),
        ],
        "reference": _OWASP,
    },
    "B": {
        "title": "Jailbreak / Policy Bypass",
        "owasp": "LLM01",
        "summary": "A crafted prompt bypassed the model's safety policy and elicited disallowed behaviour.",
        "steps": [
            ("Layer defences: harden the system prompt AND run an independent output-moderation classifier — a single "
             "model-level guardrail is not sufficient."),
            ("Normalize and decode input (base64/encodings, low-resource languages, many-shot padding) before "
             "moderation so an obfuscated request is judged on its decoded meaning."),
            ("Monitor and rate-limit multi-turn conversations; reset or escalate on repeated policy-violation signals "
             "(gradual escalation / crescendo)."),
            "Keep safety classifiers and jailbreak signatures current, and red-team continuously against new patterns.",
        ],
        "reference": _OWASP,
    },
    "C": {
        "title": "Sensitive Information Disclosure",
        "owasp": "LLM02",
        "summary": ("The model revealed secret or sensitive data (credentials, system-prompt content, private context) "
                    "it had access to."),
        "steps": [
            ("Never place secrets, credentials or privileged system-prompt content in the model context; fetch them at "
             "use time through tools with least privilege, and keep them out of prompts and logs."),
            ("Apply output filtering / DLP for secret-shaped patterns, and rotate any credential that appears in output "
             "— treat a single leak as a compromised secret."),
            "Segregate tenant and session data so one request cannot reach another's context.",
            "Do not train or fine-tune on sensitive data without scrubbing and access controls.",
        ],
        "reference": _OWASP,
    },
    "D": {
        "title": "Excessive Agency / Tool Abuse",
        "owasp": "LLM06",
        "summary": "Model output was able to drive actions or tools beyond what the task required.",
        "steps": [
            "Grant tools the minimum capability needed; avoid open-ended execution and destructive actions by default.",
            "Require human approval for high-impact or irreversible operations.",
            ("Validate and authorize every tool call server-side against the acting user's permissions, not the model's "
             "request."),
        ],
        "reference": _OWASP,
    },
    "E": {
        "title": "Improper Output Handling",
        "owasp": "LLM05",
        "summary": ("Model output flowed into a downstream sink (code execution, a query, a page) without being treated "
                    "as untrusted, enabling injection or resource abuse."),
        "steps": [
            ("Treat model output as untrusted input to every downstream system: never exec/eval, render or query with "
             "it unvalidated."),
            ("Use context-aware output encoding, parameterized queries, and sandboxing for any generated code; enforce "
             "an output schema and reject anything off-schema."),
            "Bound tokens and cost per request and rate-limit callers to prevent resource-exhaustion / denial-of-wallet.",
        ],
        "reference": _OWASP,
    },
    "H": {
        "title": "Misinformation / Hallucination",
        "owasp": "LLM09",
        "summary": "The model produced confident but unsupported or fabricated content.",
        "steps": [
            "Ground responses in retrieval with citations, and require source attribution for factual claims.",
            ("Add verification or human review for high-stakes outputs, and communicate uncertainty rather than "
             "asserting unsupported facts."),
            "Constrain scope: decline or defer when the model lacks grounded information.",
        ],
        "reference": _OWASP,
    },
}


def for_category(category: str) -> dict | None:
    """Remediation for a single-letter catalog category (``"A"``…), or None if unknown."""
    return REMEDIATION.get((category or "").strip()[:1].upper() or "\0")


def for_catalog_id(catalog_id: str) -> dict | None:
    """Remediation for a ``catalog_id`` (``"A1"``, ``"E2"`` …), keyed by its leading category letter."""
    return for_category((catalog_id or "")[:1])
