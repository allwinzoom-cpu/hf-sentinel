"""Report writers: JSON, SARIF 2.1.0, Markdown.

Every string that can come from outside the tool (target text, target ref, scope fields) is encoded for its sink:
JSON/SARIF by the JSON encoder, Markdown by escaping every inline-markup character and printing excerpts inside a
code fence longer than any backtick run they contain. HTML output (and the real-browser check) is plan 16.5.

SARIF follows GitHub code-scanning's upload rules: each rule has `security` in its tags and a `security-severity`,
each result one physical location (a black-box target has no source file, so results anchor to the scan config) plus
the target as a logical location, and stable `partialFingerprints` (target + technique) so re-scans update alerts.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
from pathlib import Path, PurePosixPath

from hfsentinel.attacks.catalog import Catalog, load_catalog
from hfsentinel.engines.nondisclosure import scrub as _nd_scrub
from hfsentinel.report.build import Report

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SECURITY_SEVERITY = {"Critical": "9.5", "High": "8.0", "Medium": "5.5", "Low": "2.0", "Info": "0.5"}
SARIF_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
MAX_TAGS = 10
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|~>])")
# A restrictive CSP so the report is inert even if an escape were ever missed: no scripts, no images (defeats
# markdown/HTML-image exfil, 16.5/A5/E5), no external loads of any kind; only our own inline <style> is allowed.
_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
_HTML_STYLE = ("body{font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a}"
               "h1,h2,h3{line-height:1.25}table{border-collapse:collapse;width:100%;margin:.5rem 0}"
               "th,td{border:1px solid #ccc;padding:.3rem .5rem;text-align:left;vertical-align:top}"
               "th{background:#f3f3f3}code,pre{background:#f6f6f6;border:1px solid #ddd;border-radius:3px}"
               "pre{padding:.6rem;overflow-x:auto;white-space:pre-wrap;word-break:break-word}"
               ".sev-Critical,.sev-High{color:#b00020;font-weight:600}.muted{color:#666}")


def _printable(text: object, limit: int = 300) -> str:
    s = "".join(ch if ch.isprintable() else " " for ch in str(text))
    return s if len(s) <= limit else s[: limit - 1] + "…"


def md(text: object, limit: int = 300) -> str:
    """Inline Markdown-safe text: entities and every markup character escaped; no line breaks survive."""
    s = _printable(text, limit).replace("&", "&amp;").replace("<", "&lt;")
    return _MD_SPECIAL.sub(r"\\\1", s)


def h(text: object, limit: int = 300) -> str:
    """HTML-safe text for element and attribute contexts: `&<>\"'` escaped, non-printables dropped (16.5)."""
    return html.escape(_printable(text, limit), quote=True)


def md_fence(text: object, limit: int = 400) -> str:
    s = _printable(text, limit)
    longest = max((len(m) for m in re.findall(r"`+", s)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{s}\n{fence}"


def to_json(report: Report) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=1, ensure_ascii=False) + "\n"


def sarif_anchor(config_path: Path | None) -> str:
    """Repo-relative POSIX path for result locations: the scan config when it is relative and inside the tree."""
    if config_path is not None and not config_path.is_absolute():
        p = PurePosixPath(config_path.as_posix())
        if ".." not in p.parts and str(p) not in ("", "."):
            return str(p)
    return "sentinel.yaml"


def to_sarif(report: Report, *, anchor: str = "sentinel.yaml", catalog: Catalog | None = None) -> str:
    by_id = (catalog or load_catalog()).by_id()
    ref = report.target["ref"]
    rule_ids = sorted({f.catalog_id for f in report.findings}, key=lambda i: (i[0], int(i[1:])))
    index = {cid: n for n, cid in enumerate(rule_ids)}
    worst, oracle_name = {}, {}
    for f in report.findings:
        worst[f.catalog_id] = f.severity
        oracle_name[f.catalog_id] = f.oracle.name  # the neutral oracle that actually confirmed it (16.16)
    rules = []
    for cid in rule_ids:
        a = by_id[cid]
        tags = ["security", "llm", *a.owasp, *a.atlas][:MAX_TAGS]
        rules.append({
            "id": f"hfsentinel/{cid}", "name": re.sub(r"[^A-Za-z0-9]+", "", a.name.title()) or cid,
            "shortDescription": {"text": f"{cid} {a.name}"},
            # The catalog's oracle prose can name upstream judges; report the neutral oracle that ran, scrubbed (16.16).
            "fullDescription": {"text": _nd_scrub(f"{a.name} (catalog {cid}). Success oracle: {oracle_name[cid]}.")},
            "help": {"text": f"{a.name}: confirmed by a deterministic oracle. OWASP {', '.join(a.owasp)}; "
                             f"MITRE ATLAS {', '.join(a.atlas)}. The HF-Sentinel report has the rate, confidence "
                             "interval and evidence hash."},
            "properties": {"tags": tags, "security-severity": SECURITY_SEVERITY[worst[cid]], "precision": "high"}})
    results = []
    for f in report.findings:
        lo, hi = f.asr_ci95
        stable = hashlib.sha256(f"{ref}\0{f.catalog_id}".encode()).hexdigest()
        results.append({
            "ruleId": f"hfsentinel/{f.catalog_id}", "ruleIndex": index[f.catalog_id],
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": _printable(
                f"{f.technique}: {f.successes}/{f.trials} trials succeeded (ASR {f.asr:.0%}, 95% CI "
                f"{lo:.0%}-{hi:.0%}) against {ref}. Severity {f.severity}.", 1000)},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": anchor},
                                     "region": {"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 2}},
                "logicalLocations": [{"name": _printable(ref, 300), "kind": "resource"}]}],
            "partialFingerprints": {"primaryLocationLineHash": f"{stable[:16]}:1", "hfsentinel/v1": stable},
            "properties": {"severity": f.severity, "asr": f.asr, "asr_ci95": [lo, hi], "trials": f.trials,
                           "successes": f.successes, "evidence_sha256": f.evidence.hash, "finding_id": f.finding_id,
                           "evidence_level": f.evidence_level}})  # LSCAN-002: what the oracle actually demonstrated
    doc = {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "HF-Sentinel", "version": report.tool["version"],
                            "semanticVersion": report.tool["version"], "rules": rules}},
        "automationDetails": {"id": f"hfsentinel/{stable_slug(ref)}/"},
        "results": results,
        "properties": {"grade": report.grade.get("overall"), "report_sha256": report.report_sha256,
                       "build": report.tool["build"],
                       "frameworks": report.frameworks.get("frameworks"),  # LSCAN-006: pinned editions/revisions
                       "coverage_claim": report.frameworks.get("coverage_claim")}}]}
    return json.dumps(doc, indent=1, ensure_ascii=False) + "\n"


def stable_slug(ref: str) -> str:
    return hashlib.sha256(ref.encode()).hexdigest()[:12]


def _pct(v: float | None) -> str:
    return "–" if v is None else f"{v:.0%}"


def _ci(ci) -> str:
    return "–" if ci is None else f"{ci[0]:.0%}–{ci[1]:.0%}"


def to_markdown(report: Report) -> str:
    g, t, run = report.grade, report.target, report.run
    out = ["# HF-Sentinel security report", "",
           f"**Target:** {md(t['ref'])} · model {md(t.get('resolved_model') or '–')}",
           (f"**Grade:** {g.get('overall') or 'not graded'} — {md(g.get('reason', ''))}; covers categories "
           f"{', '.join(g.get('covered') or []) or 'none'}"),
           (f"**Run:** {md(run['run_id'])} · {md(run['started_at'])} → {md(run['finished_at'])} · profile "
           f"{md(run['profile'])} · {run['trials']} trials at temperature {run['temperature']}{' (+1 at 0)' if run['temperature'] else ''} · ASR@k "
           f"k = {run['asr_k']}"),
           (f"**Build:** HF-Sentinel {md(report.tool['version'])} · {md(report.tool['build'][:23])}… · report sha256 "
           f"{md(report.report_sha256)}"), ""]
    s = report.scope
    out += ["## Authorization", ""]
    if s:
        line = (f"In scope via {md(s.source)} · reference {md(s.reference)} · authorized by "
                f"{md(s.authorized_by)}")
        if s.signer:
            line += (f" · signed by {md(s.signer)} ({md(s.key_fingerprint)}), valid {md(s.granted)} to "
                     f"{md(s.expires)}, scope sha256 {md(s.scope_sha256)}")
        out += [line, f"Matched {md(s.matched)} · checked {md(s.checked_at)}"]
    else:
        out.append("No scope attestation recorded.")
    out += ["", "## Category scores", "", "| Category | Tested | Score | Grade | Findings |", "|---|---|---|---|---|"]
    names = {"A": "Prompt injection", "B": "Jailbreak / policy bypass", "C": "Information disclosure",
             "D": "Agentic & tool abuse", "E": "Output handling & resource abuse", "H": "Hallucination"}
    for c, v in g["categories"].items():
        out.append(f"| {c} · {names[c]} | {'yes' if v['tested'] else 'not tested'} | "
                   f"{'–' if v['score'] is None else v['score']} | {v['grade'] or '–'} | {v['findings']} |")
    out += ["", "## Findings (confirmed)", ""]
    if not report.findings:
        out.append("No confirmed findings.")
    for f in report.findings:
        out += [f"### {md(f.catalog_id)} · {md(f.technique)} — {f.severity}", "",
                f"- ASR {_pct(f.asr)} ({f.successes}/{f.trials}), 95% CI {_ci(f.asr_ci95)} · effort {f.effort}",
                f"- baseline (un-attacked) {_pct(f.baseline_asr)} · lift {_pct(f.lift)} (graded on lift)",
                f"- OWASP {md(', '.join(f.owasp))} · MITRE ATLAS {md(', '.join(f.atlas))}",
                f"- Oracle: {md(f.oracle.kind)} / {md(f.oracle.name)} · evidence sha256 {md(f.evidence.hash or '–')}",
                f"- Evidence established: {md(f.evidence_level)} (what this oracle actually demonstrated — LSCAN-002)"]
        if f.evidence.redacted_excerpt:
            out += ["- Redacted excerpt (target output, shown inert):", "", md_fence(f.evidence.redacted_excerpt)]
        out.append("")
    out += ["## Techniques", "",
            "| ID | Technique | Disposition | Trials | Hits | ASR | Baseline | Lift | 95% CI | temp 0 | Severity |",
            "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in report.techniques:
        t0 = "–" if r.temp0_hit is None else ("hit" if r.temp0_hit else "no")
        out.append(f"| {r.catalog_id} | {md(r.name, 60)} | {r.disposition}"
                   f"{' (' + md(r.outcome) + ')' if r.outcome else ''} | {r.trials or '–'} | {r.hits if r.trials else '–'} "
                   f"| {_pct(r.asr)} | {_pct(r.baseline_asr)} | {_pct(r.lift)} | {_ci(r.asr_ci95)} | {t0} | {r.severity or '–'} |")
    held = [r for r in report.techniques if r.disposition not in ("run", "stopped")]
    if held:
        out += ["", "### Not run", ""]
        out += [f"- {r.catalog_id} ({r.disposition}): {md(r.reason, 200)}" for r in held]
    if report.campaign:
        c = report.campaign
        out += ["", "## Campaign", "",
                (f"{c['attack_requests']} attack requests vs {c['exhaustive_requests']} exhaustive "
                f"({c.get('requests_saved', 0)} fewer).")]
        if c.get("judge_calls_made") or c.get("judge_calls_saved"):
            total = c.get("judge_calls_made", 0) + c.get("judge_calls_saved", 0)
            out.append(f"System-1 triage saved {c.get('judge_calls_saved', 0)} of {total} System-2 judge calls · "
                       f"Laya-vs-judge agreement {c.get('triage_agreement')}.")
        out += ["", "| Stage | Technique | By | Action | Why |", "|---|---|---|---|---|"]
        out += [f"| {md(d['stage'], 8)} | {md(d['catalog_id'], 8)} | {md(d.get('source', 'campaign'), 12)} | "
                f"{md(d['action'], 40)} | {md(d['why'], 120)} |" for d in c["decisions"]]
        if c.get("escalations"):
            out += ["", "### Depth escalation (S4)", "", "| ID | Mutator | Hits | Confirmed |", "|---|---|---|---|"]
            out += [f"| {md(e['id'], 8)} | {md(e['mutator'], 12)} | {e['hits']}/{e['trials']} | "
                    f"{'yes' if e['confirmed'] else 'no'} |" for e in c["escalations"]]
    led = report.ledger
    cost = led.get("cost_reported_usd", 0) + led.get("cost_priced_usd", 0)
    out += ["", "## Cost", "",
            (f"{led.get('requests', 0)} requests · {led.get('prompt_tokens', 0)} prompt + "
            f"{led.get('completion_tokens', 0)} completion tokens · ${cost:.4f} "
            f"(+${led.get('cost_estimated_usd', 0):.4f} estimated) · {led.get('throttled', 0)} throttled · "
            f"{led.get('errors', 0)} errors"), "", "## Limitations", ""]
    out += [f"- {md(x, 400)}" for x in report.limitations]
    return "\n".join(out) + "\n"


_CAT_NAMES = {"A": "Prompt injection", "B": "Jailbreak / policy bypass", "C": "Information disclosure",
              "D": "Agentic & tool abuse", "E": "Output handling & resource abuse", "H": "Hallucination"}


def to_html(report: Report) -> str:
    """Self-contained HTML report (plan 16.5). Every target-derived string is HTML-escaped (element and attribute
    safe), excerpts are shown inert inside <pre>, and a restrictive CSP blocks scripts and all external loads —
    E1/E5/A5 deliberately elicit XSS and image-exfil payloads, so the sink itself must render them harmless."""
    g, t, run = report.grade, report.target, report.run
    temp0 = " (+1 at 0)" if run["temperature"] else ""
    rows = [
        '<!doctype html>', '<html lang="en"><head><meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<title>HF-Sentinel security report</title>', f'<style>{_HTML_STYLE}</style></head><body>',
        '<h1>HF-Sentinel security report</h1>',
        f'<p><strong>Target:</strong> {h(t["ref"])} · model {h(t.get("resolved_model") or "–")}</p>',
        (f'<p><strong>Grade:</strong> {h(g.get("overall") or "not graded")} — {h(g.get("reason", ""))}; covers '
         f'{h(", ".join(g.get("covered") or []) or "none")}</p>'),
        (f'<p><strong>Run:</strong> {h(run["run_id"])} · {h(run["started_at"])} → {h(run["finished_at"])} · profile '
         f'{h(run["profile"])} · {run["trials"]} trials at temperature {h(run["temperature"])}{temp0} · ASR@k '
         f'k = {h(run["asr_k"])}</p>'),
        (f'<p class="muted"><strong>Build:</strong> HF-Sentinel {h(report.tool["version"])} · '
         f'{h(report.tool["build"][:23])}… · report sha256 {h(report.report_sha256)}</p>'),
        '<h2>Authorization</h2>']
    s = report.scope
    if s:
        line = (f'In scope via {h(s.source)} · reference {h(s.reference)} · authorized by {h(s.authorized_by)}')
        if s.signer:
            line += (f' · signed by {h(s.signer)} ({h(s.key_fingerprint)}), valid {h(s.granted)} to {h(s.expires)}, '
                     f'scope sha256 {h(s.scope_sha256)}')
        rows += [f'<p>{line}</p>', f'<p class="muted">Matched {h(s.matched)} · checked {h(s.checked_at)}</p>']
    else:
        rows.append('<p>No scope attestation recorded.</p>')
    rows += ['<h2>Category scores</h2>', ('<table><thead><tr><th>Category</th><th>Tested</th><th>Score</th>'
             '<th>Grade</th><th>Findings</th></tr></thead><tbody>')]
    for c, v in g["categories"].items():
        rows.append(f'<tr><td>{h(c)} · {h(_CAT_NAMES.get(c, c))}</td><td>{"yes" if v["tested"] else "not tested"}</td>'
                    f'<td>{"–" if v["score"] is None else h(v["score"])}</td><td>{h(v["grade"] or "–")}</td>'
                    f'<td>{v["findings"]}</td></tr>')
    rows += ['</tbody></table>', '<h2>Findings (confirmed)</h2>']
    if not report.findings:
        rows.append('<p>No confirmed findings.</p>')
    for f in report.findings:
        rows += [f'<h3 class="sev-{h(f.severity)}">{h(f.catalog_id)} · {h(f.technique)} — {h(f.severity)}</h3>',
                 '<ul>',
                 f'<li>ASR {_pct(f.asr)} ({f.successes}/{f.trials}), 95% CI {_ci(f.asr_ci95)} · effort {h(f.effort)}</li>',
                 f'<li>baseline (un-attacked) {_pct(f.baseline_asr)} · lift {_pct(f.lift)} (graded on lift)</li>',
                 f'<li>OWASP {h(", ".join(f.owasp))} · MITRE ATLAS {h(", ".join(f.atlas))}</li>',
                 (f'<li>Oracle: {h(f.oracle.kind)} / {h(f.oracle.name)} · evidence sha256 '
                  f'{h(f.evidence.hash or "–")}</li>'), '</ul>']
        if f.evidence.redacted_excerpt:
            rows += ['<p class="muted">Redacted excerpt (target output, shown inert):</p>',
                     f'<pre>{h(f.evidence.redacted_excerpt, 400)}</pre>']
    rows += ['<h2>Techniques</h2>',
             ('<table><thead><tr><th>ID</th><th>Technique</th><th>Disposition</th><th>Trials</th>'
              '<th>Hits</th><th>ASR</th><th>Baseline</th><th>Lift</th><th>95% CI</th><th>temp 0</th><th>Severity</th>'
              '</tr></thead><tbody>')]
    for r in report.techniques:
        t0 = "–" if r.temp0_hit is None else ("hit" if r.temp0_hit else "no")
        disp = h(r.disposition) + (f' ({h(r.outcome)})' if r.outcome else '')
        rows.append(f'<tr><td>{h(r.catalog_id)}</td><td>{h(r.name, 60)}</td><td>{disp}</td>'
                    f'<td>{r.trials or "–"}</td><td>{r.hits if r.trials else "–"}</td><td>{_pct(r.asr)}</td>'
                    f'<td>{_pct(r.baseline_asr)}</td><td>{_pct(r.lift)}</td><td>{_ci(r.asr_ci95)}</td>'
                    f'<td>{t0}</td><td>{h(r.severity or "–")}</td></tr>')
    rows.append('</tbody></table>')
    held = [r for r in report.techniques if r.disposition not in ("run", "stopped")]
    if held:
        rows += ['<h3>Not run</h3>', '<ul>']
        rows += [f'<li>{h(r.catalog_id)} ({h(r.disposition)}): {h(r.reason, 200)}</li>' for r in held]
        rows.append('</ul>')
    if report.campaign:
        c = report.campaign
        rows += ['<h2>Campaign</h2>',
                 (f'<p>{c["attack_requests"]} attack requests vs {c["exhaustive_requests"]} exhaustive '
                  f'({c.get("requests_saved", 0)} fewer).</p>')]
        if c.get("judge_calls_made") or c.get("judge_calls_saved"):
            total = c.get("judge_calls_made", 0) + c.get("judge_calls_saved", 0)
            rows.append(f'<p>System-1 triage saved {c.get("judge_calls_saved", 0)} of {total} System-2 judge calls · '
                        f'Laya-vs-judge agreement {h(c.get("triage_agreement"))}.</p>')
        rows += [('<table><thead><tr><th>Stage</th><th>Technique</th><th>By</th><th>Action</th><th>Why</th></tr>'
                  '</thead><tbody>')]
        rows += [f'<tr><td>{h(d["stage"], 8)}</td><td>{h(d["catalog_id"], 8)}</td>'
                 f'<td>{h(d.get("source", "campaign"), 12)}</td><td>{h(d["action"], 40)}</td>'
                 f'<td>{h(d["why"], 120)}</td></tr>' for d in c["decisions"]]
        rows.append('</tbody></table>')
        if c.get("escalations"):
            rows += ['<h3>Depth escalation (S4)</h3>',
                     '<table><thead><tr><th>ID</th><th>Mutator</th><th>Hits</th><th>Confirmed</th></tr></thead><tbody>']
            rows += [f'<tr><td>{h(e["id"], 8)}</td><td>{h(e["mutator"], 12)}</td><td>{e["hits"]}/{e["trials"]}</td>'
                     f'<td>{"yes" if e["confirmed"] else "no"}</td></tr>' for e in c["escalations"]]
            rows.append('</tbody></table>')
    led = report.ledger
    cost = led.get("cost_reported_usd", 0) + led.get("cost_priced_usd", 0)
    rows += ['<h2>Cost</h2>',
             (f'<p>{led.get("requests", 0)} requests · {led.get("prompt_tokens", 0)} prompt + '
              f'{led.get("completion_tokens", 0)} completion tokens · ${cost:.4f} '
              f'(+${led.get("cost_estimated_usd", 0):.4f} estimated) · {led.get("throttled", 0)} throttled · '
              f'{led.get("errors", 0)} errors</p>'),
             '<h2>Limitations</h2>', '<ul>']
    rows += [f'<li>{h(x, 400)}</li>' for x in report.limitations]
    rows += ['</ul>', '</body></html>', '']
    return "\n".join(rows)


def write_transcripts(out_dir: Path, run_id: str, transcripts_by_id: dict[str, list[dict]]) -> Path | None:
    """`--save-transcripts` (16.17): write full transcripts for confirmed findings only, to one new 0600 file. The
    caller passes only confirmed findings' transcripts; nothing is written when there are none."""
    transcripts_by_id = {cid: t for cid, t in transcripts_by_id.items() if t}
    if not transcripts_by_id:
        return None
    out_dir = Path(out_dir)
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = out_dir / f"hfsentinel-{run_id}.transcripts.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"run_id": run_id, "note": "full transcripts for confirmed findings only (16.17/D-015)",
                   "transcripts": transcripts_by_id}, fh, ensure_ascii=False, indent=1)
    return path


def write(report: Report, out_dir: Path, formats: list[str], *, anchor: str = "sentinel.yaml") -> list[Path]:
    """Write each requested format as a new 0600 file (never overwrite, never follow a symlink)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if out_dir.is_symlink() or not out_dir.is_dir():
        raise OSError("report directory is not a plain directory")
    from hfsentinel.report.model_card import model_card  # local import: model_card imports render helpers
    renderers = {"json": ("json", to_json), "sarif": ("sarif", lambda r: to_sarif(r, anchor=anchor)),
                 "md": ("md", to_markdown), "html": ("html", to_html), "card": ("modelcard.md", model_card)}
    stem = f"hfsentinel-{report.run['run_id']}"
    written = []
    for fmt in formats:
        ext, render = renderers[fmt]
        path = out_dir / f"{stem}.{ext}"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(render(report))
        written.append(path)
    return written
