"""HF-Sentinel Space UI (plan 663/664) — a Gradio app over the *same* scan engine as the CLI.

`run_scan` reuses the exact native campaign path the CLI uses (`resolve_controls` → recon → plan → `run_campaign` →
assemble, via `cli._campaign_report`), so a scan launched from the UI matches the equivalent CLI run **by construction**.
gradio is imported lazily in `build_ui`/`launch`, so it stays a Space-deploy dependency (`requirements/space.in`) and never
enters the core image or the tests.

664: budget is enforced server-side by the Governor (`--budget-*` → `Governor.from_controls`), transcripts are redacted by
default (D-015 — full text is kept only for confirmed findings with `--save-transcripts`), scans are owner-gated
(`authorized`), and the UI serializes them through gradio's queue so one over-budget run cannot starve others.
"""
from __future__ import annotations

from pathlib import Path

from hfsentinel.controls import PROFILES, resolve_controls
from hfsentinel.targets.resolve import parse, resolve

PRESETS: tuple[str, ...] = tuple(PROFILES)
# The UI controls that bind to CLI flags (same names, so resolve_controls treats them identically to a CLI run).
UI_FLAGS: tuple[str, ...] = ("profile", "categories", "trials", "temperature", "max_tokens", "rounds", "concurrency",
                             "budget_usd", "max_requests", "max_minutes", "memorization_refs", "api_reference",
                             "halluc_registries", "check_citations", "check_sycophancy", "check_calibration", "nli_url")


def authorized(token: str | None, owners: tuple[str, ...]) -> bool:
    """664 auth: only a configured owner token may launch a scan. Empty `owners` means auth is not enforced (local use)."""
    return not owners or (bool(token) and token in owners)


def _token() -> str | None:
    from hfsentinel.secrets import hf_token
    try:
        return hf_token()
    except Exception:  # noqa: BLE001 — no token configured is fine for keyless/loopback targets
        return None


def run_scan(target_uri: str, flags: dict, *, scope_path: Path | None = None, signers_path: Path | None = None,
             token: str | None = None, owners: tuple[str, ...] = (), out_dir: Path | None = None):
    """Run a scan from UI inputs and return the assembled Report — the same campaign path the CLI/`diff` use.

    `flags` carry the same names as the CLI options, so `resolve_controls` resolves them identically. `scope_path` +
    `signers_path` authorize non-loopback targets (a signed scope file); loopback/reference targets use the built-in scope.
    """
    from hfsentinel import cli
    from hfsentinel.scope import authorize, load_allowed_signers, load_scope
    if not authorized(token, owners):
        raise PermissionError("not an authorized owner")
    controls = resolve_controls({k: v for k, v in flags.items() if v is not None}).controls
    target = resolve(parse(target_uri), token=_token())
    verified = load_scope(scope_path, signers=load_allowed_signers(signers_path)) if scope_path else None
    attestation = authorize(verified, target, resolved=True)
    report = cli._campaign_report(target, controls, attestation, ref=target_uri)
    if out_dir is not None:
        from hfsentinel.report import render
        render.write(report, Path(out_dir), list(controls.output.formats))
    return report


def build_ui(owners: tuple[str, ...] = ()):
    """Build the Gradio Blocks app (gradio imported lazily — a Space-deploy dependency, not in the core image)."""
    import gradio as gr

    from hfsentinel.report import render

    def _launch(target_uri, profile, categories, trials, temperature, max_tokens, budget_usd, check_sycophancy,
                check_calibration, scope_file, token):
        flags = {"profile": profile, "categories": categories or None, "trials": int(trials),
                 "temperature": float(temperature), "max_tokens": int(max_tokens), "budget_usd": float(budget_usd),
                 "check_sycophancy": bool(check_sycophancy), "check_calibration": bool(check_calibration)}
        try:
            report = run_scan(target_uri, flags, scope_path=(Path(scope_file) if scope_file else None),
                              token=token or None, owners=owners)
        except PermissionError:
            return "Refused: not an authorized owner.", "{}"
        except Exception as e:  # noqa: BLE001 — surface any scan error to the UI, never crash the app
            return f"Scan error: {type(e).__name__}: {e}", "{}"
        grade = f"Grade {report.grade.get('overall')} — {len(report.findings)} confirmed finding(s)"
        return grade, render.to_json(report)

    with gr.Blocks(title="HF-Sentinel") as ui:
        gr.Markdown("# HF-Sentinel — LLM offensive scanner\nStrictly model-only. Authorized targets only.")
        with gr.Row():
            target = gr.Textbox(label="Target URI", placeholder="hf-provider://org/model@provider or openai+https://host/v1#model")
            profile = gr.Dropdown(PRESETS, value="standard" if "standard" in PRESETS else PRESETS[0], label="Profile")
        with gr.Accordion("Controls", open=False):
            categories = gr.Textbox(label="Categories", placeholder="A,B,C,E,H")
            trials = gr.Slider(1, 50, value=10, step=1, label="Trials")
            temperature = gr.Slider(0.0, 1.5, value=0.7, step=0.1, label="Temperature")
            max_tokens = gr.Slider(16, 1024, value=256, step=16, label="Max tokens")
            budget_usd = gr.Slider(0.0, 20.0, value=5.0, step=0.5, label="Budget (USD, ≤20)")
            syco = gr.Checkbox(label="H5 sycophancy")
            calib = gr.Checkbox(label="H7 overconfidence")
        scope_file = gr.File(label="Signed scope file (non-loopback targets)", type="filepath")
        token = gr.Textbox(label="Owner token", type="password")
        run = gr.Button("Run scan", variant="primary")
        grade_out = gr.Textbox(label="Result", interactive=False)
        json_out = gr.Code(label="Report (JSON)", language="json")
        run.click(_launch, [target, profile, categories, trials, temperature, max_tokens, budget_usd, syco, calib,
                            scope_file, token], [grade_out, json_out])
    return ui.queue()  # 664: serialize scans so one run cannot starve others


def launch(owners: tuple[str, ...] = (), **kw) -> None:  # pragma: no cover - entrypoint
    build_ui(owners).launch(**kw)


if __name__ == "__main__":  # pragma: no cover
    import os
    launch(owners=tuple(o for o in os.environ.get("HFS_SPACE_OWNERS", "").split(",") if o))
