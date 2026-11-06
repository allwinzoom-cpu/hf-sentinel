"""HF Jobs target runner (plan 617, D-004/D-006). Launch an ephemeral Hugging Face Job that serves a model with vLLM on
localhost, runs an HF-Sentinel scan against that local endpoint, and uploads the report to a private dataset.

The scoped `job.write` token is handed to the job as a **secret** (via run_job's `secrets=`), never in the command, the
env the job echoes, or the image — so it cannot leak into job logs. The scan only ever talks to `127.0.0.1` (the job's
own vLLM), so there is no SSRF surface. `run_job` is imported lazily (and is injectable for tests), so this module loads
and is unit-tested without the newer `huggingface_hub`; launching a real job needs that hub plus the scoped token and is
the operator step that satisfies the done-when.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from hfsentinel.targets.hub import REPO_ID

# HF Jobs hardware flavors we allow (CPU for smoke, small GPUs for real serving). An unknown flavor is refused so a
# typo cannot silently pick an expensive instance (D-005 budget discipline).
FLAVORS = ("cpu-basic", "cpu-upgrade", "t4-small", "t4-medium", "l4x1", "a10g-small", "a10g-large", "a100-large")
PORT = 8000
LOOPBACK = "127.0.0.1"
MAX_MINUTES_CAP = 120  # a job that runs longer is a bug or a runaway cost; hard-capped here


class JobTargetError(ValueError):
    pass


@dataclass(frozen=True)
class JobSpec:
    """Everything run_job needs except the secret value. `secret_keys` names the secrets the job expects; the token
    value is passed separately to `launch` and never stored here (so a JobSpec is safe to log)."""
    image: str
    command: list[str]
    env: dict[str, str]
    secret_keys: tuple[str, ...]
    flavor: str
    timeout: str

    def as_dict(self) -> dict:
        return {"image": self.image, "command": self.command, "env": self.env,
                "secret_keys": list(self.secret_keys), "flavor": self.flavor, "timeout": self.timeout}


def _scan_script(model_id: str, dataset_repo: str, trials: int, max_minutes: int) -> str:
    """The shell the job runs: serve the model on loopback with vLLM, wait for readiness, scan the local endpoint, and
    upload the report to the private dataset. The token is read from the HFS secret env the job injects; it is never
    interpolated into this string. The scan URL is hard-pinned to loopback (no SSRF)."""
    base = f"http://{LOOPBACK}:{PORT}/v1"
    # Note: ${HF_TOKEN} is expanded inside the job from the injected secret, not here. `python3` is used (not a bare
    # `python`) so the script runs on the official vLLM/Python images, which ship python3 but not always `python`.
    # The scan exits 10 when it confirms a finding at/above --fail-on (the PR-gate contract); that is the *expected*
    # outcome against a vulnerable target, not a job failure, so we capture its code under `set +e` and still upload
    # the report — otherwise `set -e` would abort before the upload exactly when there is a finding worth keeping.
    return (
        "set -eu\n"
        f"python3 -m vllm.entrypoints.openai.api_server --model '{model_id}' --host {LOOPBACK} --port {PORT} &\n"
        "VLLM_PID=$!\n"
        f"for i in $(seq 1 120); do curl -sf {base}/models >/dev/null 2>&1 && break || sleep 5; done\n"
        "set +e\n"
        f"hfsentinel scan 'openai+{base}#{model_id}' --via direct --trials {trials} "
        f"--max-minutes {max_minutes} --format json --out /tmp/out\n"
        "SCAN_RC=$?\n"
        "set -e\n"
        "kill $VLLM_PID 2>/dev/null || true\n"
        'if [ "$SCAN_RC" != 0 ] && [ "$SCAN_RC" != 10 ]; then '
        'echo \"scan failed (exit $SCAN_RC)\" >&2; exit "$SCAN_RC"; fi\n'
        "python3 -c \"import os,glob; from huggingface_hub import HfApi; "
        "f=sorted(glob.glob('/tmp/out/*.json'))[-1]; "
        f"HfApi(token=os.environ['HF_TOKEN']).upload_file(path_or_fileobj=f, "
        f"path_in_repo='reports/'+os.path.basename(f), repo_id='{dataset_repo}', repo_type='dataset')\"\n"
    )


def build_job_spec(model_id: str, dataset_repo: str, *, image: str, flavor: str = "l4x1",
                   trials: int = 10, max_minutes: int = 30, timeout: str = "1h") -> JobSpec:
    """Validate inputs and assemble the JobSpec. `image` must bundle vLLM + hfsentinel + huggingface_hub (operator-built,
    pinned). The token is NOT part of the spec — it is injected as a secret at launch."""
    if not REPO_ID.match(model_id):
        raise JobTargetError("invalid model id")
    if not REPO_ID.match(dataset_repo):
        raise JobTargetError("invalid dataset repo id")
    if flavor not in FLAVORS:
        raise JobTargetError(f"unknown flavor: {flavor} (allowed: {', '.join(FLAVORS)})")
    if not image or "/" not in image or any(c.isspace() for c in image):
        raise JobTargetError("image must be a valid container reference")
    if not 1 <= trials <= 1000:
        raise JobTargetError("trials out of range")
    if not 1 <= max_minutes <= MAX_MINUTES_CAP:
        raise JobTargetError(f"max_minutes must be 1..{MAX_MINUTES_CAP}")
    command = ["sh", "-c", _scan_script(model_id, dataset_repo, trials, max_minutes)]
    return JobSpec(image=image, command=command, env={"HF_HUB_DISABLE_TELEMETRY": "1", "DO_NOT_TRACK": "1"},
                   secret_keys=("HF_TOKEN",), flavor=flavor, timeout=timeout)


def launch(spec: JobSpec, token: str, *, namespace: str | None = None,
           run_job: Callable | None = None) -> str:
    """Submit the job, passing the scoped job.write `token` as a secret (never in the command/env). `run_job` is imported
    lazily from huggingface_hub (injectable for tests); a hub without it gets a clear, actionable error. Returns the
    job id. The token is handled only here and never logged."""
    if not token:
        raise JobTargetError("a scoped job.write token is required")
    if run_job is None:
        try:
            from huggingface_hub import run_job  # type: ignore[attr-defined]
        except ImportError as e:
            raise JobTargetError("this huggingface_hub has no run_job; upgrade to a version with HF Jobs support") from e
    job = run_job(image=spec.image, command=spec.command, env=spec.env,
                  secrets={k: token for k in spec.secret_keys}, flavor=spec.flavor,
                  timeout=spec.timeout, namespace=namespace, token=token)
    return getattr(job, "id", None) or getattr(job, "job_id", "") or str(job)


@dataclass(frozen=True)
class JobResult:
    job_id: str
    dataset_repo: str
    report_path: str = ""
    extra: dict = field(default_factory=dict)
