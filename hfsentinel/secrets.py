"""Secret loading. Values are never logged, printed, or included in exceptions."""
from __future__ import annotations

import os
from pathlib import Path

# Accepted names, in priority order. `hf_tok` is the owner's .env convention (DECISIONS D-006).
HF_TOKEN_NAMES = ("HF_TOKEN", "hf_tok")
# Container-friendly file mounts (DECISIONS D-009): raw token file, or a mounted dotenv file.
TOKEN_FILE_VAR = "HF_TOKEN_FILE"
ENV_FILE_VAR = "HFSENTINEL_ENV_FILE"


class SecretNotFound(RuntimeError):
    pass


def _read_dotenv(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        out[key.strip()] = val.strip().strip("'\"")
    return out


def hf_token(dotenv: Path | None = None) -> str:
    """Lookup order: env var → HF_TOKEN_FILE (raw token) → dotenv (`dotenv` arg, HFSENTINEL_ENV_FILE, or ./.env)."""
    for name in HF_TOKEN_NAMES:
        if os.environ.get(name):
            return os.environ[name]
    token_file = os.environ.get(TOKEN_FILE_VAR)
    if token_file:
        path = Path(token_file)
        value = path.read_text(encoding="utf-8").strip() if path.is_file() else ""
        if not value:
            raise SecretNotFound(f"{TOKEN_FILE_VAR} is set but the file is missing or empty")
        return value
    env = _read_dotenv(dotenv or Path(os.environ.get(ENV_FILE_VAR) or Path.cwd() / ".env"))
    for name in HF_TOKEN_NAMES:
        if env.get(name):
            return env[name]
    raise SecretNotFound(f"HF token not found; set one of {HF_TOKEN_NAMES} in the environment or .env")


def redact(text: str, secret: str) -> str:
    return text.replace(secret, "[REDACTED]") if secret else text
