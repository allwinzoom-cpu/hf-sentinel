"""Scope enforcement (plan 16.1, D-003): only authorized targets are ever sent traffic.

A scope file is a YAML allow-list of target URIs plus an authorization record, signed with OpenSSH
(`ssh-keygen -Y sign -f <key> -n hfsentinel-scope scope.yaml` → `scope.yaml.sig`). The signature is verified per
PROTOCOL.sshsig against an `allowed_signers` trust list *before* the YAML is parsed; only Ed25519 keys are accepted.
Built-in sources need no file: the operator's own loopback host and the owner-approved reference endpoints (D-007).
Every successful check yields an Attestation for the report; every failure raises ScopeError (fail closed).
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import os
import shlex
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from hfsentinel.targets.openai_compat import LOOPBACK_HOSTS
from hfsentinel.targets.resolve import ResolvedTarget, TargetURIError, UnsupportedTarget, parse

NAMESPACE = "hfsentinel-scope"
SIGNERS_ENV = "HFS_ALLOWED_SIGNERS"
DEFAULT_SIGNERS = Path.home() / ".config" / "hfsentinel" / "allowed_signers"
REFERENCE_TARGETS = Path(__file__).resolve().parents[1] / "config" / "reference_targets.yaml"
MAX_SCOPE_BYTES = 64_000
MAX_SIG_BYTES = 8_000
MAX_SIGNERS_BYTES = 64_000
MAX_GRANT_DAYS = 366
ARMOR_BEGIN, ARMOR_END = "-----BEGIN SSH SIGNATURE-----", "-----END SSH SIGNATURE-----"


class ScopeError(ValueError):
    """The target is not authorized, or the scope cannot be trusted. Nothing may be sent."""


# ---- OpenSSH signatures ----
@dataclass(frozen=True)
class AllowedSigner:
    principals: str
    key_blob: bytes
    namespaces: tuple[str, ...] | None = None
    valid_after: dt.datetime | None = None
    valid_before: dt.datetime | None = None

    @property
    def fingerprint(self) -> str:
        return "SHA256:" + base64.b64encode(hashlib.sha256(self.key_blob).digest()).decode().rstrip("=")


def _ssh_time(value: str) -> dt.datetime:
    for fmt in ("%Y%m%d", "%Y%m%d%H%M", "%Y%m%d%H%M%S"):
        try:
            return dt.datetime.strptime(value, fmt).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    raise ScopeError("allowed_signers: unsupported time format")


def parse_allowed_signers(text: str) -> list[AllowedSigner]:
    """OpenSSH allowed_signers subset: `principals [options] ssh-ed25519 <base64> [comment]`.
    Supported options: namespaces=, valid-after=, valid-before=. Anything else (cert-authority, other key types,
    unknown options) is refused for that line."""
    signers = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            continue
        if len(tokens) < 3:
            continue
        principals, rest = tokens[0], tokens[1:]
        options: dict[str, str] = {}
        if rest[0] != "ssh-ed25519":
            for opt in rest[0].split(","):
                key, _, val = opt.partition("=")
                options[key.lower()] = val
            rest = rest[1:]
        if len(rest) < 2 or rest[0] != "ssh-ed25519" or set(options) - {"namespaces", "valid-after", "valid-before"}:
            continue
        try:
            blob = base64.b64decode(rest[1], validate=True)
            _parse_ed25519_key(blob)
            signers.append(AllowedSigner(
                principals=principals[:200], key_blob=blob,
                namespaces=tuple(options["namespaces"].split(",")) if "namespaces" in options else None,
                valid_after=_ssh_time(options["valid-after"]) if "valid-after" in options else None,
                valid_before=_ssh_time(options["valid-before"]) if "valid-before" in options else None))
        except (ValueError, ScopeError):
            continue
    return signers


def load_allowed_signers(path: Path | None = None) -> list[AllowedSigner]:
    p = Path(path or os.environ.get(SIGNERS_ENV) or DEFAULT_SIGNERS).expanduser()
    if not p.is_file() or p.stat().st_size > MAX_SIGNERS_BYTES:
        raise ScopeError("allowed_signers file not found (use --signers or HFS_ALLOWED_SIGNERS)")
    signers = parse_allowed_signers(p.read_text(encoding="utf-8", errors="replace"))
    if not signers:
        raise ScopeError("allowed_signers has no usable Ed25519 signer")
    return signers


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ScopeError("malformed signature")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def string(self) -> bytes:
        return self.take(self.u32())

    def done(self) -> None:
        if self.pos != len(self.data):
            raise ScopeError("malformed signature")


def _ssh_string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _parse_ed25519_key(blob: bytes) -> bytes:
    r = _Reader(blob)
    if r.string() != b"ssh-ed25519":
        raise ScopeError("only Ed25519 signing keys are supported")
    key = r.string()
    r.done()
    if len(key) != 32:
        raise ScopeError("malformed Ed25519 key")
    return key


def verify_sshsig(message: bytes, armored: str, signers: list[AllowedSigner], *, namespace: str = NAMESPACE,
                  now: dt.datetime | None = None) -> AllowedSigner:
    """Return the trusted signer whose key produced this signature over `message`, or raise ScopeError."""
    lines = [ln.strip() for ln in armored.strip().splitlines()]
    if len(lines) < 3 or lines[0] != ARMOR_BEGIN or lines[-1] != ARMOR_END:
        raise ScopeError("signature is not an OpenSSH signature")
    try:
        blob = base64.b64decode("".join(lines[1:-1]), validate=True)
    except ValueError:
        raise ScopeError("malformed signature") from None
    r = _Reader(blob)
    if r.take(6) != b"SSHSIG" or r.u32() != 1:
        raise ScopeError("unsupported signature version")
    pub, ns, reserved, hash_alg, sig = r.string(), r.string(), r.string(), r.string(), r.string()
    r.done()
    if ns != namespace.encode():
        raise ScopeError("signature namespace is not hfsentinel-scope")
    if hash_alg not in (b"sha256", b"sha512"):
        raise ScopeError("unsupported signature hash")
    key = _parse_ed25519_key(pub)
    sr = _Reader(sig)
    if sr.string() != b"ssh-ed25519":
        raise ScopeError("only Ed25519 signatures are supported")
    raw_sig = sr.string()
    sr.done()
    signer = next((s for s in signers if s.key_blob == pub), None)
    if signer is None:
        raise ScopeError("scope is signed by a key that is not in allowed_signers")
    digest = hashlib.new(hash_alg.decode(), message).digest()
    signed = b"SSHSIG" + _ssh_string(ns) + _ssh_string(reserved) + _ssh_string(hash_alg) + _ssh_string(digest)
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(raw_sig, signed)
    except (InvalidSignature, ValueError):
        raise ScopeError("scope signature does not verify (file changed after signing?)") from None
    now = now or dt.datetime.now(dt.timezone.utc)
    if signer.namespaces is not None and namespace not in signer.namespaces:
        raise ScopeError("signer is not allowed to sign scope files (namespaces=)")
    if (signer.valid_after and now < signer.valid_after) or (signer.valid_before and now > signer.valid_before):
        raise ScopeError("signer key is outside its validity window")
    return signer


# ---- scope file ----
class Authorization(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    reference: str = Field(min_length=1, max_length=200)  # ticket / contract / written-permission reference
    authorized_by: str = Field(min_length=1, max_length=200)
    statement: str = Field(min_length=1, max_length=1000)
    granted: dt.date
    expires: dt.date


class Entry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    uri: str = Field(min_length=1, max_length=512)
    note: str = Field(default="", max_length=200)

    @field_validator("uri")
    @classmethod
    def _uri(cls, v: str) -> str:
        try:
            parse(v)
        except (TargetURIError, UnsupportedTarget) as e:
            raise ValueError(str(e)) from None
        return v


class ScopeFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: int = Field(ge=1, le=1)
    authorization: Authorization
    targets: list[Entry] = Field(min_length=1, max_length=200)


@dataclass(frozen=True)
class Scope:
    source: str  # "signed-file" | "loopback" | "reference-endpoints (D-007)"
    entries: tuple[ResolvedTarget, ...]
    authorization: Authorization | None = None
    sha256: str = ""
    signer: str = ""
    fingerprint: str = ""


@dataclass(frozen=True)
class Attestation:
    source: str
    matched: str
    reference: str
    authorized_by: str
    signer: str
    key_fingerprint: str
    scope_sha256: str
    granted: str
    expires: str
    checked_at: str

    def to_dict(self) -> dict:
        return asdict(self)


def load_scope(path: Path, *, signers: list[AllowedSigner], today: dt.date | None = None) -> Scope:
    path = Path(path).expanduser()
    sig_path = path.with_name(path.name + ".sig")
    for p, cap in ((path, MAX_SCOPE_BYTES), (sig_path, MAX_SIG_BYTES)):
        if not p.is_file():
            raise ScopeError(f"{p.name}: not found (sign with ssh-keygen -Y sign -n {NAMESPACE})")
        if p.stat().st_size > cap:
            raise ScopeError(f"{p.name}: too large")
    data = path.read_bytes()
    signer = verify_sshsig(data, sig_path.read_text(encoding="ascii", errors="replace"), signers)
    try:  # parsed only after the signature is known good
        text = data.decode("utf-8")
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise ScopeError("scope: YAML anchors/aliases are not allowed")
        doc = ScopeFile.model_validate(yaml.safe_load(text))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise ScopeError("scope: not valid UTF-8 YAML") from None
    except ValidationError as e:
        err = e.errors()[0]
        raise ScopeError(f"scope: {'.'.join(str(x) for x in err['loc'])}: {err['msg']}") from None
    auth, today = doc.authorization, today or dt.date.today()
    if auth.expires < auth.granted or (auth.expires - auth.granted).days > MAX_GRANT_DAYS:
        raise ScopeError(f"scope: authorization window must be 0-{MAX_GRANT_DAYS} days")
    if not auth.granted <= today <= auth.expires:
        raise ScopeError("scope: authorization is not valid today (not yet granted or expired)")
    return Scope("signed-file", tuple(parse(e.uri) for e in doc.targets), auth,
                 hashlib.sha256(data).hexdigest(), signer.principals, signer.fingerprint)


def _matches(entry: ResolvedTarget, t: ResolvedTarget, *, resolved: bool) -> bool:
    if entry.kind != t.kind:
        return False
    if t.kind == "hf-provider":
        if entry.model != t.model:
            return False
        if entry.provider is None:  # an entry without @provider authorizes every provider for that model
            return True
        return t.provider == entry.provider or (not resolved and t.provider is None)  # pinned after resolution
    if t.kind == "hf-space":
        return entry.space == t.space
    if t.kind in ("openai", "hf-endpoint"):
        return entry.base_url == t.base_url and entry.model == t.model
    return entry.model == t.model  # hf-job


def builtin_scope(t: ResolvedTarget) -> Scope | None:
    """Scope that needs no file: the operator's own loopback host, or a D-007 reference endpoint."""
    if t.kind == "openai" and (urlparse(t.base_url).hostname or "") in LOOPBACK_HOSTS:
        return Scope("loopback", (t,))
    cfg = yaml.safe_load(REFERENCE_TARGETS.read_text(encoding="utf-8"))
    refs = tuple(parse(e["uri"]) for e in cfg.get("targets", []))
    if any(_matches(r, t, resolved=False) for r in refs):
        return Scope("reference-endpoints (D-007)", refs)
    return None


def authorize(scope: Scope | None, t: ResolvedTarget, *, resolved: bool) -> Attestation:
    """Raise ScopeError unless `t` is covered by `scope` (or a built-in source when no scope file is given).
    Call with resolved=False on the parsed URI before any network call, and again with resolved=True after the
    Hub has pinned the target."""
    scope = scope or builtin_scope(t)
    if scope is None:
        raise ScopeError("refused: target is not in scope (pass --scope with a signed scope file)")
    match = next((e for e in scope.entries if _matches(e, t, resolved=resolved)), None)
    if match is None:
        raise ScopeError("refused: target is not in the authorized scope")
    a = scope.authorization
    if a is not None:
        reference, authorized_by, granted, expires = a.reference, a.authorized_by, str(a.granted), str(a.expires)
    elif scope.source == "loopback":
        reference, authorized_by, granted, expires = "loopback", "operator (own host)", "", ""
    else:
        reference, authorized_by, granted, expires = "D-007", "owner (DECISIONS.md sign-off)", "", ""
    return Attestation(source=scope.source, matched=match.uri, reference=reference, authorized_by=authorized_by,
                       signer=scope.signer, key_fingerprint=scope.fingerprint, scope_sha256=scope.sha256,
                       granted=granted, expires=expires,
                       checked_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"))
