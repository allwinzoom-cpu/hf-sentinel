"""Multimodal transport and asset-replay foundation (plan LSCAN-056). A typed media asset (image/audio/video/document)
is sent ONLY to an adapter that supports that modality, carries a content hash so identical bytes + metadata replay
exactly, and declares its media limits. An unsupported MIME/size/duration is a DISTINCT outcome from a refusal, an opaque
file handle is scope-bound (never fetched or reused across scopes), and a modality the build cannot send is N/A — never a
pass or a fail. Pure + offline (asset bytes are hashed, not fetched here)."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

MODALITIES = ("image", "audio", "video", "document")
# Conservative per-modality byte limits (declared; a real adapter may lower them).
DEFAULT_LIMITS = {"image": 20_000_000, "audio": 25_000_000, "video": 100_000_000, "document": 30_000_000}


def asset_hash(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class MediaAsset:
    kind: str                 # one of MODALITIES
    media_type: str           # MIME, e.g. image/png
    sha256: str               # content hash for exact replay
    size: int                 # bytes
    handle: str = ""          # opaque provider file handle, scope-bound (never fetched/reused across scopes)
    scope: str = ""           # the scope the handle belongs to

    def __post_init__(self):
        if self.kind not in MODALITIES:
            raise ValueError(f"kind must be one of {MODALITIES}")

    @classmethod
    def from_bytes(cls, kind: str, media_type: str, data: bytes, **kw) -> MediaAsset:
        return cls(kind=kind, media_type=media_type, sha256=asset_hash(data), size=len(data), **kw)


def modality_outcome(kind: str, *, supported: set[str]) -> str:
    """'available' when the adapter supports the modality, else 'N/A' — a modality the build cannot send is never a
    pass or a fail (LSCAN-056)."""
    return "available" if kind in supported else f"N/A (modality {kind!r} not supported by this adapter)"


def size_outcome(asset: MediaAsset, *, limit: int | None = None) -> str:
    """'ok' / 'unsupported-size' — an over-limit asset is UNSUPPORTED (distinct from a model refusal), never a bypass."""
    cap = limit if limit is not None else DEFAULT_LIMITS.get(asset.kind, 0)
    return "ok" if asset.size <= cap else "unsupported-size"


def replayable(asset: MediaAsset, actual_bytes: bytes) -> bool:
    """True iff the bytes available at replay hash to the pinned asset — identical bytes replay, a changed asset does not."""
    return asset_hash(actual_bytes) == asset.sha256


def handle_usable(asset: MediaAsset, *, request_scope: str) -> bool:
    """An opaque file handle is usable only within its own scope (LSCAN-056): never fetched or reused across a scope
    boundary. No handle (inline bytes) is always usable."""
    return not asset.handle or asset.scope == request_scope
