"""Multimodal asset-replay foundation (plan LSCAN-056): hash-pinned replay, modality-availability and size outcomes
distinct from refusal, and scope-bound opaque handles."""
import pytest

from hfsentinel.targets import assets as a


def test_asset_from_bytes_hashes_and_validates_kind():
    img = a.MediaAsset.from_bytes("image", "image/png", b"\x89PNG....")
    assert img.sha256.startswith("sha256:") and img.size == 8 and img.kind == "image"
    with pytest.raises(ValueError, match="kind must be"):
        a.MediaAsset.from_bytes("hologram", "x/y", b"z")


def test_modality_and_size_outcomes_are_distinct_from_refusal():
    assert a.modality_outcome("image", supported={"image"}) == "available"
    assert "N/A" in a.modality_outcome("audio", supported={"image"})           # unsupported modality -> N/A, not fail
    small = a.MediaAsset.from_bytes("image", "image/png", b"x" * 10)
    assert a.size_outcome(small, limit=100) == "ok"
    assert a.size_outcome(small, limit=5) == "unsupported-size"                # over-limit -> unsupported, not refusal


def test_replay_requires_identical_bytes():
    asset = a.MediaAsset.from_bytes("image", "image/png", b"original-bytes")
    assert a.replayable(asset, b"original-bytes") and not a.replayable(asset, b"tampered-bytes")


def test_opaque_handle_is_scope_bound():
    h = a.MediaAsset("document", "application/pdf", "sha256:ab", 10, handle="file-123", scope="scope-A")
    assert a.handle_usable(h, request_scope="scope-A") and not a.handle_usable(h, request_scope="scope-B")
    inline = a.MediaAsset("image", "image/png", "sha256:cd", 5)
    assert a.handle_usable(inline, request_scope="any")                        # inline bytes: no cross-scope handle
