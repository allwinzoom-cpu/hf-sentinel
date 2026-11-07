"""Route-drift evidence (LSCAN-009): a replay cannot silently treat a changed provider/model/served-identity as the same
serving path, and an absent revision is 'unknown' — never inferred from a Hub repo SHA."""
from hfsentinel.targets.resolve import parse
from hfsentinel.targets.route_record import UNKNOWN_REVISION, build_route_record, route_changed


def _rt(uri):
    return parse(uri)


def test_absent_revision_is_unknown_not_a_hub_sha():
    r = build_route_record(_rt("hf-provider://org/model@together"))
    assert r.revision == UNKNOWN_REVISION  # no served identity -> unknown, not a repo SHA
    # even if a Hub SHA is around, build_route_record only takes a SERVED revision:
    r2 = build_route_record(_rt("hf-provider://org/model@together"), served_revision="abc123def456")
    assert r2.revision == "abc123def456"


def test_served_identity_is_recorded_when_exposed():
    r = build_route_record(_rt("openai+https://host/v1#m"), served_model="vendor/m-0.3", served_revision="2026-10")
    assert r.served_model == "vendor/m-0.3" and r.revision == "2026-10" and r.base_url.startswith("https://host")


def test_changed_provider_is_flagged_as_route_drift():
    a = build_route_record(_rt("hf-provider://org/model@together"))
    b = build_route_record(_rt("hf-provider://org/model@fireworks"))  # provider changed
    assert route_changed(a, b)  # replay must NOT treat these as the same serving path


def test_same_route_is_not_flagged_despite_timestamp():
    a = build_route_record(_rt("hf-provider://org/model@together"), served_model="s", served_revision="r1")
    b = build_route_record(_rt("hf-provider://org/model@together"), served_model="s", served_revision="r1")
    assert not route_changed(a, b)  # only resolved_at differs (timing, not route)


def test_changed_served_revision_is_route_drift():
    a = build_route_record(_rt("openai+https://host/v1#m"), served_revision="r1")
    b = build_route_record(_rt("openai+https://host/v1#m"), served_revision="r2")
    assert route_changed(a, b)
