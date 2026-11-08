"""Repeated-run/serving-path stability (plan / LSCAN-032): reliability with uncertainty, generation vs target separated,
and no all-deployments claim from one route."""
from engines import stability as st


def test_cells_carry_rate_and_confidence_interval():
    c = st.StabilityCell("route=deepinfra", 8, 10)
    assert c.rate == 0.8 and c.ci95 is not None and c.ci95[0] < 0.8 < c.ci95[1]
    rows = st.stability_matrix([c, st.StabilityCell("seed=1", 0, 0)])
    assert rows[0]["ci95"] is not None and rows[1]["ci95"] is None     # empty cell -> no interval, not a fake 0


def test_generation_and_target_reliability_are_separate():
    out = st.generation_vs_target(same_seed_regenerates_identical_bytes=True,
                                  target_cell=st.StabilityCell("temp=0.7", 3, 10))
    assert out["attack_generation_deterministic"] is True            # harness determinism: a yes/no
    assert out["target_reliability"]["rate"] == 0.3 and out["target_reliability"]["ci95"] is not None


def test_route_coverage_is_not_generalized_to_all_deployments():
    claim = st.route_coverage_claim(["deepinfra", "deepinfra", "together"])
    assert "2 serving route" in claim and "not generalizable to all deployments" in claim
