"""Control surface + sentinel.yaml (plan Phase 2): precedence flag → config → profile → default with per-value
sources, schema-enforced budget ceilings (D-005/D-017), adversarial config handling, exact round-trip."""
import inspect
import re
from pathlib import Path

import pytest
import yaml

from hfsentinel import cli
from hfsentinel.controls import (
    FLAG_PATHS,
    PROFILES,
    ControlError,
    Controls,
    flatten,
    load_config,
    resolve_controls,
    selected_ids,
    to_config,
)

ROOT = Path(__file__).resolve().parents[1]
PLAN = (ROOT / "hf-llm-security-scanner-project-plan.md").read_text(encoding="utf-8")


def write(tmp_path, text, name="sentinel.yaml"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# ---- Done when: a config + overriding flags produce the expected resolved control set ----
def test_config_plus_overriding_flags(tmp_path):
    (tmp_path / "sp.txt").write_text("You are a support bot.")
    cfg = write(tmp_path, """
profile: deep
target: hf-provider://Qwen/Qwen3-32B@deepinfra
select: {categories: [A, B, H], exclude: [B9], seed_set: harm-behaviors}
fuzz:
  rounds: 200
  max_attempts: 500
  mutators: [case, base64]
  tap: {width: 8}
target_io: {temperature: 0.9, concurrency: 8}
extras: {system_prompt: sp.txt}
budget: {usd: 15}
""")
    res = resolve_controls({"rounds": 40, "categories": "A,C", "trials": 7, "tap_depth": 2, "compose": False,
                            "save_transcripts": True}, load_config(cfg))
    c, src = res.controls, res.sources
    expected = {
        "profile": ("deep", "config"),
        "target": ("hf-provider://Qwen/Qwen3-32B@deepinfra", "config"),
        "select.categories": (["A", "C"], "flag"),
        "select.exclude": (["B9"], "config"),
        "select.seed_set": ("harm-behaviors", "config"),
        "select.status": ("ready+conditional", "default"),
        "select.scans": (["S1", "S2", "S3", "S5", "S6", "S10"], "profile:deep"),
        "fuzz.rounds": (40, "flag"),
        "fuzz.max_attempts": (500, "config"),
        "fuzz.mutators": (["case", "base64"], "config"),
        "fuzz.tap.width": (8, "config"),
        "fuzz.tap.depth": (2, "flag"),
        "fuzz.compose.enabled": (False, "flag"),
        "fuzz.compose.max_depth": (3, "profile:deep"),
        "fuzz.max_turns": (8, "profile:deep"),
        "target_io.trials": (7, "flag"),
        "target_io.temperature": (0.9, "config"),
        "target_io.concurrency": (8, "config"),
        "target_io.max_tokens": (1024, "default"),
        "extras.system_prompt": (str((tmp_path / "sp.txt").resolve()), "config"),  # relative to the config dir
        "budget.usd": (15.0, "config"),
        "budget.minutes": (120, "profile:deep"),
        "output.save_transcripts": (True, "flag"),
        "output.fail_on": ("critical", "default"),
    }
    got = flatten(to_config(c))
    for path, (value, source) in expected.items():
        assert (got[path], src[path]) == (value, source), path
    assert selected_ids(c)[:3] == ["A1", "A2", "A3"] and all(i[0] in "AC" for i in selected_ids(c))


def test_plan_yaml_example_is_valid():
    block = re.search(r"\*\*Config file \(`sentinel.yaml`\).*?```yaml\n(.*?)```", PLAN, re.DOTALL)[1]
    res = resolve_controls(config=yaml.safe_load(block))
    assert res.controls.fuzz.rounds == 200 and res.controls.judge.asr_k == 200
    assert res.controls.budget.usd == 20 and res.sources["output.push_to"] == "config"


def test_layer_precedence_single_key(tmp_path):
    assert resolve_controls().sources["target_io.trials"] == "profile:quick"
    assert resolve_controls({"profile": "custom"}).controls.target_io.trials == 10
    assert resolve_controls({"profile": "custom"}).sources["target_io.trials"] == "default"
    cfg = {"target_io": {"trials": 5}}
    assert resolve_controls(config=cfg).controls.target_io.trials == 5
    res = resolve_controls({"trials": 9}, cfg)
    assert (res.controls.target_io.trials, res.sources["target_io.trials"]) == (9, "flag")


def test_profile_flag_beats_config_profile():
    res = resolve_controls({"profile": "hallucination"}, {"profile": "deep"})
    assert res.controls.select.categories == ["H"] and res.sources["select.categories"] == "profile:hallucination"


@pytest.mark.parametrize("name", sorted(PROFILES))
def test_every_profile_resolves(name):
    assert resolve_controls({"profile": name}).controls.profile == name


# ---- attacks vs categories ----
def test_attacks_replace_categories_and_higher_layer_wins():
    assert selected_ids(resolve_controls({"attacks": "C1,A1"}).controls) == ["A1", "C1"]
    res = resolve_controls({"categories": "B"}, {"select": {"attacks": ["C1"]}})
    assert res.controls.select.attacks is None and all(i[0] == "B" for i in selected_ids(res.controls))
    same_layer = resolve_controls({"categories": "B", "attacks": "A1"})
    assert selected_ids(same_layer.controls) == ["A1"]


def test_unknown_ids_and_empty_selection():
    with pytest.raises(ControlError, match="unknown attack ids: Z9"):
        resolve_controls({"attacks": "A1,Z9"})
    with pytest.raises(ControlError, match="unknown attack ids"):
        resolve_controls(config={"select": {"exclude": ["A99"]}})
    with pytest.raises(ControlError, match="matches no attacks"):
        resolve_controls({"categories": "A", "exclude": "A1,A2,A3,A5"})  # quick = ready only; A4/A6 conditional


# ---- ranges, allow-lists, ceilings ----
@pytest.mark.parametrize("flags", [
    {"budget_usd": 20.01}, {"budget_judge_usd": 25.5}, {"budget_usd": 0}, {"rounds": 0}, {"trials": 1001},
    {"temperature": 2.5}, {"top_p": 0}, {"mutation_rate": 1.1}, {"concurrency": 65}, {"profile": "yolo"},
    {"categories": "A,Z"}, {"scans": "S11"}, {"fuzz_type": "random"}, {"mutators": "rot13"}, {"judge": "gpt"},
    {"status": "everything"}, {"seed_set": "my-dataset"}, {"halluc_registries": "maven"}, {"formats": "pdf"},
    {"fail_on": "low"}, {"push_to": "../x"}, {"sink_url": "http://sink.example.com"},
    {"sink_url": "https://u:p@sink.example.com"}, {"sink_url": "https://sink.example.com/?q=1"},
    {"sample": "0"}, {"sample": "1.5"}, {"sample": "x"}, {"asr_k": 11},  # asr_k > rounds (10)
])
def test_invalid_flags_rejected(flags):
    with pytest.raises(ControlError, match=r"^(flag|controls): "):
        resolve_controls({"profile": "custom", **flags})


def test_budget_ceiling_holds_in_config_too():
    with pytest.raises(ControlError, match=r"^config: budget\.usd"):
        resolve_controls(config={"budget": {"usd": 100}})


def test_cross_field_rule_uses_merged_layers():
    # config asr_k 30 alone would exceed the built-in rounds (10), but the chosen profile sets rounds 50
    assert resolve_controls({"profile": "deep"}, {"judge": {"asr_k": 30}}).controls.judge.asr_k == 30
    with pytest.raises(ControlError, match="asr_k cannot exceed"):
        resolve_controls({"profile": "deep"}, {"judge": {"asr_k": 60}})


def test_list_and_sample_parsing():
    c = resolve_controls({"profile": "custom", "categories": " A, B ,", "sample": "0.25"}).controls
    assert c.select.categories == ["A", "B"] and c.select.sample == 0.25
    assert resolve_controls({"sample": "20"}).controls.select.sample == 20
    with pytest.raises(ControlError):
        resolve_controls(config={"select": {"sample": True}})


def test_unknown_flag_name():
    with pytest.raises(ControlError, match="unknown flags: roundz"):
        resolve_controls({"roundz": 3})


# ---- config files are untrusted ----
@pytest.mark.parametrize("text, match", [
    ("fuzz: {roundz: 3}", r"config: fuzz\.roundz: Extra inputs are not permitted"),
    ("budgte: {usd: 1}", r"config: budgte"),
    ("a: &x [1]\nb: *x", "anchors/aliases"),
    ("- just\n- a list", "mapping"),
    ("fuzz: [unclosed", "valid UTF-8 YAML"),
    ("x: !!python/object/apply:os.system [id]", "valid UTF-8 YAML"),
])
def test_bad_configs(tmp_path, text, match):
    with pytest.raises(ControlError, match=match):
        resolve_controls(config=load_config(write(tmp_path, text)))


def test_config_size_encoding_and_missing(tmp_path, monkeypatch):
    p = tmp_path / "bin.yaml"
    p.write_bytes(b"\xff\xfe")
    with pytest.raises(ControlError, match="UTF-8"):
        load_config(p)
    with pytest.raises(ControlError, match="not found"):
        load_config(tmp_path / "nope.yaml")
    with pytest.raises(ControlError, match="not found"):
        load_config(tmp_path)
    monkeypatch.setattr("hfsentinel.controls.MAX_CONFIG_BYTES", 10)
    with pytest.raises(ControlError, match="exceeds"):
        load_config(write(tmp_path, "profile: quick\n"))


def test_empty_config_and_empty_section(tmp_path):
    assert load_config(write(tmp_path, "")) == {}
    assert resolve_controls(config=load_config(write(tmp_path, "fuzz: {}\n"))).controls.fuzz.rounds == 3


def test_input_files_checked(tmp_path, monkeypatch):
    with pytest.raises(ControlError, match="existing regular file"):
        resolve_controls({"goals": tmp_path / "missing.txt"})
    with pytest.raises(ControlError, match="existing regular file"):
        resolve_controls({"system_prompt": tmp_path})
    big = tmp_path / "big.txt"
    big.write_text("x" * 20)
    monkeypatch.setattr("hfsentinel.controls.MAX_INPUT_FILE_BYTES", 10)
    with pytest.raises(ControlError, match="at most"):
        resolve_controls({"tools": big})


def test_custom_seed_set_relative_to_config(tmp_path):
    (tmp_path / "seeds.txt").write_text("goal\n")
    res = resolve_controls(config=load_config(write(tmp_path, "select: {seed_set: 'custom:seeds.txt'}\n")))
    assert res.controls.select.seed_set == f"custom:{(tmp_path / 'seeds.txt').resolve()}"
    with pytest.raises(ControlError, match="seed_set"):
        resolve_controls({"seed_set": "custom:/nonexistent/seeds.txt"})


# ---- reproducibility + 1:1 mapping ----
def test_round_trip_reproduces_controls(tmp_path):
    (tmp_path / "goals.txt").write_text("g\n")
    first = resolve_controls({"profile": "deep", "rounds": 33, "goals": tmp_path / "goals.txt", "sample": "0.5",
                              "categories": "B,H", "top_p": 0.9}).controls
    other = tmp_path / "elsewhere"
    other.mkdir()
    dumped = write(other, yaml.safe_dump(to_config(first)))
    again = resolve_controls(config=load_config(dumped))
    assert again.controls == first
    assert set(again.sources.values()) == {"config"}


def test_flags_map_one_to_one_onto_the_schema():
    leaves = set(flatten(to_config(Controls())))
    assert set(FLAG_PATHS.values()) == leaves
    scan_params = set(inspect.signature(cli.scan).parameters)
    assert set(FLAG_PATHS) <= scan_params
