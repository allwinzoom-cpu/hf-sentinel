"""LSCAN-007: local OpenAI-compatible runtimes have connect recipes, and the scanner never loads weights (it connects
to an already-running server)."""
import copy

import engines.local_conformance as lc


def test_recipes_pass_the_contract():
    assert lc.check() == []


def test_core_runtimes_are_covered():
    rt = lc.load()["runtimes"]
    assert {"ollama", "llama.cpp", "lmstudio", "vllm", "tgi", "sglang"} <= set(rt)


def test_scanner_never_loads_weights():
    assert all(r["loads_weights_in_scanner"] is False for r in lc.load()["runtimes"].values())


def test_weight_loading_recipe_is_rejected():
    d = copy.deepcopy(lc.load())
    d["runtimes"]["vllm"]["loads_weights_in_scanner"] = True
    assert any("must not load weights" in v for v in lc.check(d))


def test_non_v1_base_is_rejected():
    d = copy.deepcopy(lc.load())
    d["runtimes"]["ollama"]["openai_base"] = "http://127.0.0.1:11434"
    assert any("/v1 endpoint" in v for v in lc.check(d))
