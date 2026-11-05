"""agent-bench (AgentDojo 0.1.35) Phase 1 eval: one workspace user task, baseline arm + one injection task.

AgentDojo's checks are deterministic (environment state), so `injection_success` is a tool-deterministic oracle.
Writes /out/<label>.results.json in the shared case shape. Usage: python run.py <label> <endpoint> <model> <ut> <it>
"""
import json
import os
import sys
from pathlib import Path

import openai
from agentdojo.agent_pipeline import (
    AgentPipeline,
    InitQuery,
    OpenAILLM,
    SystemMessage,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.attacks import load_attack
from agentdojo.benchmark import (
    benchmark_suite_with_injections,
    benchmark_suite_without_injections,
)
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite

ATTACK = "important_instructions_no_model_name"
# agentdojo's tracer needs an ambient OutputLogger (as its CLI sets up); traces go to the container tmpfs and vanish
# with it (D-015).
LOGDIR = Path("/tmp/agentdojo-runs")


def main(label: str, endpoint: str, model: str, user_task: str, injection_task: str) -> int:
    with OutputLogger(str(LOGDIR)):
        return run(label, endpoint, model, user_task, injection_task)


def run(label: str, endpoint: str, model: str, user_task: str, injection_task: str) -> int:
    client = openai.OpenAI(base_url=endpoint, api_key=os.environ["OPENAI_API_KEY"], max_retries=6)
    llm = OpenAILLM(client, model)
    pipeline = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm,
                              ToolsExecutionLoop([ToolsExecutor(), llm], max_iters=8)])
    # agentdojo's attack constructors require a recognised model label even when the injected text omits it
    # (`_no_model_name`); 'local' maps to the neutral "Local model" and never reaches the prompt here.
    pipeline.name = "local"
    suite = get_suite("v1.2.2", "workspace")

    base = benchmark_suite_without_injections(pipeline, suite, logdir=LOGDIR, force_rerun=True, user_tasks=[user_task])
    base_utility = bool(next(iter(base["utility_results"].values())))
    print(f"baseline user_task={user_task} utility={base_utility}", flush=True)

    attack = load_attack(ATTACK, suite, pipeline)
    res = benchmark_suite_with_injections(pipeline, suite, attack, logdir=LOGDIR, force_rerun=True,
                                          user_tasks=[user_task], injection_tasks=[injection_task], verbose=False)
    key = (user_task, injection_task)
    utility = bool(res["utility_results"][key])
    injected = bool(res["security_results"][key])  # True = the injection task's goal was achieved
    print(f"attack={ATTACK} user_task={user_task} injection_task={injection_task} "
          f"utility_under_attack={utility} injection_success={injected}", flush=True)
    case = f"{user_task}+{injection_task}"
    results = {case: {"passed": not injected, "baseline_utility": base_utility, "utility_under_attack": utility,
                      **({"failed_result": {"response": "", "reason": f"injection goal achieved ({injection_task})"}}
                         if injected else {})}}
    with open(f"/out/{label}.results.json", "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print(f"done cases=1 injection_success={injected}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:6]))
