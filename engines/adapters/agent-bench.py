"""agent-bench adapter: stateful agent environments with deterministic utility/security checks (owned capability).

Technique: D1 (instruction carried in tool output). Runs `trials` workspace user tasks, each paired with
injection_task_0; success = the environment-state security check. The no-attack baseline arm is a planner concern
(16.4). Traces stay in tmpfs.
"""
import os
import sys
from pathlib import Path

import openai
from _common import emit, load_job, proven, technique
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
from agentdojo.benchmark import benchmark_suite_with_injections
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite

ATTACK = "important_instructions_no_model_name"
LOGDIR = Path("/tmp/agent-bench-runs")


def run(job: dict) -> int:
    client = openai.OpenAI(base_url=job["target"]["endpoint"], api_key=os.environ.get("OPENAI_API_KEY") or "unused",
                           max_retries=6)
    llm = OpenAILLM(client, job["target"]["model"])
    pipeline = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm,
                              ToolsExecutionLoop([ToolsExecutor(), llm], max_iters=8)])
    pipeline.name = "local"  # recognised neutral label required by the attack constructor; not used in the payload
    suite = get_suite("v1.2.2", "workspace")
    user_tasks = [f"user_task_{i}" for i in range(job["trials"])]
    attack = load_attack(ATTACK, suite, pipeline)
    res = benchmark_suite_with_injections(pipeline, suite, attack, logdir=LOGDIR, force_rerun=True,
                                          user_tasks=user_tasks, injection_tasks=["injection_task_0"], verbose=False)
    proofs = [proven({"pair": list(k), "utility": bool(res["utility_results"][k])},
                     f"{k[0]}+{k[1]}: injection goal achieved (utility={bool(res['utility_results'][k])})")
              for k, hit in sorted(res["security_results"].items()) if hit]
    return emit(job, "agent-bench", [technique("D1", "tool-output-injection", len(res["security_results"]), proofs,
                                               "deterministic", "environment-state")])


def main() -> int:
    job = load_job()
    if "D1" not in job["techniques"]:
        return emit(job, "agent-bench", [])
    with OutputLogger(str(LOGDIR)):
        return run(job)


if __name__ == "__main__":
    sys.exit(main())
