"""S2 runner: our pipeline over the fork's programmatic benchmark (no fork CLI).

uv run python bench/run.py --bench mad --config STATIC --model gpt-oss:20b --suite workspace --attack none --n 1
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SUITES = ["workspace", "banking", "slack", "travel"]
MODELS = ["gpt-4.1", "gpt-oss:20b", "gpt-oss:120b", "kimi-k3.1-pro", "deepseek-v4.1-flash"]
CONFIGS = ["NONE", "STATIC", "ADAPTIVE_RULES", "ADAPTIVE", "ADAPTIVE_AUDIT"]
# USD per 1M tokens (in, out) — ESTIMATES
PRICES = {"gpt-4.1": (2, 8), "gpt-oss:20b": (0.05, 0.20), "gpt-oss:120b": (0.10, 0.50), "kimi-k3.1-pro": (0.60, 2.50)}
VERSION = "v1.2.2"


def ollama_key(which: str) -> str:
    var = "OLLAMA_API_KEY" if which == "A" else "OLLAMA_API_KEY1"
    if not os.environ.get(var):
        sys.exit(f"{var} not set (source ~/.zshrc)")
    return os.environ[var]


def provider_env(model: str, key: str) -> dict:
    if model == "gpt-4.1":
        return {"OPENAI_COMPATIBLE_BASE_URL": "https://api.openai.com/v1",
                "OPENAI_COMPATIBLE_API_KEY": os.environ["OPENAI_API_KEY"]}
    return {"OPENAI_COMPATIBLE_BASE_URL": "https://ollama.com/v1", "OPENAI_COMPATIBLE_API_KEY": ollama_key(key)}


def run_suite(a) -> int:
    import yaml
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
    from agentdojo.logging import OutputLogger
    from agentdojo.task_suite.load_suites import get_suite

    from bench.mad_guard import make_pipeline

    logdir = Path(a.logdir)
    logdir.mkdir(parents=True, exist_ok=True)
    monitor_cfg = yaml.safe_load((ROOT / "bench/configs" / f"{a.config}.yaml").read_text())
    pipe = make_pipeline(a.config, a.model, provider_env(a.model, a.key), monitor_cfg,
                         log_path=logdir / f"events-{a.suite}.jsonl", run_id=f"{a.config}-{a.model}-{a.suite}-{int(time.time())}")
    if a.name:
        pipe.name = a.name
    suite = get_suite(VERSION, a.suite)
    uts = sorted(suite.user_tasks, key=lambda t: int(t.rsplit("_", 1)[1]))[: a.n]
    rows = []
    with OutputLogger(str(logdir)):
        if a.attack == "none":
            for ut in uts:
                rows.append(run_task_without_injection_tasks(suite, pipe, suite.get_user_task_by_id(ut), logdir,
                                                             a.force, VERSION))
        else:
            attack = load_attack(a.attack, suite, pipe)  # after pipe.name is set
            for ut in uts:
                u, s = run_task_with_injection_tasks(suite, pipe, suite.get_user_task_by_id(ut), attack, logdir,
                                                     a.force, a.inj, VERSION)
                rows += list(zip(u.values(), s.values()))
    tok = pipe.llm_counter.total
    pi, po = PRICES.get(a.model, (None, None))
    est = None if pi is None else round((tok["prompt_tokens"] * pi + tok["completion_tokens"] * po) / 1e6, 4)
    rec = {"config": a.config, "model": a.model, "suite": a.suite, "attack": a.attack, "n_tasks": len(uts),
           "pipeline": pipe.name, "prompt_tokens": tok["prompt_tokens"], "completion_tokens": tok["completion_tokens"],
           "tokens_estimated": tok["estimated"], "est_usd": est, "price_is_estimate": True, "ts": time.time()}
    spend = ROOT / "runs/mad/spend.jsonl"
    spend.parent.mkdir(parents=True, exist_ok=True)
    with spend.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    ut_ok = sum(bool(u) for u, _ in rows)
    print(f"[{a.suite}] utility {ut_ok}/{len(rows)}  ASR {sum(bool(s) for _, s in rows) if a.attack != 'none' else '-'}"
          f"  logs {logdir / pipe.name / a.suite}  spend {rec}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--bench", default="mad", choices=["mad"])
    p.add_argument("--config", required=True, choices=CONFIGS)
    p.add_argument("--model", required=True, choices=MODELS)
    p.add_argument("--suite", default="all", choices=SUITES + ["all"])
    p.add_argument("--attack", default="important_instructions", choices=["important_instructions", "none"])
    p.add_argument("--n", type=int, default=None, help="limit user tasks (smoke)")
    p.add_argument("--inj", action="append", default=None, help="limit injection task ids (smoke), repeatable")
    p.add_argument("--key", default="A", choices=["A", "B"])
    p.add_argument("--logdir", default=None)
    p.add_argument("--name", default=None, help="override pipeline name (e.g. openai-compatible-multi-agent "
                                                "to resume the raw-fork-CLI NONE baseline)")
    p.add_argument("--force", action="store_true", help="rerun even if logs exist")
    a = p.parse_args(argv)
    a.logdir = a.logdir or str(ROOT / "runs/mad" / a.config / a.model)
    if a.config == "NONE" and a.model == "gpt-4.1" and not a.name:
        a.name = "openai-compatible-multi-agent"  # reuse the paid raw-fork-CLI baseline logs
    if a.suite != "all":
        return run_suite(a)
    # --max-workers in the fork is broken for multi-agent: one process per suite
    base = [x for x in (argv if argv is not None else sys.argv[1:])]
    i = base.index("--suite") if "--suite" in base else None
    if i is not None:
        del base[i:i + 2]
    procs = [subprocess.Popen([sys.executable, __file__, *base, "--suite", s]) for s in SUITES]
    codes = [pr.wait() for pr in procs]
    print("exit codes", dict(zip(SUITES, codes)))
    return 1 if any(codes) else 0  # negative = killed by signal


if __name__ == "__main__":
    sys.exit(main())
