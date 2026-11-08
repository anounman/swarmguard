"""S2 runner: our pipeline over the fork's programmatic benchmark (no fork CLI).

uv run python bench/run.py --bench mad --config STATIC --model gpt-oss:20b --suite workspace --attack none --n 1
Providers + budget gate: bench/providers.py, bench/budget.py (budget.yaml is the law; PLAN C13-C16).
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from itertools import groupby
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import budget as B  # noqa: E402
from bench import providers as P  # noqa: E402

SUITES = ["workspace", "banking", "slack", "travel"]
MODELS = P.MODELS
CONFIGS = ["NONE", "STATIC", "ADAPTIVE_RULES", "ADAPTIVE", "ADAPTIVE_AUDIT"]
KEY_SPLIT = {"workspace": "A", "banking": "A", "slack": "B", "travel": "B"}  # 3 concurrent/key -> 2 suites/key
VERSION = "v1.2.2"


def pipe_name(a) -> str:
    from bench.mad_guard import pipeline_name
    return a.name or pipeline_name(a.config, a.res["model_id_for_api"])


def plan(a, suite_name: str) -> tuple[list, list]:
    """(all planned episode pairs, those still without a log)."""
    from agentdojo.task_suite.load_suites import get_suite
    suite = get_suite(VERSION, suite_name)
    pairs = B.plan_pairs(suite.user_tasks, suite.injection_tasks, a.attack, a.n, a.inj, a.max_episodes)
    return pairs, (pairs if a.force else B.missing(pairs, a.logdir, pipe_name(a), suite_name, a.attack))


def check_gate(a, suites: list[str], bud: dict) -> int:
    """Print one decision line; 0 = go, 2 = refused. On go (not --dry-run) reserve the projection per suite so
    concurrent launches see it before the final spend rows land (released by the row with the same run_id)."""
    per = {s: len(plan(a, s)[1]) for s in suites}
    eps = sum(per.values())
    d = B.gate(a.model, eps, bud, B.read_spend(), key=a.res["key"])
    print("GATE " + ("ALLOW " if d["allowed"] else "REFUSE ") + " ".join(f"{k}={v}" for k, v in d.items()), flush=True)
    code = 0 if d["allowed"] else 2
    if code and a.no_gate:
        print("!!! BUDGET GATE BYPASSED (--no-gate, orchestrator override) !!!", file=sys.stderr, flush=True)
        code = 0
    if code == 0 and not a.dry_run:
        for s, n in per.items():
            B.record({"ts": time.time(), "reserved": True, "run_id": f"{a._run_id}-{s}", "provider": a.res["provider"],
                      "key": KEY_SPLIT[s] if a.suite == "all" and a.res["provider"] == "ollama" else a.res["key"],
                      "model": P.canonical(a.model), "config": a.config, "suite": s,
                      "est_usd": round(d["projected_usd"] * n / max(eps, 1), 4)})
    return code


def spend_record(a, pipeline: str, n_tasks: int, n_episodes: int, tok: dict, bud: dict) -> dict:
    pi, po = B.price(a.model, bud)
    return {"ts": time.time(), "provider": a.res["provider"], "key": a.res["key"], "model": P.canonical(a.model),
            "config": a.config, "suite": a.suite, "attack": a.attack, "n_tasks": n_tasks, "n_episodes": n_episodes,
            "prompt_tokens": tok["prompt_tokens"], "completion_tokens": tok["completion_tokens"],
            "tokens_estimated": tok["estimated"],
            "est_usd": round((tok["prompt_tokens"] * pi + tok["completion_tokens"] * po) / 1e6, 4),
            "price_is_estimate": "output" not in bud["prices"][P.canonical(a.model)], "logdir": str(a.logdir),
            "pipeline": pipeline, "run_id": f"{a._run_id}-{a.suite}"}


def run_suite(a, bud: dict) -> int:
    import yaml
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
    from agentdojo.logging import OutputLogger
    from agentdojo.task_suite.load_suites import get_suite

    from bench.mad_guard import make_pipeline

    logdir = Path(a.logdir)
    logdir.mkdir(parents=True, exist_ok=True)
    pairs, todo = plan(a, a.suite)
    # ponytail: SG_MONITOR_CFG overrides the monitor yaml (C23: ADAPTIVE(v3) = ADAPTIVE + bench/configs/ADAPTIVE_v3.yaml
    # + --logdir runs/mad/ADAPTIVE_v3/<model>, so v2 and v3 never share a logdir while both run)
    monitor_cfg = yaml.safe_load(Path(os.environ.get("SG_MONITOR_CFG") or ROOT / "bench/configs" / f"{a.config}.yaml").read_text())
    pipe = make_pipeline(a.config, a.res["model_id_for_api"], P.provider_env(a.res), monitor_cfg,
                         log_path=logdir / f"events-{a.suite}.jsonl", run_id=f"{a.config}-{a.model}-{a.suite}-{int(time.time())}")
    if a.name:
        pipe.name = a.name
    suite = get_suite(VERSION, a.suite)
    by_ut = [(ut, [i for _, i in g]) for ut, g in groupby(pairs, key=lambda p: p[0])]
    rows, ok = [], False
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))  # so a kill still reaches the finally below
    try:
        with OutputLogger(str(logdir)):
            if a.attack == "none":
                for ut, _ in by_ut:
                    rows.append(run_task_without_injection_tasks(suite, pipe, suite.get_user_task_by_id(ut), logdir,
                                                                 a.force, VERSION))
            else:
                attack = load_attack(a.attack, suite, pipe)  # after pipe.name is set
                for ut, its in by_ut:  # explicit injection list honours --inj and --max-episodes
                    u, s = run_task_with_injection_tasks(suite, pipe, suite.get_user_task_by_id(ut), attack, logdir,
                                                         a.force, its, VERSION)
                    rows += list(zip(u.values(), s.values()))
        ok = True
    finally:  # a crash (500/429/kill) must still book the tokens already spent
        rec = {**spend_record(a, pipe.name, len(by_ut), len(todo), pipe.llm_counter.total, bud), "crashed": not ok}
        B.record(rec)
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
    p.add_argument("--max-episodes", type=int, default=None, help="stop after N episodes per suite (ASR sample)")
    p.add_argument("--key", default=None, choices=["A", "B"], help="ollama key (default A; --suite all: 2 suites/key)")
    p.add_argument("--logdir", default=None)
    p.add_argument("--name", default=None, help="override pipeline name (e.g. openai-compatible-multi-agent "
                                                "to resume the raw-fork-CLI NONE baseline)")
    p.add_argument("--force", action="store_true", help="rerun even if logs exist")
    p.add_argument("--dry-run", action="store_true", help="print the budget-gate decision; no model calls")
    p.add_argument("--no-gate", action="store_true", help="orchestrator override: run even if the gate refuses")
    p.add_argument("--_gated", action="store_true", help=argparse.SUPPRESS)  # child of --suite all: parent gated
    p.add_argument("--_run_id", default=None, help=argparse.SUPPRESS)  # parent's id, ties reservation to final row
    a = p.parse_args(argv)
    a._run_id = a._run_id or f"{a.config}-{a.model}-{os.getpid()}-{int(time.time())}"
    bud = P.load_budget()
    try:
        a.res = P.resolve(a.model, a.key, bud)
    except ValueError as e:
        print(f"REFUSE {e}", file=sys.stderr)
        return 2
    if a.res["provider"] != "ollama" and not P.env_key(a.res["key_name"]):  # before gate: no orphan reservation
        # ponytail: ollama keys stay checked late (provider_env) -- suite all splits A/B across children
        print(f"GATE REFUSE provider={a.res['provider']} model={P.canonical(a.model)} "
              f"reason={a.res['key_name']} not set (env or ~/.zshrc)", flush=True)
        return 2  # supervise.py: rc 2 = wait, not a try
    a.logdir = a.logdir or str(ROOT / "runs/mad" / a.config / P.dir_name(a.model))
    if a.config == "NONE" and P.canonical(a.model) == "openai/gpt-4.1" and not a.name:
        a.name = "openai-compatible-multi-agent"  # resume the paid raw-fork-CLI baseline logs (now via OpenRouter)
    suites = SUITES if a.suite == "all" else [a.suite]
    if not a._gated:
        if a.res["provider"] == "ollama" and a.suite == "all":
            a.res["key"] = None  # gate on the shared ollama cap across both keys
        code = check_gate(a, suites, bud)
        if a.dry_run or code:
            return code
    if a.suite != "all":
        return run_suite(a, bud)
    # --max-workers in the fork is broken for multi-agent: one process per suite
    base = list(argv if argv is not None else sys.argv[1:])
    for flag in ("--suite", "--key"):  # --key is ignored with --suite all: max 3 concurrent/key -> KEY_SPLIT
        if flag in base:
            i = base.index(flag)
            del base[i:i + 2]
    if a.key and a.res["provider"] == "ollama":
        print(f"--key {a.key} ignored with --suite all (KEY_SPLIT {KEY_SPLIT})", file=sys.stderr)
    procs = []
    for s in SUITES:
        extra = ["--key", KEY_SPLIT[s]] if a.res["provider"] == "ollama" else []
        procs.append(subprocess.Popen([sys.executable, __file__, *base, "--suite", s, *extra, "--_gated",
                                       "--_run_id", a._run_id]))
    codes = [pr.wait() for pr in procs]
    print("exit codes", dict(zip(SUITES, codes)))
    return 1 if any(codes) else 0  # negative = killed by signal


if __name__ == "__main__":
    sys.exit(main())
