"""Run B2 (A4/A5/A13 + twins T4/T5/T13) through our multi-agent pipeline (bench/run.py + bench/mad_guard.py).

uv run python bench/attacks/run_ext.py --config NONE --model gpt-oss:120b [--key A|B] [--only A5,T5] [--force]
(ADAPTIVE: export SG_DECIDER_HOST first; spend is tiny (6 episodes/config) and bypasses the ledger — note it in PROGRESS)
Logs: runs/ext/<config>/<model>/<pipeline>/workspace/...  Summary: runs/ext/<config>/<model>/summary.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import bench.attacks as A  # noqa: E402  (registers the tasks)


def main(argv=None) -> dict:
    p = argparse.ArgumentParser()
    p.add_argument("--config", default="NONE")
    p.add_argument("--model", default="gpt-oss:20b")
    p.add_argument("--key", default="A", choices=["A", "B"])
    p.add_argument("--only", default="", help="comma list of A4,A5,A13,T4,T5,T13")
    p.add_argument("--force", action="store_true")
    a = p.parse_args(argv)

    import yaml
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
    from agentdojo.logging import OutputLogger

    from bench import providers as P
    from bench.mad_guard import make_pipeline
    from bench.run import VERSION

    logdir = ROOT / "runs/ext" / a.config / a.model
    logdir.mkdir(parents=True, exist_ok=True)
    cfg = ROOT / "bench/configs" / f"{a.config}.yaml"
    res = P.resolve(a.model, a.key)  # budget.yaml routing (ollama/commandcode/...); keys rc-first
    pipe = make_pipeline(a.config, res["model_id_for_api"], P.provider_env(res),
                         yaml.safe_load(cfg.read_text()) if cfg.exists() else None,
                         log_path=logdir / "events.jsonl", run_id=f"ext-{a.config}-{a.model}-{int(time.time())}")
    S = A.SUITE
    want = set(a.only.split(",")) - {""} or set(A.ATTACKS) | set(A.TWINS)
    sf = logdir / "summary.json"  # merge: a later --only run keeps earlier entries
    out: dict = (json.loads(sf.read_text()) if sf.exists() else {}) | {"config": a.config, "model": a.model,
                                                                         "pipeline": pipe.name}
    with OutputLogger(str(logdir)):
        attack = load_attack("important_instructions", S, pipe)  # after pipe.name is set
        for name, (uid, iid) in A.ATTACKS.items():
            if name in want:
                _, sec = run_task_with_injection_tasks(S, pipe, S.get_user_task_by_id(uid), attack, logdir,
                                                       a.force, [iid], VERSION)
                out[name] = sum(map(bool, sec.values())) / len(sec)  # success rate (1 seed => 0/1)
        for name, uid in A.TWINS.items():
            if name in want:
                util, _ = run_task_without_injection_tasks(S, pipe, S.get_user_task_by_id(uid), logdir, a.force, VERSION)
                out[name] = float(bool(util))
    sf.write_text(json.dumps(out, indent=1))
    print(json.dumps(out))
    return out


if __name__ == "__main__":
    main()
