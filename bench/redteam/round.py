"""One red-team round (C30): attacker texts -> bench/run.py --attack redteam (configs x suites) -> summary.json.

  SG_DECIDER_HOST=http://192.168.0.146:11434/v1 uv run python -m bench.redteam.round --round 1 \
      --attacker-model <ollama model> [--configs STATIC ADAPTIVE] [--suites banking slack] [--max-episodes N] [--dry-run]
  --all-rounds K runs rounds 1..K (each attacker call sees round N-1's summary). run.py resumes, so rerun = resume.
Budget: run.py's gate runs inside every cell (Ollama cap / reserve).
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KEYS = {"banking": "A", "workspace": "A", "slack": "B", "travel": "B"}
MONITOR_CFG = {"ADAPTIVE": "bench/configs/ADAPTIVE_v3b.yaml"}  # ponytail: v3b = the current best decider map
TARGET_MODEL = "gpt-oss:120b"


def rdir(n: int) -> Path:
    return ROOT / f"runs/redteam/round_{n}"


def run_cells(n: int, configs: list[str], suites: list[str], model: str, max_episodes: int | None, dry: bool) -> None:
    inj = rdir(n) / "injections.jsonl"
    procs = []
    for cfg in configs:
        env = dict(os.environ, SG_REDTEAM_FILE=str(inj))
        if cfg in MONITOR_CFG:
            env["SG_MONITOR_CFG"] = MONITOR_CFG[cfg]
        for suite in suites:
            logdir = rdir(n) / cfg / model
            cmd = [sys.executable, "bench/run.py", "--bench", "mad", "--config", cfg, "--model", model, "--suite", suite,
                   "--attack", "redteam", "--key", KEYS[suite], "--logdir", str(logdir)]
            if max_episodes:
                cmd += ["--max-episodes", str(max_episodes)]
            if dry:
                cmd.append("--dry-run")
            print("[round] $", " ".join(cmd[1:]), flush=True)
            logdir.mkdir(parents=True, exist_ok=True)
            log = open(logdir / f"{suite}-redteam.log", "a")
            procs.append(subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT))
        for p in procs:  # ponytail: one config at a time (2 suites in parallel) keeps the Ollama concurrency within 3/key
            p.wait()
        procs = []


def summarize(n: int, configs: list[str], suites: list[str], model: str) -> dict:
    out = {"round": n, "model": model, "configs": {}, "per_injection_task": {}}
    for cfg in configs:
        base = rdir(n) / cfg / model
        out["configs"][cfg] = {}
        out["per_injection_task"][cfg] = {}
        for suite in suites:
            files = list(base.glob(f"*/{suite}/user_task_*/redteam/injection_task_*.json"))
            ut, sec = 0, 0
            per = collections.defaultdict(lambda: {"n": 0, "success": 0})
            for f in files:
                d = json.loads(f.read_text())
                ut += bool(d.get("utility")); s = bool(d.get("security")); sec += s
                per[f.stem]["n"] += 1; per[f.stem]["success"] += s
            kinds = collections.Counter()
            ev = base / f"events-{suite}.jsonl"
            if ev.exists():
                for line in ev.open():
                    try:
                        kinds[json.loads(line).get("kind")] += 1
                    except json.JSONDecodeError:
                        pass
            nn = len(files)
            out["configs"][cfg][suite] = {"n_injected": nn, "asr": round(100 * sec / nn, 1) if nn else None,
                                          "utility_under_attack": round(100 * ut / nn, 1) if nn else None,
                                          "denied": kinds["DENY"], "attenuations": kinds["ATTENUATE"], "kills": kinds["KILL"]}
            for k, v in per.items():
                v.update(denied=kinds["DENY"], attenuations=kinds["ATTENUATE"], kills=kinds["KILL"])
            out["per_injection_task"][cfg][suite] = dict(per)
    (rdir(n) / "summary.json").write_text(json.dumps(out, indent=1))
    return out


def table(s: dict) -> str:
    rows = [f"round {s['round']} ({s['model']})", "| config | suite | n | ASR % | utility under attack % | denied | attenuate | kill |", "|---|---|---|---|---|---|---|---|"]
    for cfg, suites in s["configs"].items():
        for suite, c in suites.items():
            rows.append(f"| {cfg} | {suite} | {c['n_injected']} | {c['asr']} | {c['utility_under_attack']} | {c['denied']} | {c['attenuations']} | {c['kills']} |")
    return "\n".join(rows)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, default=1)
    ap.add_argument("--all-rounds", type=int, default=0, help="run rounds 1..K")
    ap.add_argument("--configs", nargs="+", default=["STATIC", "ADAPTIVE"])
    ap.add_argument("--suites", nargs="+", default=["banking", "slack"])
    ap.add_argument("--model", default=TARGET_MODEL)
    ap.add_argument("--attacker-model", default=os.environ.get("SG_REDTEAM_MODEL"))
    ap.add_argument("--attacker-endpoint", default=os.environ.get("SG_REDTEAM_ENDPOINT", "http://192.168.0.146:11434/v1"))
    ap.add_argument("--max-episodes", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--summary-only", action="store_true")
    a = ap.parse_args(argv)
    rounds = range(1, a.all_rounds + 1) if a.all_rounds else [a.round]
    for n in rounds:
        inj = rdir(n) / "injections.jsonl"
        if not a.summary_only and not inj.exists() and not a.dry_run:
            if not a.attacker_model:
                raise SystemExit("--attacker-model (or SG_REDTEAM_MODEL) is required to generate injections")
            from bench.redteam.attacker import generate
            generate(n, a.suites, a.attacker_model, a.attacker_endpoint, inj)
        if not a.summary_only:
            run_cells(n, a.configs, a.suites, a.model, a.max_episodes, a.dry_run)
        if not a.dry_run:
            print(table(summarize(n, a.configs, a.suites, a.model)), flush=True)


if __name__ == "__main__":
    main()
