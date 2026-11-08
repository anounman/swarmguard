"""The loop (PLAN §5): build -> smoke -> bench -> metrics -> compare -> harvest -> (retrain) -> sync.

  python -m loop.loop --stage build|smoke|bench|metrics|compare|harvest|retrain|sync|all --iter N
Each iteration writes loop/iter_N/{metrics.json,diff.md}. `all` stops when every target PASSes or past the
deadline in loop/config.yaml. Bench/smoke shell out to S2's CLI:
  uv run python bench/run.py --bench mad --config X --model M --suite S --attack A --n N --logdir D
for A in config.yaml `attacks` (none -> benign utility, important_instructions -> ASR), sequentially per cell.
"""
from __future__ import annotations

import argparse
import datetime as dt
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from loop import compare, harvest, metrics

ROOT = Path(__file__).resolve().parent.parent
CFG = yaml.safe_load((Path(__file__).with_name("config.yaml")).read_text())


class StageFailed(RuntimeError):
    pass


def sh(cmd: list[str]) -> None:
    print("$", " ".join(cmd), flush=True)
    if subprocess.run(cmd, cwd=ROOT).returncode != 0:
        raise StageFailed(" ".join(cmd))


def run_cmd(config: str, model: str, suite: str, n: int | None, logdir: Path, attack: str) -> list[str]:
    cmd = [sys.executable, "bench/run.py", "--bench", CFG["bench"], "--config", config, "--model", model,
           "--suite", suite, "--attack", attack, "--logdir", str(logdir)]
    return cmd + (["--n", str(n)] if n else [])


def tag_events(logdir: Path, suite: str, attack: str) -> None:
    """run.py writes events-<suite>.jsonl for every attack; move it to events-<suite>.<attack>.jsonl so metrics/harvest
    know which events are benign (gateway events carry no attack meta yet)."""
    src = logdir / f"events-{suite}.jsonl"
    if src.exists():
        with (logdir / f"events-{suite}.{attack}.jsonl").open("a") as f:
            f.write(src.read_text())
        src.unlink()


def suites_parallel(config: str, model: str, n: int | None, logdir: Path) -> list[str]:
    """Per attack (sequential): one process per suite (fork's --max-workers>1 is broken for multi-agent).
    Returns failed '<suite>/<attack>' cells instead of raising, so one rate-limited suite doesn't stop the rest."""
    if not (ROOT / "bench/run.py").exists():
        raise StageFailed("bench/run.py missing (S2 not merged yet)")
    bad = []
    for attack in CFG["attacks"]:
        procs = []
        for s in CFG.get("model_suites", {}).get(model, CFG["suites"]):
            cmd = run_cmd(config, model, s, n, logdir, attack)
            print("$", " ".join(cmd), flush=True)
            procs.append((s, subprocess.Popen(cmd, cwd=ROOT)))
        for s, p in procs:
            if p.wait() != 0:
                bad.append(f"{config}/{model}/{s}/{attack}")
            tag_events(logdir, s, attack)
    return bad


def model_dir(runs: Path, config: str, model: str) -> Path:
    return runs / CFG["bench"] / config / model


def stage_build(a) -> None:
    sh(["uv", "run", "pytest", "-q"])


def stage_smoke(a) -> None:
    s = CFG["smoke"]
    bad = [x for config in s["configs"]
           for x in suites_parallel(config, s["model"], s["n"], Path(a.runs) / "smoke" / config / s["model"])]
    if bad:
        raise StageFailed(f"smoke failed: {bad}")


def stage_bench(a) -> None:
    # resumable: agentdojo skips existing valid logs. Order NONE -> STATIC -> ADAPTIVE_RULES -> ADAPTIVE.
    # A failed cell doesn't stop the others; the stage fails at the end.
    bad = [x for config in CFG["configs"] for model, cfgs in CFG["models"].items() if config in cfgs
           for x in suites_parallel(config, model, None, model_dir(Path(a.runs), config, model))]
    if bad:
        raise StageFailed(f"bench failed cells: {bad}")


def stage_metrics(a) -> None:
    metrics.main(["--runs", a.runs, "--bench", CFG["bench"], "--out", a.results])
    it = iter_dir(a)
    it.mkdir(parents=True, exist_ok=True)
    shutil.copy(Path(a.results) / "metrics.json", it / "metrics.json")


def stage_compare(a) -> bool:
    prev = Path(a.loopdir) / f"iter_{a.iter - 1}" / "metrics.json"
    return compare.run(iter_dir(a) / "metrics.json", iter_dir(a), prev if a.iter > 0 else None)


def stage_harvest(a) -> None:
    harvest.main(["--runs", a.runs, "--bench", CFG["bench"], "--iter", str(a.iter), "--out-dir", a.train_dir])


def stage_retrain(a) -> None:
    """Only if decider targets failed. Runs on the Linux box (C8); orchestrator executes it via pc-compute."""
    cmd = CFG["retrain_cmd"].format(iter=a.iter)
    if not (ROOT / "train/train_lora.py").exists():
        print(f"[retrain] SKIP: train/train_lora.py not ready (S3). When ready, on the box run:\n  {cmd}")
        return
    print(f"[retrain] merge train/rows_iter_*.jsonl -> train/rows_all.jsonl, sync to box, then run on the box:\n  {cmd}\n"
          f"  then: ollama create swarmguard-decider:v{a.iter} -f train/Modelfile  (back to bench, ADAPTIVE only)")


def stage_sync(a, note: str = "") -> None:
    it = iter_dir(a)
    it.mkdir(parents=True, exist_ok=True)
    with (it / "diff.md").open("a") as f:
        f.write(f"- {dt.datetime.now().strftime('%H:%M')} iter {a.iter}: {note or 'sync'}\n")


def iter_dir(a) -> Path:
    return Path(a.loopdir) / f"iter_{a.iter}"


def past_deadline() -> bool:
    return dt.datetime.now(dt.timezone.utc) > dt.datetime.fromisoformat(CFG["deadline"])


def decider_failed(a) -> bool:
    import json
    f = iter_dir(a) / "compare.json"
    if not f.exists():
        return False
    return any(t["id"].startswith("decider") and t["status"] != "PASS" for t in json.loads(f.read_text())["targets"])


def stalled(a) -> bool:
    """Iteration produced the same measurements as the previous one (no new logs; retrain is a manual step on the box),
    so another pass would only spin until the deadline."""
    import json
    prev = Path(a.loopdir) / f"iter_{a.iter - 1}" / "metrics.json"
    cur = iter_dir(a) / "metrics.json"
    return a.iter > 0 and prev.exists() and json.loads(prev.read_text())["runs"] == json.loads(cur.read_text())["runs"]


def run_all(a) -> None:
    stage_build(a)
    stage_smoke(a)
    while True:
        try:
            stage_bench(a)
        except StageFailed as e:  # partial bench still yields metrics; failed cells are retried next pass (resumable)
            print(f"[loop] bench partial: {e}")
        stage_metrics(a)
        ok = stage_compare(a)
        stage_harvest(a)
        if not ok and decider_failed(a):
            stage_retrain(a)
        stage_sync(a, f"all_pass={ok}")
        if ok or past_deadline() or stalled(a):
            print(f"[loop] stop: all_pass={ok} past_deadline={past_deadline()} stalled={stalled(a)} (iter {a.iter})")
            return
        a.iter += 1


STAGES = {"build": stage_build, "smoke": stage_smoke, "bench": stage_bench, "metrics": stage_metrics,
          "compare": stage_compare, "harvest": stage_harvest, "retrain": stage_retrain, "sync": stage_sync,
          "all": run_all}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", required=True, choices=list(STAGES))
    ap.add_argument("--iter", type=int, default=0)
    ap.add_argument("--runs", default="runs")
    ap.add_argument("--results", default="results")
    ap.add_argument("--loopdir", default="loop")
    ap.add_argument("--train-dir", default="train")
    a = ap.parse_args(argv)
    try:
        r = STAGES[a.stage](a)
    except StageFailed as e:
        print(f"[loop] stage {a.stage} FAILED: {e}")
        sys.exit(1)
    if a.stage == "sync" or a.stage == "all":
        return
    if a.stage != "build":
        stage_sync(a, f"stage {a.stage} done" + (f" all_pass={r}" if isinstance(r, bool) else ""))


if __name__ == "__main__":
    main()
