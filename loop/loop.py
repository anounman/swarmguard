"""The loop (PLAN §5): build -> smoke -> bench -> metrics -> compare -> harvest -> (retrain) -> sync.

  python -m loop.loop --stage build|smoke|bench|metrics|compare|harvest|retrain|sync|all --iter N [--dry-run]
Each iteration writes loop/iter_N/{metrics.json,diff.md}. `all` stops when every target PASSes or past the
deadline in loop/config.yaml. Bench/smoke shell out to bench/run.py, one process per suite:
  uv run python bench/run.py --bench mad --config X --model M --suite S --attack A --logdir D [--key K] [--n N]
      [--inj I] [--max-episodes E]
for A in the item's attacks (none -> benign utility, important_instructions -> ASR), sequentially per cell.
Every command is first run with --dry-run (budget gate, budget.yaml): exit 0 = launch, else the cell is skipped.
Lanes (config.yaml, one per provider) run concurrently; --dry-run prints the plan + gate decisions, launches nothing.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from loop import compare, harvest, metrics

ROOT = Path(__file__).resolve().parent.parent
CFG = yaml.safe_load((Path(__file__).with_name("config.yaml")).read_text())
_print_lock = threading.Lock()


class StageFailed(RuntimeError):
    pass


def log(*a) -> None:
    with _print_lock:
        print(*a, flush=True)


def sh(cmd: list[str]) -> None:
    log("$", " ".join(cmd))
    if subprocess.run(cmd, cwd=ROOT).returncode != 0:
        raise StageFailed(" ".join(cmd))


def budget() -> dict:
    return yaml.safe_load(metrics.BUDGET.read_text())


def run_cmd(config: str, model: str, suite: str, attack: str, logdir: Path, key: str | None = None,
            n: int | None = None, inj: str | None = None, max_episodes: int | None = None) -> list[str]:
    cmd = [sys.executable, "bench/run.py", "--bench", CFG["bench"], "--config", config, "--model", model,
           "--suite", suite, "--attack", attack, "--logdir", str(logdir)]
    for flag, v in (("--key", key), ("--n", n), ("--inj", inj), ("--max-episodes", max_episodes)):
        if v:
            cmd += [flag, str(v)]
    return cmd


def suite_keys(model: str, suites: list[str]) -> list[tuple[str, str | None]]:
    """(suite, ollama key) pairs: 2 suites per Ollama key (3-concurrent limit); other providers take no --key."""
    if metrics.provider_of(model, budget()) != "ollama":
        return [(s, None) for s in suites]
    keyed = {s: k for k, ss in CFG["ollama_keys"].items() for s in ss}
    return [(s, keyed.get(s, "A")) for s in suites]


def gate(cmd: list[str]) -> bool | None:
    """bench/run.py --dry-run: True = allowed (rc 0); False = budget refusal (rc 2 + stdout 'GATE REFUSE ...') -> skip;
    None = anything else (crash, unknown flag, missing/stale key 'REFUSE ...' on stderr) -> caller counts a failure."""
    r = subprocess.run(cmd + ["--dry-run"], cwd=ROOT, capture_output=True, text=True)
    out = (r.stdout or "").strip().splitlines()[-1:]
    last = out or (r.stderr or "").strip().splitlines()[-1:] or ["(no output)"]
    ok = True if r.returncode == 0 else (False if r.returncode == 2 and out and out[0].startswith("GATE REFUSE") else None)
    log(f"[gate] {({True: 'OK  ', False: 'SKIP'}).get(ok, 'ERR ')} rc={r.returncode} {' '.join(cmd[2:])} :: {last[0]}")
    return ok


def events_size(logdir: Path, suite: str) -> int:
    f = logdir / f"events-{suite}.jsonl"
    return f.stat().st_size if f.exists() else 0


def tag_events(logdir: Path, suite: str, attack: str, offset: int = 0) -> None:
    """run.py appends to events-<suite>.jsonl for every attack; move the bytes THIS process wrote (after `offset`, the
    size before Popen) to events-<suite>.<attack>.jsonl so metrics/harvest know which events are benign (gateway events
    carry no attack meta yet). Older content (e.g. supervise.py's mixed-attack lines) stays untagged = attack unknown."""
    src = logdir / f"events-{suite}.jsonl"
    if not src.exists():
        return
    with src.open("rb") as f:
        f.seek(offset)
        new = f.read()
    end = offset + len(new)
    # ponytail: if another writer (supervise.py) appended meanwhile, leave everything untagged rather than lose lines;
    # the size check -> truncate window is microseconds.
    if src.stat().st_size != end:
        log(f"[tag] {src} grew while tagging (concurrent writer?) -> left untagged")
        return
    with (logdir / f"events-{suite}.{attack}.jsonl").open("ab") as f:
        f.write(new)
    src.unlink() if offset == 0 else os.truncate(src, offset)


def suites_parallel(config: str, item: dict, logdir: Path, dry: bool = False, n: int | None = None,
                    inj: str | None = None) -> list[str]:
    """Per attack (sequential): one process per suite (fork's --max-workers>1 is broken for multi-agent), each gated.
    Returns failed '<config>/<model>/<suite>/<attack>' cells instead of raising, so one rate-limited suite doesn't
    stop the rest. Gate-refused (budget) cells are logged and skipped (not failures); gate errors are failures."""
    if not (ROOT / "bench/run.py").exists():
        raise StageFailed("bench/run.py missing")
    model, bad = item["model"], []
    for attack in item.get("attacks", CFG["attacks"]):
        procs = []
        for s, key in suite_keys(model, item.get("suites", CFG["suites"])):
            cmd = run_cmd(config, model, s, attack, logdir, key, n, inj, item.get("max_episodes"))
            # ponytail: suites of one cell are gated one by one; parallel suites can jointly overshoot by < 1 cell
            ok = gate(cmd)
            if ok is None:
                bad.append(f"{config}/{model}/{s}/{attack} (gate error)")
            if not ok or dry:
                continue
            log("$", " ".join(cmd))
            off = events_size(logdir, s)
            procs.append((s, off, subprocess.Popen(cmd, cwd=ROOT)))
        for s, off, p in procs:
            if p.wait() != 0:
                bad.append(f"{config}/{model}/{s}/{attack}")
            tag_events(logdir, s, attack, off)
    return bad


def model_dir(runs: Path, config: str, model: str) -> Path:
    return runs / CFG["bench"] / config / metrics.model_dirname(model)


def remaining_usd(provider: str, runs: Path) -> float:
    """cap - spent for a provider (no reserve), from budget.yaml + spend.jsonl; used by only_if_remaining_usd_gt."""
    p = budget()["providers"].get(provider, {})
    cap = p.get("cap_usd", p.get("cap_usd_total", p.get("month_usd", 0.0)))
    return cap - metrics.spend_summary(runs / CFG["bench"])["by_provider"].get(provider, 0.0)  # = B.spent() (gate's)


def run_lane(name: str, items: list[dict], runs: Path, dry: bool) -> list[str]:
    bad = []
    for item in items:
        if (lim := item.get("only_if_remaining_usd_gt")) is not None:
            rem = remaining_usd(name, runs)
            if rem <= lim:
                log(f"[lane {name}] SKIP {item['model']} {item['configs']}: remaining ${rem:.2f} <= ${lim}")
                continue
        for config in item["configs"]:
            log(f"[lane {name}] {config} {item['model']} suites={item.get('suites', 'all')} "
                f"attacks={item.get('attacks', CFG['attacks'])}" + (" (dry-run)" if dry else ""))
            bad += suites_parallel(config, item, model_dir(runs, config, item["model"]), dry)
    return bad


def stage_build(a) -> None:
    sh(["uv", "run", "pytest", "-q"])


def stage_smoke(a) -> None:
    s = CFG["smoke"]
    item = {"model": s["model"]}
    bad = [x for config in s["configs"]
           for x in suites_parallel(config, item, Path(a.runs) / "smoke" / config / metrics.model_dirname(s["model"]),
                                    a.dry_run, s["n"], s.get("inj"))]
    if bad:
        raise StageFailed(f"smoke failed: {bad}")


def stage_bench(a) -> None:
    # resumable: agentdojo skips existing valid logs. Lanes concurrent; a failed cell doesn't stop the others;
    # the stage fails at the end.
    with ThreadPoolExecutor(max_workers=len(CFG["lanes"])) as ex:
        futs = [ex.submit(run_lane, name, items, Path(a.runs), a.dry_run) for name, items in CFG["lanes"].items()]
        bad = [x for f in futs for x in f.result()]
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
    print(f"[retrain] convert train/rows_iter_*.jsonl into the box's data_v2 split (train/README.md), scp to "
          f"~/swarmguard-train, then run on the box:\n  {cmd}\n"
          f"  then: bash export.sh out/decider_v2/merged && ollama create swarmguard-decider:v{a.iter} -f Modelfile "
          f"(back to bench, ADAPTIVE only; add ADAPTIVE to smoke.configs)")


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
    if a.dry_run:
        stage_smoke(a)
        stage_bench(a)
        return
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
    ap.add_argument("--dry-run", action="store_true", help="smoke/bench: print plan + budget-gate decisions, launch nothing")
    a = ap.parse_args(argv)
    try:
        r = STAGES[a.stage](a)
    except StageFailed as e:
        print(f"[loop] stage {a.stage} FAILED: {e}")
        sys.exit(1)
    if a.stage == "sync" or a.stage == "all" or a.dry_run:
        return
    if a.stage != "build":
        stage_sync(a, f"stage {a.stage} done" + (f" all_pass={r}" if isinstance(r, bool) else ""))


if __name__ == "__main__":
    main()
