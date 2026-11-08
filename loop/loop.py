"""The loop (PLAN §5): build -> smoke -> bench -> metrics -> compare -> harvest -> (retrain) -> sync.

  python -m loop.loop [--stage build|smoke|bench|metrics|compare|harvest|retrain|sync|all] --iter N [--dry-run]
      [--sub dataset|box|calibrate]   (retrain only: run one sub-step; `make calibrate` = --sub calibrate)
harvest = FN/FP windows (loop/harvest.py) + train.from_mad_runs over config `harvest.mad_configs` -> rows_iter_N_mad.jsonl.
retrain (decider v3, PLAN §8a) = dataset (train.merge_v3: v2 + harvested + synth) -> box (print BOX_COMMANDS.md a-c with
tag swarmguard-decider:v{decider.version+1}; the orchestrator executes them) -> calibrate (train/eval.py on val + tests
against $SG_DECIDER_HOST, --calibrate-from -> loop/iter_N/risk_map.yaml + results/decider_eval.json summary).
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
import json
import os
import re
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
    mad = CFG["harvest"]["mad_configs"]
    if a.dry_run:
        log(f"[harvest] FN/FP windows -> {a.train_dir}/rows_iter_{a.iter}.jsonl")
        log("[harvest] $", " ".join(harvest.mad_cmd(a.runs, CFG["bench"], mad, a.train_dir, a.iter)))
        return
    try:
        harvest.main(["--runs", a.runs, "--bench", CFG["bench"], "--iter", str(a.iter), "--out-dir", a.train_dir,
                      "--mad-configs", *mad])
    except subprocess.CalledProcessError as e:
        raise StageFailed(f"train.from_mad_runs: {e}") from e


def new_version() -> int:
    """decider.version = the tag served now; retrain builds the next one (orchestrator bumps the config once served)."""
    return CFG["decider"]["version"] + 1


def merge_cmd(a) -> list[str]:
    td = Path(a.train_dir)
    synth = str(td / CFG["synth"]["rows"]) if CFG["synth"]["enabled"] else os.devnull
    return [sys.executable, "-m", "train.merge_v3", "--v2", str(td / "data"),
            "--mad", str(td / f"rows_iter_{a.iter}_mad.jsonl"), "--synth", synth,
            "--extra", str(td / f"rows_iter_{a.iter}_fnfp.jsonl"), "--out", str(td / "data_v3")]


def box_commands(n: int) -> str:
    """BOX_COMMANDS.md steps a-c (push, train, export; bash blocks) with the v3 tag/paths bumped to v{n}. Steps d-e
    (eval, calibration) are the calibrate sub-step. data_v3/ is the dataset dir and stays."""
    txt = (ROOT / CFG["decider"]["box_commands"]).read_text().split("## a.", 1)[1].split("## d.", 1)[0]
    blocks = re.findall(r"```bash\n(.*?)```", txt, re.S)
    # ponytail: textual bump of the doc's v3 names (decider_v3, :v3, train_v3.log, ..._v3_val.json); data_v3 stays
    return re.sub(r"(?<!data_)v3(?=\b|_)", f"v{n}", "\n".join(blocks))


def eval_cmds(a, n: int) -> dict[Path, list[str]]:
    td, res, c = Path(a.train_dir), Path(a.results), CFG["calibration"]
    host = os.environ.get(CFG["decider"]["host_env"]) or f"${CFG['decider']['host_env']}"
    base = [sys.executable, "train/eval.py", "--endpoint", host, "--model", f"swarmguard-decider:v{n}"]
    val, test = res / f"decider_eval_v{n}_val.json", res / f"decider_eval_v{n}_test.json"
    return {val: base + ["--splits", str(td / "data_v3/val.jsonl"), "--limit", str(c["val_limit"]), "--out", str(val)],
            test: base + ["--splits", str(td / "data/test_ood.jsonl"), str(td / "data/test_drift.jsonl"),
                          str(td / "data_v3/test_mad_ood.jsonl"), "--limit", str(c["test_limit"]), "--out", str(test)]}


def attenuate_raw(knots: list) -> float:
    """Raw decider risk the risk_map sends to 6.0 (action_for: 6 = ATTENUATE)."""
    for (x0, y0), (x1, y1) in zip(knots, knots[1:]):
        if y0 < 6.0 <= y1:
            return x0 + (6.0 - y0) * (x1 - x0) / (y1 - y0)
    return 10.0


def decider_summary(val: dict, test: dict | None) -> dict:
    """Flat keys for the decider.* targets (loop/targets.yaml); metrics.py loads results/decider_eval.json as `decider`.
    FPR at the ATTENUATE boundary is measured on held-out test_mad_ood (falls back to val) at the val-calibrated cutoff."""
    sp = (test or {}).get("splits", {})
    ood = sp.get("test_ood.jsonl", {})
    x6 = attenuate_raw(val["calibration"]["risk_map"])
    sw = sp.get("test_mad_ood.jsonl", {}).get("sweep") or val["calibration"]["sweep"]
    fpr = next((r["fpr"] for r in sw if r["cutoff"] >= x6), None)
    return {"f1": ood.get("f1@risk>=8"), "fpr_at_95_recall": ood.get("fpr@95recall"),
            "test_mad_ood_f1": sp.get("test_mad_ood.jsonl", {}).get("f1@risk>=8"),
            "benign_fpr_attenuate": None if fpr is None else round(100 * fpr, 2), "attenuate_raw_cutoff": x6,
            "model": val.get("model"), "calibration": val["calibration"], "splits": sp}


def stage_calibrate(a) -> None:
    """retrain sub-step: eval the new decider on val (+ held-out tests), write loop/iter_N/risk_map.yaml. The
    orchestrator copies that line into the monitor block of bench/configs/ADAPTIVE.yaml + ADAPTIVE_AUDIT.yaml (+ host_model) before the next bench."""
    n = new_version()
    cmds = eval_cmds(a, n)
    served = bool(os.environ.get(CFG["decider"]["host_env"]))
    for out, cmd in cmds.items():
        if a.dry_run or (not out.exists() and not served):
            log("[retrain/calibrate] $", " ".join(cmd))
        elif not out.exists():
            sh(cmd)
    val, test = list(cmds)
    if a.dry_run or not val.exists():
        log(f"[retrain/calibrate] {'plan' if a.dry_run else 'PENDING (decider not served / no val eval)'}: "
            f"$ {sys.executable} train/eval.py --calibrate-from {val} > {iter_dir(a) / 'risk_map.yaml'}; "
            f"then copy it into bench/configs/ADAPTIVE.yaml + ADAPTIVE_AUDIT.yaml (monitor block) + host_model: swarmguard-decider:v{n}")
        return
    r = subprocess.run([sys.executable, "train/eval.py", "--calibrate-from", str(val)], cwd=ROOT, capture_output=True,
                       text=True)
    if r.returncode != 0:
        raise StageFailed(f"eval.py --calibrate-from: {r.stderr.strip()[-300:]}")
    it = iter_dir(a)
    it.mkdir(parents=True, exist_ok=True)
    (it / "risk_map.yaml").write_text(
        f"# swarmguard-decider:v{n}, calibrated on {val} (fpr targets {CFG['calibration']['fpr_targets']}).\n"
        f"# Orchestrator: paste over `risk_map:` in bench/configs/ADAPTIVE.yaml + ADAPTIVE_AUDIT.yaml (monitor block), set\n"
        f"# host_model: swarmguard-decider:v{n}, bump loop/config.yaml decider.version to {n}, then bench.\n"
        + r.stdout)
    summ = decider_summary(json.loads(val.read_text()), json.loads(test.read_text()) if test.exists() else None)
    (Path(a.results) / "decider_eval.json").write_text(json.dumps(summ, indent=1))
    log(f"[retrain/calibrate] -> {it / 'risk_map.yaml'}  benign FPR@ATTENUATE={summ['benign_fpr_attenuate']}%")


def stage_retrain(a) -> None:
    """Only if decider targets failed. Sub-steps: dataset (Mac) -> box (printed; orchestrator runs them on the Linux
    box, C8) -> calibrate (needs the new tag served at $SG_DECIDER_HOST; else prints what to run)."""
    sub, n = getattr(a, "sub", None), new_version()
    if sub in (None, "dataset"):
        td = Path(a.train_dir)
        if CFG["synth"]["enabled"] and not (td / CFG["synth"]["rows"]).exists():
            log(f"[retrain/dataset] synth rows missing; teacher (Command Code, <= ${CFG['synth']['budget_usd']}): "
                f"uv run python -m train.synth_teacher --out {td / 'data_v3'} --max-usd {CFG['synth']['budget_usd']}")
        cmd = merge_cmd(a)
        if a.dry_run:
            log(f"[retrain/dataset] wrap {td}/rows_iter_*.jsonl (FN/FP) -> {cmd[cmd.index('--extra') + 1]}")
            log("[retrain/dataset] $", " ".join(cmd))
        else:
            fnfp = sorted(p for p in td.glob("rows_iter_*.jsonl") if re.fullmatch(r"rows_iter_\d+\.jsonl", p.name))
            harvest.wrap_for_merge(fnfp, Path(cmd[cmd.index("--extra") + 1]))
            sh(cmd)
    if sub in (None, "box"):
        log(f"[retrain/box] tag swarmguard-decider:v{n} (v{n - 1} stays served); orchestrator runs on the box "
            f"({CFG['decider']['box_commands']}, base {CFG['decider']['base']}):\n{box_commands(n)}")
    if sub in (None, "calibrate"):
        stage_calibrate(a)


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
        log("[metrics] -> results/metrics.json + iter metrics.json; [compare] vs loop/targets.yaml")
        stage_harvest(a)
        log("[retrain] (only if decider targets fail) sub-steps: dataset -> box -> calibrate")
        stage_retrain(a)
        log("[sync] PROGRESS.md entry by the orchestrator (C10)")
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
    ap.add_argument("--stage", default="all", choices=list(STAGES))
    ap.add_argument("--sub", choices=["dataset", "box", "calibrate"], help="retrain: run one sub-step only")
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
