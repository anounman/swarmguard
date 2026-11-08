"""Metrics from AgentDojo-format run logs (PLAN §5 stage 4).

Reuse: per-file loading/validation is agentdojo's own `load_task_results` / `TaskResults`
(bench/mad/src/agentdojo/benchmark.py). Not `load_suite_results`/`create_results_table.make_dataframe`:
both raise FileNotFoundError on partial runs (SC4), so we glob the tree and pool (micro-average, as the paper).
security=True in agentdojo == injection SUCCEEDED, so ASR = mean(security) over injected runs.

Layout: <runs>/<bench>/<config>/<model>/<pipeline>/<suite>/<user_task>/<attack|none>/<inj|none>.json
        <runs>/<bench>/<config>/<model>/**/events-<suite>.<attack>.jsonl  (sg.schema.Event lines; loop.py renames
        run.py's events-<suite>.jsonl after each process so the attack is known; other events files = attack unknown)
        <runs>/<bench>/spend.jsonl                          ({config, model, usd|est_usd|cost_usd, ...})
"""
from __future__ import annotations

import argparse
import json
import math
import re
import time
from pathlib import Path

import numpy as np
import yaml
from scipy.stats import binomtest
from agentdojo.benchmark import load_task_results

from sg.schema import Event, EventKind

TARGETS = Path(__file__).with_name("targets.yaml")


def wilson(k: int, n: int) -> list[float] | None:
    if n == 0:
        return None
    ci = binomtest(k, n).proportion_ci(method="wilson")
    return [round(100 * ci.low, 1), round(100 * ci.high, 1)]


def wald(k: int, n: int, z: float = 1.96) -> list[float] | None:
    # ponytail: Wald CI by hand (paper's Tab. V); scipy has no wald method, statsmodels not in .venv
    if n == 0:
        return None
    p = k / n
    h = z * math.sqrt(p * (1 - p) / n)
    return [round(100 * max(0.0, p - h), 1), round(100 * min(1.0, p + h), 1)]


def pct(k: int, n: int) -> float | None:
    return round(100 * k / n, 1) if n else None


def load_runs(model_dir: Path) -> tuple[list, int]:
    """All valid TaskResults under one <config>/<model> dir; returns (results, n_invalid).
    Deduped by (suite, user_task, attack, injection_task): two pipeline dirs in one cell (e.g. a raw-fork-CLI
    baseline + a run.py rerun) count once (first in sorted path order)."""
    out, bad, seen = [], 0, set()
    for f in sorted(model_dir.rglob("*.json")):
        try:
            attack, ut, suite = f.parent.name, f.parent.parent.name, f.parent.parent.parent.name
            pipeline_dir = f.parents[3]
            r = load_task_results(pipeline_dir.name, suite, ut, attack, f.stem, pipeline_dir.parent)
        except Exception:  # crashed mid-run (no utility key) or not a run log
            bad += 1
            continue
        k = (r.suite_name, r.user_task_id, r.attack_type or "none", r.injection_task_id)
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out, bad


EV_ATTACK = re.compile(r"^events-[^.]+\.(\w+)\.jsonl$")  # events-<suite>.<attack>.jsonl (written by loop.py)


def load_events(model_dir: Path) -> list[Event]:
    """Events with meta.attack stamped from the filename when the gateway did not stamp it (unknown -> left unset)."""
    evs = []
    for f in sorted(model_dir.rglob("events*.jsonl")):
        m = EV_ATTACK.match(f.name)
        for line in f.read_text().splitlines():
            if line.strip():
                try:
                    e = Event.model_validate_json(line)
                except Exception:
                    continue
                if m:
                    e.meta.setdefault("attack", m.group(1))
                evs.append(e)
    return evs


def is_benign_event(e: Event) -> bool:
    # unknown attack (no meta, legacy events-<suite>.jsonl) is NOT benign: excluded from FPR proxy and FP harvest
    return e.meta.get("attack") == "none" and not e.meta.get("injection_task_id")


def pctl(xs: list[float], q: float) -> float | None:
    return round(float(np.percentile(xs, 100 * q)), 2) if xs else None


def cell(model_dir: Path) -> dict:
    runs, invalid = load_runs(model_dir)
    # benchmark_suite_with_injections also runs injection tasks as user tasks -> exclude them
    runs = [r for r in runs if r.user_task_id.startswith("user_task_")]
    benign = [r for r in runs if (r.attack_type or "none") == "none"]
    attacked = [r for r in runs if (r.attack_type or "none") != "none"]
    ub, ua, sa = (sum(r.utility for r in benign), sum(r.utility for r in attacked), sum(r.security for r in attacked))
    evs = load_events(model_dir)
    ben = [e for e in evs if is_benign_event(e)]
    b_deny = sum(e.kind == EventKind.DENY for e in ben)
    b_calls = b_deny + sum(e.kind == EventKind.TOOL_CALL for e in ben)
    lat = [e.latency_ms for e in evs if e.kind in (EventKind.DENY, EventKind.TOOL_CALL) and e.latency_ms is not None]
    return {
        "utility_no_attack": pct(ub, len(benign)),
        "utility_no_attack_ci": wald(ub, len(benign)),
        "utility_under_attack": pct(ua, len(attacked)),
        "asr": pct(sa, len(attacked)),
        "asr_ci": wilson(sa, len(attacked)),
        "n_user_tasks": len(benign),
        "n_injected": len(attacked),
        "n_successful_attacks": sa,
        "errors": sum(r.error is not None for r in runs),
        "invalid_logs": invalid,
        "suites": sorted({r.suite_name for r in runs}),
        "n_events": len(evs),
        "denied_calls_benign_rate": pct(b_deny, b_calls),
        "denied_calls": sum(e.kind == EventKind.DENY for e in evs),
        "attenuations": sum(e.kind == EventKind.ATTENUATE for e in evs),
        "kills": sum(e.kind == EventKind.KILL for e in evs),
        "p50_latency_ms": pctl(lat, 0.50),
        "p95_latency_ms": pctl(lat, 0.95),
        "est_usd": None,
        "utility_delta_vs_none": None,  # filled in compute()
        "asr_drop_vs_none": None,
        "utility_gain_vs_rules": None,
    }


def spend(bench_dir: Path) -> dict[tuple[str, str], float]:
    out: dict[tuple[str, str], float] = {}
    f = bench_dir / "spend.jsonl"
    if not f.exists():
        return out
    for line in f.read_text().splitlines():
        try:
            d = json.loads(line)
        except Exception:
            continue
        usd = next((d[k] for k in ("est_usd", "usd", "cost_usd") if isinstance(d.get(k), (int, float))), 0.0)
        key = (str(d.get("config")), str(d.get("model")))
        out[key] = out.get(key, 0.0) + usd
    return out


def ci_overlap(a: list | None, b: list | None) -> bool:
    return a is not None and b is not None and a[0] <= b[1] and b[0] <= a[1]


def compute(runs_root: Path, bench: str = "mad", out: Path = Path("results")) -> dict:
    bench_dir = runs_root / bench
    cells: dict[str, dict[str, dict]] = {}
    usd = spend(bench_dir)
    for cdir in sorted(p for p in bench_dir.iterdir() if p.is_dir()) if bench_dir.exists() else []:
        for mdir in sorted(p for p in cdir.iterdir() if p.is_dir()):
            c = cell(mdir)
            c["est_usd"] = round(usd[(cdir.name, mdir.name)], 4) if (cdir.name, mdir.name) in usd else None
            cells.setdefault(cdir.name, {})[mdir.name] = c
    # "better by how much": per model. One sign convention: delta = ours - NONE (negative utility delta = cost).
    # H2 gain = ADAPTIVE - ADAPTIVE_RULES utility, only "at equal ASR" (PLAN §6): ASR Wilson CIs must overlap.
    for cfg, models in cells.items():
        for m, c in models.items():
            base = cells.get("NONE", {}).get(m, {})
            rules = cells.get("ADAPTIVE_RULES", {}).get(m, {})
            sub = lambda a, b: round(a - b, 1) if a is not None and b is not None else None  # noqa: E731
            c["utility_delta_vs_none"] = sub(c["utility_no_attack"], base.get("utility_no_attack"))
            c["asr_drop_vs_none"] = sub(base.get("asr"), c["asr"])
            c["utility_gain_vs_rules"] = (sub(c["utility_no_attack"], rules.get("utility_no_attack"))
                                          if ci_overlap(c["asr_ci"], rules.get("asr_ci")) else None)
    dec_f = out / "decider_eval.json"
    return {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "bench": bench,
        "runs": cells,
        "decider": json.loads(dec_f.read_text()) if dec_f.exists() else {},
        "reported": yaml.safe_load(TARGETS.read_text())["reported"],
    }


def fmt(v) -> str:
    if v is None:
        return "–"
    if isinstance(v, list):
        return f"[{v[0]}, {v[1]}]"
    return str(v)


def to_markdown(m: dict) -> str:
    L = [f"# Results ({m['bench']}) — generated {m['generated']}", "",
         "Ours = measured from run logs (pooled over suites; ASR Wilson 95% CI, utility Wald 95% CI). "
         "ASR = % injected runs where the injection goal was achieved. Δ = ours − NONE (negative = utility cost).", "",
         "| Config | Model | Utility | 95% CI | Util. under attack | ASR | 95% CI | n benign | n injected | errors "
         "| benign denied % | attenuate | kill | p50 ms | p95 ms | util Δ vs NONE | $ |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for cfg, models in m["runs"].items():
        for model, c in models.items():
            L.append("| " + " | ".join(fmt(x) for x in [
                cfg, model, c["utility_no_attack"], c["utility_no_attack_ci"], c["utility_under_attack"], c["asr"],
                c["asr_ci"], c["n_user_tasks"], c["n_injected"], c["errors"], c["denied_calls_benign_rate"],
                c["attenuations"], c["kills"], c["p50_latency_ms"], c["p95_latency_ms"], c["utility_delta_vs_none"],
                c["est_usd"]]) + " |")
    L += ["", "## Reference (reported, not replicated)†", "",
          "| Model | ASR none | ASR indiv-CaMeL | ASR multi-CaMeL | Util none | Util indiv-CaMeL | Util multi-CaMeL "
          "| Util Δ multi vs none |", "|---|---|---|---|---|---|---|---|"]
    for model, r in m["reported"]["models"].items():
        L.append(f"| {model} | {r['asr_none']}† | {r['asr_indiv']}† | {r['asr_multi']}† | {r['util_none']}† "
                 f"| {r['util_indiv']}† | {r['util_multi']}† | {round(r['util_multi'] - r['util_none'], 1)}† |")
    L += ["", f"† Reported in Peters-Gill et al. (2026), {m['reported']['source']}, Tab. III (ASR, n=949) / "
          "Tab. V (utility, n=97); models via OpenRouter; not replicated by us.", ""]
    if m["decider"]:
        L += ["## Decider (offline, B3)", "", "```json", json.dumps(m["decider"], indent=2), "```", ""]
    return "\n".join(L)


def main(argv: list[str] | None = None) -> dict:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default="runs")
    ap.add_argument("--bench", default="mad")
    ap.add_argument("--out", default="results")
    a = ap.parse_args(argv)
    out = Path(a.out)
    m = compute(Path(a.runs), a.bench, out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps(m, indent=2))
    (out / "results.md").write_text(to_markdown(m))
    print(f"metrics -> {out}/metrics.json, {out}/results.md")
    return m


if __name__ == "__main__":
    main()
