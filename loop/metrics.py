"""Metrics from AgentDojo-format run logs (PLAN §5 stage 4).

Reuse: per-file loading/validation is agentdojo's own `load_task_results` / `TaskResults`
(bench/mad/src/agentdojo/benchmark.py). Not `load_suite_results`/`create_results_table.make_dataframe`:
both raise FileNotFoundError on partial runs (SC4), so we glob the tree and pool (micro-average, as the paper).
security=True in agentdojo == injection SUCCEEDED, so ASR = mean(security) over injected runs.

Layout: <runs>/<bench>/<config>/<model>/<pipeline>/<suite>/<user_task>/<attack|none>/<inj|none>.json
        <runs>/<bench>/<config>/<model>/**/events-<suite>.<attack>.jsonl  (sg.schema.Event lines; loop.py renames
        run.py's events-<suite>.jsonl after each process so the attack is known; other events files = attack unknown)
        <runs>/<bench>/spend.jsonl     ({ts, provider, key, model, config, logdir, est_usd|usd|cost_usd, ...}; old rows
                                        have no provider/key/logdir -> inferred from budget.yaml)
Model dirs: a provider-prefixed model id is stored under its last path part (openai/gpt-4.1 -> gpt-4.1, so the anchor
lands next to the on-disk NONE/gpt-4.1 baseline and docs/REPORT.md keys keep working).
user_task_100..103 are bench/attacks carriers/twins registered on workspace -> excluded from utility/ASR.
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

from bench import budget as B
from sg.labels import SINKS
from sg.schema import Event, EventKind

TARGETS = Path(__file__).with_name("targets.yaml")
BUDGET = Path(__file__).resolve().parent.parent / "budget.yaml"
CARRIER_MIN = 100  # user_task_100+ = bench/attacks carriers/twins, not MultiAgentDojo tasks


def model_dirname(model: str) -> str:
    return model.split("/")[-1]


def provider_of(model: str, budget: dict | None = None) -> str:
    budget = budget if budget is not None else yaml.safe_load(BUDGET.read_text())
    return ((budget.get("prices") or {}).get(model) or {}).get("provider", "ollama")


def real_task(tid) -> bool:
    """A MultiAgentDojo user task (not an injection task run as a user task, not a carrier/twin)."""
    tid = str(tid or "")
    return tid.startswith("user_task_") and tid.rsplit("_", 1)[1].isdigit() and int(tid.rsplit("_", 1)[1]) < CARRIER_MIN


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


DENIED_PREFIX, DENY_ERR, KILL_ERR = "DENIED_", "PermissionError:", "AbortAgentError"  # sg/guard.py wording


def log_counts(runs: list) -> tuple[int, int]:
    """(denied, total) tool results in fork logs. Denied = sg/guard.py rename DENIED_<tool> or its 'PermissionError:'
    error text (attenuation). ponytail: a native tool PermissionError would count too (none in NONE logs)."""
    res = [m for r in runs for m in r.messages if m["role"] == "tool"]
    den = sum((m.get("tool_call") and m["tool_call"].function.startswith(DENIED_PREFIX))
              or (m.get("error") or "").startswith(DENY_ERR) for m in res)
    return den, len(res)


def killed(r, adaptive: bool = False) -> bool:
    # a sub-agent KILL surfaces as the orchestrator's tool error 'AbortAgentError: SwarmGuard stopped ...'.
    # An orchestrator-level KILL leaves no text: task_suite.py stores e.messages with error=None, so the log just
    # ends on the assistant's sink call with no tool result.
    # ponytail: dangling sink call = KILL only under ADAPTIVE*; NONE/STATIC dangle too (iteration cutoffs), never kills.
    last = r.messages[-1] if r.messages else {}
    dangling = last.get("role") == "assistant" and any(tc.function in SINKS for tc in last.get("tool_calls") or [])
    return (KILL_ERR in (r.error or "") or (adaptive and dangling)
            or any(KILL_ERR in (m.get("error") or "") for m in r.messages if m["role"] == "tool"))


def pctl(xs: list[float], q: float) -> float | None:
    return round(float(np.percentile(xs, 100 * q)), 2) if xs else None


def cell(model_dir: Path) -> dict:
    runs, invalid = load_runs(model_dir)
    # benchmark_suite_with_injections also runs injection tasks as user tasks -> exclude them (+ carriers/twins)
    runs = [r for r in runs if real_task(r.user_task_id)]
    benign = [r for r in runs if (r.attack_type or "none") == "none"]
    attacked = [r for r in runs if (r.attack_type or "none") != "none"]
    ub, ua, sa = (sum(r.utility for r in benign), sum(r.utility for r in attacked), sum(r.security for r in attacked))
    evs = [e for e in load_events(model_dir) if "user_task_id" not in e.meta or real_task(e.meta["user_task_id"])]
    b_deny, b_calls = log_counts(benign)  # from fork logs: events files may mix attack + benign (supervise.py)
    a_deny, a_calls = log_counts(attacked)
    # latency of a gateway check does not depend on the attack -> every events*.jsonl (tagged or not)
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
        "benign_suites": sorted({r.suite_name for r in benign}),  # utility comparisons gate on this (benign only)
        "attack_suites": sorted({r.suite_name for r in attacked}),  # ua_gain_vs_static gates on this (C24)
        "n_events": len(evs),
        # C27: per-suite breakdown — pooled utility/ASR are confounded by suite mix while cells are partial
        # (workspace = 560/949 injected and the easiest suite); the report's per-suite table reads these keys.
        "by_suite": {s: {"n_user_tasks": sum(r.suite_name == s for r in benign),
                         "n_injected": sum(r.suite_name == s for r in attacked),
                         "utility_no_attack": pct(sum(r.utility for r in benign if r.suite_name == s), sum(r.suite_name == s for r in benign)),
                         "utility_under_attack": pct(sum(r.utility for r in attacked if r.suite_name == s), sum(r.suite_name == s for r in attacked)),
                         "asr": pct(sum(r.security for r in attacked if r.suite_name == s), sum(r.suite_name == s for r in attacked))}
                     for s in sorted({r.suite_name for r in runs})},
        "denied_calls_benign_rate": pct(b_deny, b_calls),
        # ponytail: fork-log denials only; a killed sub-agent's history (and its earlier denials) is discarded
        "denied_calls_attack_rate": pct(a_deny, a_calls),
        "killed_runs": sum(killed(r, model_dir.parent.name.startswith("ADAPTIVE")) for r in runs),
        "denied_calls": sum(e.kind == EventKind.DENY for e in evs),
        "attenuations": sum(e.kind == EventKind.ATTENUATE for e in evs),
        "kills": sum(e.kind == EventKind.KILL for e in evs),
        "latency_p50_ms": pctl(lat, 0.50),
        "latency_p95_ms": pctl(lat, 0.95),
        "n_checks": len(lat),
        # ponytail: old names kept as aliases, loop/targets.yaml (not ours to edit) reads p50_latency_ms
        "p50_latency_ms": pctl(lat, 0.50),
        "p95_latency_ms": pctl(lat, 0.95),
        "est_usd": None,
        "utility_delta_vs_none": None,  # filled in compute()
        "asr_drop_vs_none": None,
        "utility_gain_vs_rules": None,
        "ua_gain_vs_static": None,  # utility under attack, ADAPTIVE - STATIC (PLAN §6 row added 08:20; loop sync C24)
        "utility_retention": None,  # % of own NONE utility (PLAN §6 H1, C13)
    }


def spend_rows(bench_dir: Path, budget: dict | None = None) -> list[dict]:
    """spend.jsonl rows normalised to {ts, provider, key, config, mdir, usd}. Glue to bench/budget.py (the gate's own
    accounting): superseded/expired reservations dropped (B.live), pre-C13 rows repriced from tokens (B.row_usd),
    provider inferred for old rows (B.row_provider). Broken lines are skipped."""
    budget = budget if budget is not None else yaml.safe_load(BUDGET.read_text())
    f = bench_dir / "spend.jsonl"
    rows = []
    for line in f.read_text().splitlines() if f.exists() else []:
        try:
            d = json.loads(line)
        except Exception:
            continue
        if isinstance(d, dict):
            rows.append(d)
    out = []
    for d in B.live(rows):
        prov, model = B.row_provider(d, budget), str(d.get("model"))
        out.append({"ts": d.get("ts") or 0, "provider": prov, "key": d.get("key") or "unknown",
                    "model": model_dirname(model), "config": str(d.get("config")), "usd": B.row_usd(d, budget),
                    "mdir": Path(d["logdir"]).name if d.get("logdir") else model_dirname(model)})
    return out


def spend(bench_dir: Path) -> dict[tuple[str, str], float]:
    out: dict[tuple[str, str], float] = {}
    for r in spend_rows(bench_dir):
        out[(r["config"], r["mdir"])] = out.get((r["config"], r["mdir"]), 0.0) + r["usd"]
    return out


def spend_summary(bench_dir: Path) -> dict:
    budget = yaml.safe_load(BUDGET.read_text())
    # every allowed provider present (0.0 if unspent) so docs/REPORT.md spend placeholders always resolve
    by_p = {p: 0.0 for p, c in (budget.get("providers") or {}).items() if (c or {}).get("allowed", True)}
    by_k: dict[str, float] = {}
    by_m: dict[str, float] = {}
    rows = spend_rows(bench_dir, budget)
    for r in rows:
        by_m[r["model"]] = by_m.get(r["model"], 0.0) + r["usd"]
        by_p[r["provider"]] = by_p.get(r["provider"], 0.0) + r["usd"]
        if r["provider"] == "ollama":
            by_k[r["key"]] = by_k.get(r["key"], 0.0) + r["usd"]
    rnd = lambda d: {k: round(v, 4) for k, v in sorted(d.items())}  # noqa: E731
    return {"total_usd": round(sum(r["usd"] for r in rows), 4), "by_provider": rnd(by_p), "by_ollama_key": rnd(by_k),
            "by_model": rnd(by_m)}


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
            # utility comparisons only on the same BENIGN suite set: pooled utilities over different suites (runs in
            # progress, or injected-only suites) are not comparable.
            same_b = c["benign_suites"] == base.get("benign_suites")
            same_r = c["benign_suites"] == rules.get("benign_suites")
            c["utility_delta_vs_none"] = sub(c["utility_no_attack"], base.get("utility_no_attack")) if same_b else None
            c["asr_drop_vs_none"] = sub(base.get("asr"), c["asr"])
            bu = base.get("utility_no_attack")
            c["utility_retention"] = (round(100 * c["utility_no_attack"] / bu, 1)
                                      if same_b and c["utility_no_attack"] is not None and bu else None)
            c["utility_gain_vs_rules"] = (sub(c["utility_no_attack"], rules.get("utility_no_attack"))
                                          if same_r and ci_overlap(c["asr_ci"], rules.get("asr_ci")) else None)
            static = cells.get("STATIC", {}).get(m, {})
            same_a = c.get("attack_suites") == static.get("attack_suites")  # None == None when the key is absent
            c["ua_gain_vs_static"] = (sub(c["utility_under_attack"], static.get("utility_under_attack"))
                                      if same_a and cfg.startswith("ADAPTIVE") and cfg != "ADAPTIVE_RULES" else None)  # v2/v3/v3b
    dec_f = out / "decider_eval.json"
    return {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "bench": bench,
        "runs": cells,
        "spend": spend_summary(bench_dir),
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
         "| benign denied % | attack denied % | attenuate | killed runs | p50 ms | p95 ms | util Δ vs NONE | retention % | $ |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for cfg, models in m["runs"].items():
        for model, c in models.items():
            L.append("| " + " | ".join(fmt(x) for x in [
                cfg, model, c["utility_no_attack"], c["utility_no_attack_ci"], c["utility_under_attack"], c["asr"],
                c["asr_ci"], c["n_user_tasks"], c["n_injected"], c["errors"], c["denied_calls_benign_rate"],
                c["denied_calls_attack_rate"], c["attenuations"], c["killed_runs"], c["latency_p50_ms"], c["latency_p95_ms"], c["utility_delta_vs_none"],
                c["utility_retention"], c["est_usd"]]) + " |")
    L += ["", "## Reference (reported, not replicated)†", "",
          "| Model | ASR none | ASR indiv-CaMeL | ASR multi-CaMeL | Util none | Util indiv-CaMeL | Util multi-CaMeL "
          "| Util Δ multi vs none |", "|---|---|---|---|---|---|---|---|"]
    for model, r in m["reported"]["models"].items():
        L.append(f"| {model} | {r['asr_none']}† | {r['asr_indiv']}† | {r['asr_multi']}† | {r['util_none']}† "
                 f"| {r['util_indiv']}† | {r['util_multi']}† | {round(r['util_multi'] - r['util_none'], 1)}† |")
    L += ["", f"† Reported in Peters-Gill et al. (2026), {m['reported']['source']}, Tab. III (ASR, n=949) / "
          "Tab. V (utility, n=97); models via OpenRouter; not replicated by us.", ""]
    sp = m.get("spend", {})
    L += ["## Spend (est. USD)", "", f"total {sp.get('total_usd')} · by provider {sp.get('by_provider')} · "
          f"Ollama by key {sp.get('by_ollama_key')} · by model {sp.get('by_model')}", ""]
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
    (out / "spend.json").write_text(json.dumps(m["spend"], indent=2))  # PLAN R6: per provider + per ollama key
    print(f"metrics -> {out}/metrics.json, {out}/results.md")
    return m


if __name__ == "__main__":
    main()
