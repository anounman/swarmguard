"""Budget gate + spend log (PLAN §5 bench stage, budget.yaml). Pure functions; no network."""
from __future__ import annotations

import json
import time
from pathlib import Path

from bench.providers import ROOT, canonical, provider_of

SPEND = ROOT / "runs/mad/spend.jsonl"
DEFAULT_TOK = (6000, 2000)  # prompt, completion per episode until >= 3 measured rows


def read_spend(path: Path | None = None) -> list[dict]:
    p = Path(path or SPEND)
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []


def row_provider(r: dict, budget: dict) -> str:
    if r.get("provider"):
        return r["provider"]
    # ponytail: pre-C13 rows carry no provider; legacy 'gpt-4.1' rows were OpenAI direct, the rest ollama.
    return "openai" if r.get("model") == "gpt-4.1" else provider_of(r.get("model", ""), budget)


RESERVE_TTL = 6 * 3600  # ponytail: a SIGKILLed run never releases its reservation; expire it instead


def row_usd(r: dict, budget: dict) -> float:
    """est_usd; pre-C13 rows (no provider) were priced with run.py's old table -> reprice at budget.yaml prices."""
    if r.get("provider") or r.get("reserved"):
        return r.get("est_usd") or 0
    try:
        pi, po = price(r.get("model", ""), budget)
        return ((r.get("prompt_tokens") or 0) * pi + (r.get("completion_tokens") or 0) * po) / 1e6
    except KeyError:
        return r.get("est_usd") or 0


def live(rows, now: float | None = None) -> list[dict]:
    """Drop reservations that a final row (same run_id) has replaced, or that expired."""
    now = now or time.time()
    done = {r.get("run_id") for r in rows if not r.get("reserved") and r.get("run_id")}
    return [r for r in rows if not r.get("reserved")
            or (r.get("run_id") not in done and now - r.get("ts", 0) < RESERVE_TTL)]


def spent(rows, provider, budget, key=None, since: float | None = None) -> float:
    return sum(row_usd(r, budget) for r in live(rows) if row_provider(r, budget) == provider
               and (key is None or r.get("key") == key) and (since is None or r.get("ts", 0) >= since))


def price(model: str, budget: dict) -> tuple[float, float]:
    p = budget["prices"][canonical(model)]
    return p["input"], p.get("output", p.get("output_est"))


def tokens_per_episode(rows, model) -> tuple[float, float, bool]:
    """(prompt, completion, measured). Uses rows with n_episodes, or legacy benign rows (episodes = n_tasks)."""
    m = canonical(model)

    def eps(r):  # n_episodes=0 (resumed, nothing to do) must stay 0, not fall back to n_tasks
        return r["n_episodes"] if r.get("n_episodes") is not None else (
            r.get("n_tasks") or 0 if r.get("attack") == "none" else 0)
    ok = [r for r in rows if canonical(r.get("model", "")) == m and not r.get("tokens_estimated")
          and not r.get("reserved") and not r.get("crashed") and eps(r) > 0 and (r.get("prompt_tokens") or 0) > 0]
    if len(ok) < 3:
        return (*DEFAULT_TOK, False)
    n = sum(eps(r) for r in ok)
    return sum(r["prompt_tokens"] for r in ok) / n, sum(r["completion_tokens"] for r in ok) / n, True


def plan_pairs(user_tasks, injection_tasks, attack, n=None, inj=None, max_episodes=None) -> list[tuple]:
    """Ordered (user_task, injection_task|None) episodes as run.py runs them; deterministic, so resumable."""
    uts = sorted(user_tasks, key=lambda t: int(t.rsplit("_", 1)[1]))[:n]
    if attack == "none":
        pairs = [(u, None) for u in uts]
    else:
        its = list(inj) if inj else sorted(injection_tasks, key=lambda t: int(t.rsplit("_", 1)[1]))
        pairs = [(u, i) for u in uts for i in its]
    return pairs[:max_episodes] if max_episodes else pairs


def missing(pairs, logdir, pipeline, suite, attack) -> list[tuple]:
    """Pairs without a fork log yet (path layout = agentdojo.benchmark.load_task_results)."""
    base = Path(logdir) / pipeline / suite
    return [(u, i) for u, i in pairs
            if not (base / u / (attack if i else "none") / f"{i or 'none'}.json").exists()]


def gate(model: str, episodes: int, budget: dict, rows: list[dict], key=None, now: float | None = None) -> dict:
    """Budget decision. allowed=False with a one-line reason if over cap/window or provider disallowed."""
    now = now or time.time()
    prov = provider_of(model, budget)
    pc = budget["providers"].get(prov) or {}
    pi, po = price(model, budget)
    tp, tc, measured = tokens_per_episode(rows, model)
    proj = episodes * (tp * pi + tc * po) / 1e6
    total = spent(rows, prov, budget)
    cap = pc.get("cap_usd_total", pc.get("cap_usd", pc.get("month_usd", 0)))
    remaining = cap - total - pc.get("reserve_usd", 0)
    d = {"provider": prov, "key": key, "model": canonical(model), "episodes": episodes, "spent_usd": round(total, 4),
         "remaining_usd": round(remaining, 4), "projected_usd": round(proj, 4), "tokens_measured": measured,
         "tokens_per_episode": round(tp + tc)}
    if prov == "ollama" and key and any(r.get("key") for r in rows):  # pre-C13 rows carry no key
        d["spent_key_usd"] = round(spent(rows, prov, budget, key=key), 4)
    reason = None
    if pc.get("allowed") is False or prov in ("openai", "groq"):
        reason = f"provider {prov} not allowed"
    elif proj > remaining:
        reason = f"projected ${proj:.2f} > remaining ${remaining:.2f}"
    for name, secs in (("window_5h_usd", 5 * 3600), ("window_7d_usd", 7 * 86400)):
        if name in pc:
            used = spent(rows, prov, budget, since=now - secs)
            d[name.replace("_usd", "")] = f"{used:.2f}+{proj:.2f}/{pc[name]}"
            if reason is None and used + proj > pc[name]:
                reason = f"{name[:-4]} would overflow: ${used:.2f} + ${proj:.2f} > ${pc[name]}"
    d["allowed"], d["reason"] = reason is None, reason or "ok"
    return d


def record(rec: dict, path: Path | None = None) -> None:
    p = Path(path or SPEND)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as f:
        f.write(json.dumps(rec) + "\n")
