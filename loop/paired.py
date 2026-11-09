"""Paired (matched-episode) comparison of two configs of one model: exact McNemar on discordant episodes.

Episode key = (suite, user_task, injection_task); benign runs have injection_task None. Only keys both configs ran
count, so partial cells compare like with like. stdlib only.
"""
from __future__ import annotations

from math import comb


def mcnemar_p(b: int, c: int) -> float:
    """Exact two-sided McNemar p: binomial(b+c, 0.5) on the discordant counts."""
    n = b + c
    if n == 0:
        return 1.0
    return min(1.0, 2 * sum(comb(n, k) for k in range(min(b, c) + 1)) / 2 ** n)


def outcomes(runs) -> dict[tuple, tuple[bool, bool]]:
    """TaskResults -> {(suite, user_task, injection_task|None): (utility, security)}; real MAD user tasks only."""
    from loop.metrics import real_task  # local: metrics imports this module
    return {(r.suite_name, r.user_task_id, r.injection_task_id if (r.attack_type or "none") != "none" else None):
            (bool(r.utility), bool(r.security)) for r in runs if real_task(r.user_task_id)}


def _pair(xs: list[tuple[bool, bool]]) -> dict:
    a = sum(x and not y for x, y in xs)
    b = sum(y and not x for x, y in xs)
    n = len(xs)
    return {"n": n, "a_only": a, "b_only": b, "both": sum(x and y for x, y in xs),
            "rate_a": round(100 * sum(x for x, _ in xs) / n, 1) if n else None,
            "rate_b": round(100 * sum(y for _, y in xs) / n, 1) if n else None,
            "p_mcnemar": float(f"{mcnemar_p(a, b):.3g}")}


def compare(a: dict, b: dict) -> dict:
    """a, b from outcomes(). a_only/b_only = discordant episodes where only A / only B had the outcome."""
    keys = sorted(set(a) & set(b), key=str)
    ben = [k for k in keys if k[2] is None]
    inj = [k for k in keys if k[2] is not None]
    return {"utility_no_attack": _pair([(a[k][0], b[k][0]) for k in ben]),
            "utility_under_attack": _pair([(a[k][0], b[k][0]) for k in inj]),
            "attack_success": _pair([(a[k][1], b[k][1]) for k in inj])}
