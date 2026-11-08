"""raw_*.jsonl -> train/data/{train,val,test_ood,test_drift}.jsonl + stats.json.

AgentDojo: pipelines in OOD are held out entirely (test_ood = unseen agent model, SEEN tasks). Rest -> train/val by
run hash. AgentDrift: task-disjoint train/val/test respected; test -> test_drift (the true held-out-task split).
Dedupe on the user prompt (what the model sees): train has no duplicates; val/test drop any prompt that is in train.
Line: {"messages": chat (system,user,assistant), "row": TrainRow, "cls", "source", "attack_type", "suite"}.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter, defaultdict

from sg.schema import TrainRow
from train.common import to_chat, user_prompt

OOD = ["claude-3-7-sonnet-20250219", "gemini-2.0-flash-001", "meta-llama_Llama-3.3-70B-Instruct", "Meta-SecAlign-70B"]


def load(path):
    with open(path) as f:
        return [json.loads(l) for l in f]


def key(r):
    if "_k" not in r:
        row = TrainRow.model_validate(r["row"])
        r["_k"] = hashlib.md5(user_prompt(row.task, row.role, row.window).encode()).hexdigest()
    return r["_k"]


def dedup(rows, seen: set):
    out = []
    for r in rows:
        if key(r) not in seen:
            seen.add(key(r))
            out.append(r)
    return out


def pick(rows, n, seed=0):
    rows = list(rows)
    random.Random(seed).shuffle(rows)
    return rows[:n]


def balanced(dojo, drift, quota: dict[str, tuple[int, int]], seed=0):
    by = defaultdict(list)
    for r in dojo:
        by[("dojo", r["cls"])].append(r)
    for r in drift:
        by[("drift", r["cls"])].append(r)
    out = []
    for c, (nd, nr) in quota.items():
        a, b = pick(by[("dojo", c)], nd, seed), pick(by[("drift", c)], nr, seed)
        out += a + b
    random.Random(seed).shuffle(out)
    return out


def emit(rows, path):
    with open(path, "w") as f:
        for r in rows:
            row = TrainRow.model_validate(r["row"])
            f.write(json.dumps({"messages": to_chat(row), "row": r["row"], "cls": r["cls"], "source": r["pipeline"],
                                "attack_type": r.get("attack_type"), "suite": r.get("suite")}) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="train/data")
    ap.add_argument("--dojo", default="train/data/raw_agentdojo.jsonl")
    ap.add_argument("--scale", type=float, default=1.0, help="multiply all quotas (dry run: 0.01)")
    ap.add_argument("--test-cap", type=int, default=600, help="rows per class in each test split")
    a = ap.parse_args()
    dojo = load(a.dojo)
    ood = [r for r in dojo if r["pipeline"] in OOD]
    ind = [r for r in dojo if r["pipeline"] not in OOD]
    is_val = lambda r: int(hashlib.md5(r["row"]["window"][0]["run_id"].encode()).hexdigest(), 16) % 20 == 0
    s = a.scale
    # (agentdojo, agentdrift) per class; max/min class = 2:1
    q_train = {"success": (int(2200 * s), int(1000 * s)), "failed": (int(1700 * s), int(600 * s)),
               "injection": (int(600 * s), int(1000 * s)), "benign": (int(2200 * s), int(1000 * s))}
    q_val = {c: (max(1, n // 12), max(1, m // 12)) for c, (n, m) in q_train.items()}
    seen = set()
    train = balanced(dedup([r for r in ind if not is_val(r)], seen), dedup(load(f"{a.dir}/raw_drift_train.jsonl"), seen), q_train)
    tk = {key(r) for r in train}
    cls4 = ("success", "failed", "injection", "benign")
    splits = {
        "train": train,
        "val": balanced(dedup([r for r in ind if is_val(r)], set(tk)), dedup(load(f"{a.dir}/raw_drift_val.jsonl"), set(tk)), q_val),
        "test_ood": balanced(dedup(ood, set(tk)), [], {c: (a.test_cap, 0) for c in cls4}),
        "test_drift": balanced([], dedup(load(f"{a.dir}/raw_drift_test.jsonl"), set(tk)), {c: (0, a.test_cap) for c in cls4}),
    }
    stats = {"ood_pipelines_held_out": OOD, "notes": {"test_ood": "unseen agent model, seen tasks",
             "test_drift": "held-out tasks (AgentDrift task-disjoint)"}, "splits": {}}
    for name, rows in splits.items():
        emit(rows, f"{a.dir}/{name}.jsonl")
        stats["splits"][name] = {
            "n": len(rows),
            "by_class": dict(Counter(r["cls"] for r in rows)),
            "by_source": dict(Counter(r["pipeline"] for r in rows)),
            "by_attack_type": dict(Counter(r.get("attack_type") for r in rows)),
            "by_risk": dict(Counter(str(r["row"]["output"]["risk"]) for r in rows)),
        }
    json.dump(stats, open(f"{a.dir}/stats.json", "w"), indent=1)
    print(json.dumps({k: (v["n"], v["by_class"]) for k, v in stats["splits"].items()}))


if __name__ == "__main__":
    main()
