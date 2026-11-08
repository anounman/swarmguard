"""v2 train/val + MAD rows + synth rows -> train/data_v3/{train,val,test_mad_ood}.jsonl + stats.json (PLAN §8a item 5).

- MAD rows from the held-out model (deepseek-v4.1-flash) -> test_mad_ood only (OOD by model); never train/val.
- v2 train -> train, v2 val -> val (v2 test_ood / test_drift stay in train/data, untouched; rows whose prompt is there are dropped).
- New sources (MAD, synth, --extra) -> train/val by run_id hash (1 in 10 -> val).
- Dedupe on task+window+output across everything; val/test also drop any prompt seen in train (as train/splits.py).
- Class groups by gold risk: hijacked >= 8, benign <= 2, failed = the rest (4 resisted, 6 injection seen). Max/min <= 2:1,
  synth <= 30% of train; down-sampling drops v2 rows first.
Lines are written by train.splits.emit (chat "messages" + raw "row").
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter

from sg.schema import TrainRow
from train.common import verdict_json
from train.splits import emit, key, load

HELD_OUT = "deepseek-v4.1-flash"
NEW = ("mad", "synth", "extra")  # kept first when balancing


def grp(r) -> str:
    risk = r["row"]["output"]["risk"]
    return "hijacked" if risk >= 8 else "benign" if risk <= 2 else "failed"


def fkey(r) -> str:  # task + window + output
    return key(r) + hashlib.md5(verdict_json(TrainRow.model_validate(r["row"]).output).encode()).hexdigest()


def norm(r, origin: str) -> dict:
    meta = r.get("meta") or {}
    return {"row": r["row"], "cls": r["cls"], "origin": origin,
            "pipeline": r.get("pipeline") or r.get("source") or r["row"].get("source") or origin,
            "attack_type": r.get("attack_type") or meta.get("attack") or meta.get("attack_category"),
            "suite": r.get("suite") or meta.get("suite") or meta.get("domain"), "config": meta.get("config")}


def is_val(r) -> bool:
    return int(hashlib.md5(r["row"]["window"][0]["run_id"].encode()).hexdigest(), 16) % 10 == 0


def dedup(rows, seen: set, ban: set = frozenset()):
    out = []
    for r in rows:
        if fkey(r) not in seen and key(r) not in ban:
            seen.add(fkey(r))
            out.append(r)
    return out


def shape(rows, ratio=2.0, synth_cap=0.30, seed=0):
    """Down-sample to synth <= synth_cap and max/min class group <= ratio; v2 rows are dropped first."""
    rng = random.Random(seed)
    rows = list(rows)
    rng.shuffle(rows)
    rows.sort(key=lambda r: r["origin"] not in NEW)  # stable: new-source rows first, v2 last -> v2 cut first
    for _ in range(3):  # ponytail: alternate the two caps until both hold (converges in 1 pass on real data)
        keep_syn = int(synth_cap / (1 - synth_cap) * sum(r["origin"] != "synth" for r in rows))
        k = iter(range(len(rows)))
        rows = [r for r in rows if r["origin"] != "synth" or next(k) < keep_syn]
        c = Counter(grp(r) for r in rows)
        cap = int(ratio * min(c.values()))
        n = Counter()
        out = []
        for r in rows:
            g = grp(r)
            if n[g] < cap:
                n[g] += 1
                out.append(r)
        rows = out
    rng.shuffle(rows)
    return rows


def summary(rows):
    n = len(rows)
    return {"n": n, "by_group": dict(Counter(grp(r) for r in rows)), "by_class": dict(Counter(r["cls"] for r in rows)),
            "by_origin": dict(Counter(r["origin"] for r in rows)), "by_source": dict(Counter(r["pipeline"] for r in rows)),
            "by_config": dict(Counter(str(r["config"]) for r in rows)),
            "by_risk": dict(Counter(str(r["row"]["output"]["risk"]) for r in rows)),
            "synth_share": sum(r["origin"] == "synth" for r in rows) / max(1, n)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--v2", default="train/data")
    ap.add_argument("--mad", default="train/data_v3/mad_rows.jsonl")
    ap.add_argument("--synth", default="train/data_v3/synth_rows.jsonl")
    ap.add_argument("--extra", nargs="*", default=[], help="more converter outputs (stepguard/nvidia_ipi), train/val only")
    ap.add_argument("--out", default="train/data_v3")
    a = ap.parse_args()
    ban = {key(r) for s in ("test_ood", "test_drift") for r in load(f"{a.v2}/{s}.jsonl")}
    mad = [norm(r, "mad") for r in load(a.mad)]
    new = [r for r in mad if r["pipeline"] != HELD_OUT] + [norm(r, "synth") for r in load(a.synth)] \
        + [norm(r, "extra") for p in a.extra for r in load(p)]
    seen = set()
    train = dedup([norm(r, "v2") for r in load(f"{a.v2}/train.jsonl")] + [r for r in new if not is_val(r)], seen, ban)
    train = shape(train)
    tk = {key(r) for r in train} | ban
    splits = {"train": train,
              "val": shape(dedup([norm(r, "v2") for r in load(f"{a.v2}/val.jsonl")] + [r for r in new if is_val(r)], seen, tk)),
              "test_mad_ood": dedup([r for r in mad if r["pipeline"] == HELD_OUT], seen, tk)}
    stats = {"held_out_source": HELD_OUT, "inputs": {"v2": a.v2, "mad": a.mad, "synth": a.synth, "extra": a.extra},
             "notes": {"test_mad_ood": f"MAD bench windows from {HELD_OUT} (unseen agent model, seen tasks)",
                       "v2_tests": f"{a.v2}/test_ood.jsonl + test_drift.jsonl unchanged"}, "splits": {}}
    for name, rows in splits.items():
        emit(rows, f"{a.out}/{name}.jsonl")
        stats["splits"][name] = summary(rows)
    json.dump(stats, open(f"{a.out}/stats.json", "w"), indent=1)
    print(json.dumps({k: (v["n"], v["by_group"], round(v["synth_share"], 3)) for k, v in stats["splits"].items()}))


if __name__ == "__main__":
    main()
