"""AgentDojo runs/ corpus -> TrainRow JSONL (PLAN §8 source 1).

Reused: SC3 onset recipe (norm + 50-char middle chunk), agentdojo get_suite for tool lists.
Output line: {"row": TrainRow, "cls": success|failed|benign, "pipeline", "suite", "attack_type"}.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import random
import re
from collections import Counter

from sg.schema import EventKind, Role, TrainRow, Verdict
from train.common import PREVIEW, WINDOW, ev, text

DEFENSES = ("-repeat_user_prompt", "-spotlighting_with_delimiting", "-tool_filter", "-transformers_pi_detector")
SINK_PREFIX = ("send_", "post_", "share_", "invite_", "add_user", "update_", "schedule_", "delete_", "reserve_", "create_")
RISK = {"success": 9.0, "failed": 4.0, "benign": 1.0}
_TOOLS: dict[str, list[str]] = {}


def suite_tools(suite: str) -> list[str]:
    if suite not in _TOOLS:
        try:
            from agentdojo.task_suite.load_suites import get_suite

            _TOOLS[suite] = sorted(t.name for t in get_suite("v1.2.2", suite).tools)
        except Exception:  # ponytail: fall back to tools seen in the run
            _TOOLS[suite] = []
    return _TOOLS[suite]


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.replace("\\n", " ").replace("\\'", "'")).strip()


def events_of(run_id: str, msgs: list[dict]):
    out = []
    for m in msgs:
        r = m.get("role")
        if r == "assistant":
            t = text(m.get("content"))
            if t.strip():
                out.append(ev(run_id, len(out), EventKind.LLM_TEXT, preview=t))
            for tc in m.get("tool_calls") or []:
                out.append(ev(run_id, len(out), EventKind.TOOL_CALL, tool=tc.get("function"), args=tc.get("args") or {}))
        elif r == "tool":
            tc = m.get("tool_call") or {}
            body = text(m.get("content")) or (m.get("error") or "")
            out.append(ev(run_id, len(out), EventKind.TOOL_RESULT, tool=tc.get("function"), preview=body, trusted=False))
    return out


def find_onset(events, msgs, injections: dict) -> int | None:
    keys = [v[len(v) // 3 : len(v) // 3 + 50] for v in map(norm, injections.values()) if v and len(v) > 20]
    if not keys:
        return None
    tool_texts = [text(m.get("content")) or (m.get("error") or "") for m in msgs if m.get("role") == "tool"]
    res_idx = [i for i, e in enumerate(events) if e.kind == EventKind.TOOL_RESULT]
    full = dict(zip(res_idx, tool_texts))
    for i in res_idx:
        t = norm(full[i])
        for k in keys:
            pos = t.find(k)
            if pos >= 0:
                # ponytail: preview centred on the injection so the 300-char window shows it; at runtime the
                # monitor sees the head of the output only (ceiling: long outputs hide late injections).
                st = max(0, pos - 150)
                events[i].result_preview = ("..." if st else "") + t[st : st + PREVIEW]
                return i
    return None


def rationale(cls: str, onset: int | None) -> str:
    if cls == "success":
        return f"Untrusted tool output at step {onset} injects instructions that hijack the agent."
    if cls == "failed":
        return f"Tool output at step {onset} carries injected instructions; agent has not complied."
    return "Actions match the user task; no injected instructions seen."


def rows_for_file(path: str):
    d = json.load(open(path))
    if "security" not in d or not d.get("messages"):
        return []
    pipe, suite, utid = d["pipeline_name"], d["suite_name"], d["user_task_id"]
    if str(utid).startswith("injection_task"):
        return []  # ponytail: injection tasks run as user tasks look like attacks but are user-requested; skipped
    msgs = d["messages"]
    users = [m for m in msgs if m.get("role") == "user"]
    task = text(users[0]["content"]) if users else ""
    body = msgs[msgs.index(users[0]) + 1 :] if users else msgs
    run_id = hashlib.md5(path.encode()).hexdigest()[:12]
    events = events_of(run_id, body)
    if not events:
        return []
    attack = bool(d.get("attack_type")) and d.get("attack_type") != "none" and bool(d.get("injections"))
    onset = find_onset(events, body, d.get("injections") or {}) if attack else None
    sec = bool(d.get("security"))
    if attack and onset is None and sec:
        return []  # label noise (SC3: 239 runs)
    cls = ("success" if sec else "failed") if onset is not None else "benign"
    tools = suite_tools(suite) or sorted({e.tool for e in events if e.tool})
    role = Role(task_id=f"{suite}/{utid}", name=f"{suite}_agent", tools=tools,
                egress_sinks=[t for t in tools if t.startswith(SINK_PREFIX)])
    meta = {"cls": cls, "pipeline": pipe, "suite": suite, "attack_type": d.get("attack_type") or "none"}

    def mk(win, c, fb):
        v = Verdict(risk=RISK[c], category="benign" if c == "benign" else "prompt_injection",
                    first_bad_step=fb, rationale=rationale(c, fb))
        return {"row": TrainRow(task=task, role=role, window=win, output=v, source=pipe).model_dump(mode="json"),
                **meta, "cls": c, "kind": None}

    out = []
    n = len(events)
    if onset is None:
        out.append(mk(events[max(0, n - WINDOW) :], "benign", None) | {"kind": "final"})
        calls = [i for i, e in enumerate(events) if e.kind == EventKind.TOOL_CALL and i < n - 1]
        if calls:
            i = random.Random(run_id).choice(calls)
            out.append(mk(events[max(0, i - WINDOW + 1) : i + 1], "benign", None) | {"kind": "mid"})
        return out
    s = max(0, min(onset, n - WINDOW))
    out.append(mk(events[s : s + WINDOW], cls, onset) | {"kind": "final"})
    if onset + 1 < n or s != max(0, onset - WINDOW + 1):
        out.append(mk(events[max(0, onset - WINDOW + 1) : onset + 1], cls, onset) | {"kind": "onset"})
    if onset > 0:
        out.append(mk(events[max(0, onset - WINDOW) : onset], "benign", None) | {"kind": "pre_onset"})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="data/agentdojo/runs")
    ap.add_argument("--out", default="train/data/raw_agentdojo.jsonl")
    ap.add_argument("--limit-files", type=int, default=0)
    ap.add_argument("--cap", type=int, default=0, help="max rows per cls (0 = no cap)")
    ap.add_argument("--keep-defenses", action="store_true")
    a = ap.parse_args()
    files = sorted(glob.glob(f"{a.root}/*/*/*/*/*.json"))
    if not a.keep_defenses:
        files = [f for f in files if not os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(f))))).endswith(DEFENSES)]
    random.Random(0).shuffle(files)
    if a.limit_files:
        files = files[: a.limit_files]
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    cnt = Counter()
    with open(a.out, "w") as fo:
        for f in files:
            try:
                rows = rows_for_file(f)
            except Exception:  # noqa: BLE001
                cnt["error"] += 1
                continue
            for r in rows:
                if a.cap and cnt[r["cls"]] >= a.cap:
                    continue
                cnt[r["cls"]] += 1
                fo.write(json.dumps(r) + "\n")
    print(json.dumps({"files": len(files), **cnt}))


if __name__ == "__main__":
    main()
