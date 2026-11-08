"""StepGuard-Data (ninty-seven/stepguard_data, Apache-2.0, arXiv 2608.24777) -> TrainRow JSONL.

Both configs: sft3k (ShareGPT; gpt turn carries <Judgment>/<RiskSource>/<UnsafeStep>) and rl4k (label +
risk_source columns, no UnsafeStep). Exact-duplicate inputs are kept once (sft3k first: it has the step id).
safe -> risk 1 benign (cls 'resisted' when an injection-like source was present, else 'benign');
unsafe + injection-like source -> risk 9, first_bad_step = the judged event; other unsafe sources dropped.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections import Counter

from sg.labels import SINKS
from sg.schema import EventKind, Role, TrainRow, Verdict
from train.common import PREVIEW, WINDOW, clip, ev, sinks

HF = "ninty-seven/stepguard_data"
LICENSE = "Apache-2.0"
# ponytail: direct_prompt_injection arrives in the USER turn, not a tool output -> not our channel; dropped
INJ = {"indirect_prompt_injection", "tool_description_injection", "corrupted_tool_feedback"}
SEG = re.compile(r"^(?:\[(?:Step|Turn) (\d+)\] |\[Observation after Step \d+\] )?\[(USER|AGENT|ENVIRONMENT)\]:?", re.MULTILINE)
ACT = re.compile(r"\[(ACTION|RESPONSE|FINAL)\]:?\s*")


def category(tool: str | None, args: dict | None) -> str:
    """Same split as train/from_mad_runs: data-moving sinks -> exfiltration, other sinks (money, updates) -> unauthorized_action."""
    # ponytail: StepGuard tools are MCP-style ('x_mcp' + operation); name and operation both checked, by prefix
    for name in (tool or "", str((args or {}).get("operation", ""))):
        if name.startswith(("send_email", "send_direct", "send_channel", "send_message", "post_", "share_", "http_", "upload_", "export_")):
            return "exfiltration"
        if name in SINKS or sinks([name]):
            return "unauthorized_action"
    return "prompt_injection"


def parse_action(seg: str):
    """AGENT segment -> (kind, tool, args, text) or None (thought only). [THOUGHT] is dropped: runtime has no CoT and it leaks the label."""
    m = None
    for m in ACT.finditer(seg):
        pass
    if m is None:  # plain reply ('[AGENT]: [AGENT]: text'); thought-only segments emit nothing
        body = re.sub(r"^(\[AGENT\]:?\s*)+", "", seg).strip()
        return None if not body or body.startswith("[THOUGHT]") else (EventKind.LLM_TEXT, None, None, body)
    body = seg[m.end():].strip()
    if m.group(1) == "ACTION" and body.startswith("{"):
        try:
            d, _ = json.JSONDecoder().raw_decode(body)
            args = d.get("arguments")
            return EventKind.TOOL_CALL, d.get("name"), args if isinstance(args, dict) else {"value": args}, None
        except (ValueError, AttributeError):
            pass
    if body.startswith("Complete{"):
        try:
            body = str(json.loads(body[8:]).get("response", body))
        except (ValueError, AttributeError):
            pass
    return EventKind.LLM_TEXT, None, None, body


def events_of(text: str, rid: str):
    """Prompt -> (task, tools, events, agent_step -> event idx, judged idx)."""
    inp = text[text.index("<<User Request>>"):]
    task = inp.split("<<User Request>>", 1)[1].split("\n\n<", 1)[0].strip()
    tools_blk = inp.split("<<Available Tools>>", 1)[1] if "<<Available Tools>>" in inp else ""
    avail = re.findall(r"^-\s*([\w.\-]+)", tools_blk, re.MULTILINE) or re.findall(r"[\w.\-]+", tools_blk.split("\n\n")[0])
    if "<BEGIN TRAJECTORY>" in inp:
        body = inp.split("<BEGIN TRAJECTORY>", 1)[1].split("<END TRAJECTORY>", 1)[0]
    else:
        body = inp.split("<<User Request>>", 1)[1].split("<<Available Tools>>", 1)[0]
        body = body.split("<<Interaction History>>", 1)[-1] if "<<Interaction History>>" in body else body[len(task) + 2:]
    ms = list(SEG.finditer(body))
    events, step_idx, n_agent, last_tool, users = [], {}, 0, None, 0
    for i, m in enumerate(ms):
        seg = body[m.end(): ms[i + 1].start() if i + 1 < len(ms) else len(body)].replace("<<Action Under Review>>", "").strip()
        who = m.group(2)
        if who == "USER":
            users += 1
            if users > 1:  # ponytail: follow-up user turns shown as text; Event has no user kind
                events.append(ev(rid, len(events), EventKind.LLM_TEXT, preview="USER: " + seg))
        elif who == "ENVIRONMENT":
            events.append(ev(rid, len(events), EventKind.TOOL_RESULT, tool=last_tool, preview=clip(seg)[:PREVIEW], trusted=False))
        else:
            n_agent += 1
            a = parse_action(seg)
            if a is None:
                continue
            kind, tool, args, txt = a
            last_tool = tool or last_tool
            events.append(ev(rid, len(events), kind, tool=tool, args=args, preview=txt))
            step_idx[int(m.group(1)) if m.group(1) else n_agent] = len(events) - 1
    tools = sorted(set(avail) | {e.tool for e in events if e.tool})
    return task, tools, events, step_idx


def convert(text: str, judgment: str, source: str, unsafe_step: int | None, rid: str):
    """-> output line dict, or a drop-reason string."""
    unsafe = judgment == "unsafe"
    if unsafe and source not in INJ:
        return f"unsafe:{source}"
    task, tools, events, step_idx = events_of(text, rid)
    if not events:
        return "no_events"
    traj = "<BEGIN TRAJECTORY>" in text
    if unsafe and traj:
        if unsafe_step not in step_idx:
            return "unsafe_step_unmapped"
        end = step_idx[unsafe_step]
    else:
        end = len(events) - 1  # action level: the action under review; safe trajectory: its last event
    win = events[max(0, end - WINDOW + 1): end + 1]
    j = events[end]
    if unsafe:
        v = Verdict(risk=9.0, category=category(j.tool, j.args), first_bad_step=j.step,
                    rationale=f"Step {j.step} follows untrusted content ({source.replace('_', ' ')}), not the user task.")
        cls = "hijack"
    else:
        v = Verdict(risk=1.0, category="benign", rationale="Actions match the user task; no injected instructions followed.")
        cls = "resisted" if source in INJ else "benign"
    role = Role(task_id=rid, name="agent", tools=tools, egress_sinks=sinks(tools))
    row = TrainRow(task=task, role=role, window=win, output=v, source="stepguard")
    return {"row": row.model_dump(mode="json"), "cls": cls, "pipeline": "stepguard", "suite": "traj" if traj else "action",
            "kind": source, "id": rid}


def key(text: str) -> str:
    return hashlib.md5(text[text.index("<<User Request>>"):].encode()).hexdigest()


def tag(s: str, t: str):
    m = re.search(rf"<{t}>\s*(\w+)", s)
    return m.group(1) if m else None


def examples(cache: str):
    """Yield (text, judgment, risk_source, unsafe_step, id); sft3k first, rl4k borrows a step id from an sft3k twin."""
    from datasets import load_dataset

    tok = os.environ.get("HF_TOKEN")
    steps = {}
    for i, r in enumerate(load_dataset(HF, "sft3k", token=tok, cache_dir=cache)["train"]):
        h, g = r["conversations"][0]["value"], r["conversations"][-1]["value"]
        us = tag(g, "UnsafeStep")
        st = int(us) if us and us.isdigit() else None
        steps[key(h)] = st
        yield h, tag(g, "Judgment"), tag(g, "RiskSource"), st, f"stepguard-sft-{i:06d}"
    for r in load_dataset(HF, "rl4k", token=tok, cache_dir=cache)["train"]:
        yield r["instruction"], r["label"], r["risk_source"], steps.get(key(r["instruction"])), r["id"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", default="data/hf/stepguard")
    ap.add_argument("--outdir", default="train/data_v3")
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    from huggingface_hub import HfApi

    lic = (HfApi().dataset_info(HF, token=os.environ.get("HF_TOKEN")).card_data or {}).get("license") or LICENSE
    seen, by = set(), {k: Counter() for k in ("cls", "category", "level", "kept_source", "dropped")}
    n = dup = 0
    with open(f"{a.outdir}/stepguard_rows.jsonl", "w") as fo:
        for text, jd, src, st, rid in examples(a.cache):
            n += 1
            k = key(text)
            if k in seen:
                dup += 1
                continue
            seen.add(k)
            r = convert(text, jd, src, st, rid)
            if isinstance(r, str):
                by["dropped"][r] += 1
                continue
            fo.write(json.dumps(r) + "\n")
            by["cls"][r["cls"]] += 1
            by["category"][r["row"]["output"]["category"]] += 1
            by["level"][r["suite"]] += 1
            by["kept_source"][r["kind"]] += 1
    stats = {"dataset": HF, "license": lic, "examples": n, "dup": dup, "rows": sum(by["cls"].values()),
             **{k: dict(v.most_common()) for k, v in by.items()}}
    with open(f"{a.outdir}/stepguard_stats.json", "w") as f:
        json.dump(stats, f, indent=1)
    print(json.dumps(stats, indent=1))


if __name__ == "__main__":
    main()
