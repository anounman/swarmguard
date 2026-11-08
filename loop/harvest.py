"""Harvest decider training rows from failures (PLAN §5 stage 6).

FN = injection succeeded (security True) under STATIC / ADAPTIVE*  -> window ending at the bad step, risk 9.
FP = benign run (attack none) with a DENY event                    -> window ending at the denied step, risk 1.
Window = last <=8 events. Events come from <model_dir>/**/events*.jsonl when they carry run keys in meta
(suite / user_task_id / injection_task_id); else the window is rebuilt from the log's messages.
v3 (PLAN §8a item 1): with --mad-configs, also run train/from_mad_runs.py (same CLI, logic stays there) over
<runs>/<bench> -> rows_iter_N_mad.jsonl (+ .stats.json). `wrap_for_merge` turns FN/FP rows into merge_v3 --extra lines.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from sg.schema import Event, EventKind, Role, TrainRow, Verdict
from loop.metrics import load_events, load_runs, is_benign_event

ROOT = Path(__file__).resolve().parents[1]
GUARDED = ("STATIC", "ADAPTIVE")  # prefix match: STATIC, ADAPTIVE_RULES, ADAPTIVE, ADAPTIVE_AUDIT
W = 8


def _text(content) -> str:
    if isinstance(content, str):
        return content
    return " ".join(str(b.get("content", "")) for b in content or [] if isinstance(b, dict))


def _get(o, k):
    return o.get(k) if isinstance(o, dict) else getattr(o, k, None)


def events_from_messages(r) -> list[Event]:
    # ponytail: no gateway events for this run -> synthesise TOOL_CALL/TOOL_RESULT from the flattened log
    run_id = f"{r.suite_name}/{r.user_task_id}/{r.injection_task_id or 'none'}"
    out, step = [], 0
    for msg in r.messages:
        if msg["role"] == "assistant":
            for tc in msg.get("tool_calls") or []:
                out.append(Event(run_id=run_id, agent_id="agent", step=step, kind=EventKind.TOOL_CALL,
                                 tool=_get(tc, "function"), args=dict(_get(tc, "args") or {})))
                step += 1
        elif msg["role"] == "tool":
            out.append(Event(run_id=run_id, agent_id="agent", step=step, kind=EventKind.TOOL_RESULT,
                             tool=_get(msg.get("tool_call"), "function"),
                             result_preview=(msg.get("error") or _text(msg.get("content")))[:500]))
            step += 1
    return out


def _key(suite, ut, it) -> tuple:
    return (suite, ut, it or "none")


def _ev_key(e: Event) -> tuple | None:
    m = e.meta
    if "user_task_id" not in m:
        return None
    return _key(m.get("suite"), m["user_task_id"], m.get("injection_task_id"))


def _role(evs: list[Event], task_id: str) -> Role:
    for e in reversed(evs):
        if isinstance(e.meta.get("role"), dict):
            try:
                return Role.model_validate(e.meta["role"])
            except Exception:
                pass
    return Role(task_id=task_id, tools=sorted({e.tool for e in evs if e.tool}))


def _task(r) -> str:
    return next((_text(m["content"]) for m in r.messages if m["role"] == "user"), "")


def harvest(runs_root: Path, bench: str = "mad") -> list[TrainRow]:
    rows: list[TrainRow] = []
    bench_dir = runs_root / bench
    for cdir in sorted(p for p in bench_dir.iterdir() if p.is_dir()) if bench_dir.exists() else []:
        for mdir in sorted(p for p in cdir.iterdir() if p.is_dir()):
            evs = load_events(mdir)
            by_key: dict[tuple, list[Event]] = {}
            for e in evs:
                if (k := _ev_key(e)) is not None:
                    by_key.setdefault(k, []).append(e)
            src = f"mad:{cdir.name}:{mdir.name}"
            # FN
            if cdir.name.startswith(GUARDED):
                runs, _ = load_runs(mdir)
                for r in runs:
                    if (r.attack_type or "none") == "none" or not r.security or not r.user_task_id.startswith("user_task_"):
                        continue
                    run_evs = by_key.get(_key(r.suite_name, r.user_task_id, r.injection_task_id)) or events_from_messages(r)
                    calls = [i for i, e in enumerate(run_evs) if e.kind == EventKind.TOOL_CALL]
                    end = calls[-1] if calls else len(run_evs) - 1  # ponytail: bad step = last executed call
                    win = run_evs[max(0, end - W + 1): end + 1]
                    if not win:
                        continue
                    rows.append(TrainRow(task=_task(r), role=_role(win, r.user_task_id), window=win, source=src,
                                         output=Verdict(risk=9, category="prompt_injection", first_bad_step=win[-1].step,
                                                        rationale=f"injection {r.injection_task_id} succeeded "
                                                                  f"({r.attack_type}) under {cdir.name}")))
            # FP: benign events grouped by run_id, one row per DENY
            ben: dict[str, list[Event]] = {}
            for e in evs:
                if is_benign_event(e):
                    ben.setdefault(e.run_id, []).append(e)
            for run_id, run_evs in ben.items():
                run_evs.sort(key=lambda e: (e.step, e.ts))
                for i, e in enumerate(run_evs):
                    if e.kind != EventKind.DENY:
                        continue
                    win = run_evs[max(0, i - W + 1): i + 1]
                    rows.append(TrainRow(task=str(e.meta.get("task", "")), role=_role(win, run_id), window=win, source=src,
                                         output=Verdict(risk=1, category="benign", first_bad_step=None,
                                                        rationale=f"benign run; denied {e.tool} was a false positive "
                                                                  f"({e.reason})")))
    return rows


def mad_cmd(runs: str, bench: str, configs: list[str], out_dir: str, it: int) -> list[str]:
    out = Path(out_dir) / f"rows_iter_{it}_mad.jsonl"
    return [sys.executable, "-m", "train.from_mad_runs", "--runs", str(Path(runs) / bench), "--configs", *configs,
            "--out", str(out), "--stats", str(out.with_suffix(".stats.json"))]


def mad_rows(runs: str, bench: str, configs: list[str], out_dir: str, it: int) -> Path:
    cmd = mad_cmd(runs, bench, configs, out_dir, it)
    print("$", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True)
    return Path(cmd[cmd.index("--out") + 1])


def wrap_for_merge(srcs: list[Path], dst: Path) -> int:
    """FN/FP TrainRow lines -> {row, cls} lines that train/merge_v3.py --extra reads."""
    n = 0
    with dst.open("w") as f:
        for p in srcs:
            for line in p.read_text().splitlines():
                r = json.loads(line)
                f.write(json.dumps({"row": r, "cls": "hijacked" if r["output"]["risk"] >= 8 else "benign",
                                    "pipeline": r.get("source")}) + "\n")
                n += 1
    return n


def main(argv: list[str] | None = None) -> Path:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default="runs")
    ap.add_argument("--bench", default="mad")
    ap.add_argument("--iter", type=int, required=True)
    ap.add_argument("--out-dir", default="train")
    ap.add_argument("--mad-configs", nargs="*", default=[], help="also run train.from_mad_runs over these configs")
    a = ap.parse_args(argv)
    rows = harvest(Path(a.runs), a.bench)
    out = Path(a.out_dir) / f"rows_iter_{a.iter}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(r.model_dump_json() + "\n" for r in rows))
    fn = sum(r.output.risk >= 8 for r in rows)
    print(f"harvest -> {out}  rows={len(rows)} FN={fn} FP={len(rows) - fn}")
    if a.mad_configs:
        mad_rows(a.runs, a.bench, a.mad_configs, a.out_dir, a.iter)
    return out


if __name__ == "__main__":
    main()
