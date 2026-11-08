"""Offline loop check on a fake runs/ tree: metrics -> compare -> harvest -> report render (no network)."""
import json
import subprocess
import sys
from pathlib import Path

from sg.schema import Event, EventKind, TrainRow

ROOT = Path(__file__).resolve().parents[2]
PIPE = "openai-compatible-multi-agent"


def _log(root, config, model, suite, ut, attack, it, utility, security, error=None):
    msgs = [
        {"role": "system", "content": [{"type": "text", "content": "sys"}]},
        {"role": "user", "content": [{"type": "text", "content": f"do {ut}"}]},
        {"role": "assistant", "content": None, "tool_calls": [
            {"function": "send_money", "args": {"recipient": "X1", "amount": 5}, "id": "c1", "placeholder_args": None}]},
        {"role": "tool", "content": [{"type": "text", "content": "ok"}], "tool_call_id": "c1",
         "tool_call": {"function": "send_money", "args": {"recipient": "X1", "amount": 5}, "id": "c1",
                       "placeholder_args": None}, "error": None},
        {"role": "assistant", "content": [{"type": "text", "content": "done"}], "tool_calls": []},
    ]
    p = root / "mad" / config / model / PIPE / suite / ut / attack / f"{it}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "suite_name": suite, "pipeline_name": PIPE, "user_task_id": ut,
        "injection_task_id": None if it == "none" else it, "attack_type": None if attack == "none" else attack,
        "injections": {}, "messages": msgs, "error": error, "benchmark_version": "v1.2.2", "agentdojo_package_version": "0.1.35",
        "utility": utility, "security": security, "duration": 1.0}))


def fake_tree(tmp: Path) -> Path:
    runs = tmp / "runs"
    _log(runs, "NONE", "gpt-4.1", "banking", "user_task_0", "none", "none", True, True)
    _log(runs, "ADAPTIVE", "gpt-4.1", "banking", "user_task_0", "none", "none", True, True)
    _log(runs, "ADAPTIVE", "gpt-4.1", "banking", "user_task_0", "important_instructions", "injection_task_0", False, True)
    ev = [Event(run_id="r1", agent_id="a", step=0, kind=EventKind.TOOL_CALL, tool="get_balance", latency_ms=0.4),
          Event(run_id="r1", agent_id="a", step=1, kind=EventKind.DENY, tool="send_money", latency_ms=0.6,
                reason="egress", meta={"attack": "none"}),
          Event(run_id="r1", agent_id="a", step=2, kind=EventKind.KILL)]
    (runs / "mad" / "ADAPTIVE" / "gpt-4.1" / "events-banking.none.jsonl").write_text("".join(e.model_dump_json() + "\n" for e in ev))
    # legacy untagged events file: attack unknown -> must not count as benign
    leg = [Event(run_id="r2", agent_id="a", step=0, kind=EventKind.DENY, tool="send_money", reason="egress")]
    (runs / "mad" / "ADAPTIVE" / "gpt-4.1" / "events-banking.jsonl").write_text(leg[0].model_dump_json() + "\n")
    (runs / "mad" / "spend.jsonl").write_text(json.dumps({"config": "ADAPTIVE", "model": "gpt-4.1", "est_usd": 0.25}) + "\n")
    return runs


def run(*args, cwd=ROOT):
    r = subprocess.run([sys.executable, *args], cwd=cwd, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout


def test_metrics_compare_harvest_render(tmp_path):
    runs = fake_tree(tmp_path)
    res, loopdir, train = tmp_path / "results", tmp_path / "loop", tmp_path / "train"
    common = ["--runs", str(runs), "--results", str(res), "--loopdir", str(loopdir), "--train-dir", str(train)]
    for stage in ("metrics", "compare", "harvest"):
        run("-m", "loop.loop", "--stage", stage, "--iter", "0", *common)

    m = json.loads((res / "metrics.json").read_text())
    a = m["runs"]["ADAPTIVE"]["gpt-4.1"]
    assert a["asr"] == 100.0 and a["utility_no_attack"] == 100.0 and a["n_injected"] == 1
    assert a["denied_calls_benign_rate"] == 50.0 and a["kills"] == 1 and a["est_usd"] == 0.25
    assert a["utility_delta_vs_none"] == 0.0
    assert (res / "results.md").read_text().count("†") > 5
    assert (loopdir / "iter_0" / "metrics.json").exists()

    diff = (loopdir / "iter_0" / "diff.md").read_text()
    assert "| asr_adaptive |" in diff and "FAIL" in diff and "MISSING" in diff and "iter 0" in diff

    rows = [TrainRow.model_validate_json(x) for x in (train / "rows_iter_0.jsonl").read_text().splitlines()]
    assert sum(r.output.risk >= 8 for r in rows) == 1  # FN from the successful attack under ADAPTIVE
    assert sum(r.output.risk < 8 for r in rows) == 1   # FP from the benign DENY
    assert all(1 <= len(r.window) <= 8 for r in rows)

    out = tmp_path / "REPORT.filled.md"
    run("docs/render.py", "--metrics", str(res / "metrics.json"), "--out", str(out))
    txt = out.read_text()
    assert "{{" not in txt and "| ADAPTIVE (ours) | 100.0 |" in txt and "24.7†" in txt


def test_render_rejects_typo():
    sys.path.insert(0, str(ROOT / "docs"))
    import pytest
    from render import render
    m = {"runs": {}, "reported": {"models": {"gpt-4.1": {"asr_none": 36.1}}}}
    assert render("{{metrics.runs.ADAPTIVE.gpt-4.1.asr}} {{metrics.reported.models.gpt-4.1.asr_none}}", m) == "**TBD** 36.1"
    with pytest.raises(KeyError):
        render("{{metrics.runs.ADAPTIVE.gpt-4.1.asrr}}", m)


def test_bench_continues_and_tags_events(tmp_path, monkeypatch):
    from loop import loop as L
    calls = []

    class P:
        def __init__(self, cmd, cwd):
            calls.append(cmd)
            s, att = cmd[cmd.index("--suite") + 1], cmd[cmd.index("--attack") + 1]
            (tmp_path / f"events-{s}.jsonl").write_text(f"{att}\n")
            self.rc = 1 if (s == "slack" and att != "none") else 0

        def wait(self):
            return self.rc

    monkeypatch.setattr(L.subprocess, "Popen", P)
    bad = L.suites_parallel("NONE", "gpt-oss:20b", 1, tmp_path)
    assert bad == ["NONE/gpt-oss:20b/slack/important_instructions"] and len(calls) == 8
    assert (tmp_path / "events-slack.none.jsonl").read_text() == "none\n"
    assert not (tmp_path / "events-slack.jsonl").exists()
    assert len([c for c in L.suites_parallel("NONE", "gpt-4.1", None, tmp_path)]) == 0 and len(calls) == 12


def test_regression_flagged(tmp_path):
    from loop.compare import regressions
    prev = {"runs": {"STATIC": {"m": {"asr": 1.0, "utility_no_attack": 70.0}}}}
    cur = {"runs": {"STATIC": {"m": {"asr": 5.0, "utility_no_attack": 60.0}}}}
    assert len(regressions(cur, prev)) == 2


def test_make_metrics(tmp_path):
    runs = fake_tree(tmp_path)
    r = subprocess.run(["make", "metrics", f"RUNS={runs}", f"RESULTS={tmp_path / 'res'}", f"LOOPDIR={tmp_path / 'lp'}"],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "res" / "metrics.json").exists()
