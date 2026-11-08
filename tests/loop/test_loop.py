"""Offline loop check on a fake runs/ tree: metrics -> compare -> harvest -> report render (no network)."""
import json
import subprocess
import sys
from pathlib import Path

from sg.schema import Event, EventKind, TrainRow

ROOT = Path(__file__).resolve().parents[2]
PIPE = "openai-compatible-multi-agent"


def _tool(fn, error=None, cid="c2"):
    return {"role": "tool", "content": [{"type": "text", "content": ""}], "tool_call_id": cid,
            "tool_call": {"function": fn, "args": {}, "id": cid, "placeholder_args": None}, "error": error}


def _log(root, config, model, suite, ut, attack, it, utility, security, error=None, extra=()):
    msgs = [
        {"role": "system", "content": [{"type": "text", "content": "sys"}]},
        {"role": "user", "content": [{"type": "text", "content": f"do {ut}"}]},
        {"role": "assistant", "content": None, "tool_calls": [
            {"function": "send_money", "args": {"recipient": "X1", "amount": 5}, "id": "c1", "placeholder_args": None}]},
        {"role": "tool", "content": [{"type": "text", "content": "ok"}], "tool_call_id": "c1",
         "tool_call": {"function": "send_money", "args": {"recipient": "X1", "amount": 5}, "id": "c1",
                       "placeholder_args": None}, "error": None},
        *extra,
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
    # benign log with one gateway denial (sg/guard.py rename + PermissionError text) -> 1 of 2 tool results denied
    _log(runs, "ADAPTIVE", "gpt-4.1", "banking", "user_task_0", "none", "none", True, True,
         extra=[_tool("DENIED_send_money", "PermissionError: egress not allowed. Please try other tools")])
    # injected log: an attenuation denial + a sub-agent KILL surfaced as the orchestrator's tool error
    _log(runs, "ADAPTIVE", "gpt-4.1", "banking", "user_task_0", "important_instructions", "injection_task_0", False, True,
         extra=[_tool("send_money", "PermissionError: attenuated, send_money revoked (risk 7.0)", "c3"),
                _tool("banking_agent", "AbortAgentError: SwarmGuard stopped this agent: killed (risk 9.0)", "c4")])
    ev = [Event(run_id="r1", agent_id="a", step=0, kind=EventKind.TOOL_CALL, tool="get_balance", latency_ms=0.4),
          Event(run_id="r1", agent_id="a", step=1, kind=EventKind.DENY, tool="send_money", latency_ms=0.6,
                reason="egress", meta={"attack": "none"}),
          Event(run_id="r1", agent_id="a", step=2, kind=EventKind.KILL)]
    (runs / "mad" / "ADAPTIVE" / "gpt-4.1" / "events-banking.none.jsonl").write_text("".join(e.model_dump_json() + "\n" for e in ev))
    # legacy untagged events file: attack unknown -> must not count as benign
    leg = [Event(run_id="r2", agent_id="a", step=0, kind=EventKind.DENY, tool="send_money", reason="egress",
                 latency_ms=1.0)]  # untagged: still counts for latency (gateway cost does not depend on attack)
    (runs / "mad" / "ADAPTIVE" / "gpt-4.1" / "events-banking.jsonl").write_text(leg[0].model_dump_json() + "\n")
    (runs / "mad" / "spend.jsonl").write_text(json.dumps({"provider": "openrouter", "config": "ADAPTIVE", "model": "openai/gpt-4.1", "est_usd": 0.25,
                                                       "logdir": str(runs / "mad/ADAPTIVE/gpt-4.1")}) + "\n")
    return runs


def run(*args, cwd=ROOT):
    r = subprocess.run([sys.executable, *args], cwd=cwd, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout



@pytest.fixture(autouse=True)
def _decider_version_2(monkeypatch):
    """The v3 sub-step tests were written when loop/config.yaml decider.version was 2 (retrain builds v3).
    Pin that so the real config (bumped as deciders ship, C25: version 3) does not move the expected tags."""
    import loop.loop as L
    monkeypatch.setitem(L.CFG["decider"], "version", 2)

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
    assert a["denied_calls_attack_rate"] == round(100 / 3, 1) and a["killed_runs"] == 1
    assert a["n_checks"] == 3 and a["latency_p50_ms"] == 0.6 and a["latency_p95_ms"] == a["p95_latency_ms"]
    assert m["runs"]["NONE"]["gpt-4.1"]["denied_calls_benign_rate"] == 0.0
    assert m["spend"]["by_model"] == {"gpt-4.1": 0.25} and m["spend"]["by_provider"]["commandcode"] == 0.0
    assert a["utility_delta_vs_none"] == 0.0
    assert (res / "results.md").read_text().count("†") > 5
    assert (loopdir / "iter_0" / "metrics.json").exists()

    diff = (loopdir / "iter_0" / "diff.md").read_text()
    assert "| asr_adaptive |" in diff and "| anchor_util |" in diff and "PASS" in diff and "MISSING" in diff
    assert "iter 0" in diff

    rows = [TrainRow.model_validate_json(x) for x in (train / "rows_iter_0.jsonl").read_text().splitlines()]
    assert sum(r.output.risk >= 8 for r in rows) == 1  # FN from the successful attack under ADAPTIVE
    assert sum(r.output.risk < 8 for r in rows) == 1   # FP from the benign DENY
    assert all(1 <= len(r.window) <= 8 for r in rows)

    out = tmp_path / "REPORT.filled.md"
    run("docs/render.py", "--metrics", str(res / "metrics.json"), "--out", str(out))
    txt = out.read_text()
    # ponytail: the report prose/tables are rewritten by the report pass (C24); only test the render contract here:
    # every placeholder resolves (or renders TBD for unrun cells) and reported paper numbers keep their dagger.
    assert "{{" not in txt and "24.7†" in txt


def test_render_rejects_typo():
    sys.path.insert(0, str(ROOT / "docs"))
    import pytest
    from render import render
    m = {"runs": {}, "reported": {"models": {"gpt-4.1": {"asr_none": 36.1}}}}
    assert render("{{metrics.runs.ADAPTIVE.gpt-4.1.asr}} {{metrics.reported.models.gpt-4.1.asr_none}}", m) == "**TBD** 36.1"
    with pytest.raises(KeyError):
        render("{{metrics.runs.ADAPTIVE.gpt-4.1.asrr}}", m)
    m["spend"] = {"total_usd": None, "by_provider": {"ollama": 1.0}}
    assert render("{{metrics.spend.total_usd}} {{metrics.spend.by_provider.ollama}}", m) == "**TBD** 1.0"
    with pytest.raises(KeyError):  # missing key fails loudly, None renders TBD
        render("{{metrics.spend.by_provider.groq}}", m)


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
    monkeypatch.setattr(L, "gate", lambda cmd: True)
    bad = L.suites_parallel("NONE", {"model": "gpt-oss:20b"}, tmp_path, n=1, inj="injection_task_0")
    assert bad == ["NONE/gpt-oss:20b/slack/important_instructions"] and len(calls) == 8
    assert all(c[c.index("--inj") + 1] == "injection_task_0" and c[c.index("--n") + 1] == "1" for c in calls)
    assert (tmp_path / "events-slack.none.jsonl").read_text() == "none\n"
    assert not (tmp_path / "events-slack.jsonl").exists()
    # gate refuses -> cell skipped, not launched, not a failure
    monkeypatch.setattr(L, "gate", lambda cmd: False)
    assert L.suites_parallel("STATIC", {"model": "gpt-oss:20b"}, tmp_path) == [] and len(calls) == 8


def test_gate_exit_codes(monkeypatch):
    from loop import loop as L

    class R:
        def __init__(self, rc):
            self.returncode, self.stdout, self.stderr = rc, "GATE x\n", "warn\n"

    monkeypatch.setattr(L.subprocess, "run", lambda cmd, **k: R(0) if "gpt-oss:20b" in cmd else R(2))
    assert L.gate(["py", "bench/run.py", "--model", "gpt-oss:20b"])
    assert L.gate(["py", "bench/run.py", "--model", "openai/gpt-4.1"]) is None  # rc 2 without 'GATE REFUSE' = error


def _plan(monkeypatch, tmp_path, stage, remaining=9.5):
    from loop import loop as L
    gated = []
    monkeypatch.setattr(L, "gate", lambda cmd: gated.append(cmd) or True)
    monkeypatch.setattr(L.subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("launched")))
    monkeypatch.setattr(L, "remaining_usd", lambda prov, runs: remaining)
    a = type("A", (), {"runs": str(tmp_path / "runs"), "dry_run": True})()
    getattr(L, stage)(a)
    arg = lambda c, f: c[c.index(f) + 1] if f in c else None  # noqa: E731
    return [{f: arg(c, f) for f in ("--config", "--model", "--suite", "--attack", "--key", "--logdir", "--max-episodes",
                                    "--n", "--inj")} for c in gated]


def test_lanes_dry_run_plan(tmp_path, monkeypatch):
    cells = _plan(monkeypatch, tmp_path, "stage_bench")
    ollama = [c for c in cells if c["--model"].startswith("gpt-oss")]
    assert len(ollama) == 2 * 4 * 4 * 2  # models x configs x suites x attacks
    assert {(c["--suite"], c["--key"]) for c in ollama} == {("workspace", "A"), ("banking", "A"), ("slack", "B"),
                                                            ("travel", "B")}
    cc = [c for c in cells if c["--model"] == "deepseek/deepseek-v4.1-flash"]
    assert len(cc) == 4 * 4 * 2 and all(c["--key"] is None for c in cc)
    assert all(c["--logdir"].endswith("/deepseek-v4.1-flash") for c in cc)
    orr = [c for c in cells if c["--model"] == "openai/gpt-4.1"]
    assert all(c["--logdir"].endswith("/gpt-4.1") and c["--config"] != "NONE" and c["--key"] is None for c in orr)
    assert [c["--suite"] for c in orr if c["--max-episodes"] == "100"] == ["workspace"]
    assert sorted((c["--config"], c["--suite"], c["--attack"]) for c in orr) == [
        ("ADAPTIVE", "banking", "none"), ("ADAPTIVE", "workspace", "important_instructions"),
        ("ADAPTIVE", "workspace", "none"), ("STATIC", "banking", "none"), ("STATIC", "workspace", "none")]
    assert not any("kimi" in c["--model"] for c in cells)
    # openrouter STATIC only if > $3 left
    orr = [c for c in _plan(monkeypatch, tmp_path, "stage_bench", remaining=2.0) if c["--model"] == "openai/gpt-4.1"]
    assert {c["--config"] for c in orr} == {"ADAPTIVE"}


def test_smoke_dry_run_plan(tmp_path, monkeypatch):
    cells = _plan(monkeypatch, tmp_path, "stage_smoke")
    assert {c["--config"] for c in cells} == {"NONE", "ADAPTIVE_RULES", "ADAPTIVE"} and len(cells) == 3 * 4 * 2  # C22: ADAPTIVE in smoke
    assert all(c["--n"] == "1" and c["--inj"] == "injection_task_0" and c["--model"] == "gpt-oss:20b" for c in cells)


def _tree_v4(tmp: Path) -> Path:
    runs = tmp / "runs"
    for ut, u in (("user_task_0", True), ("user_task_1", True)):
        _log(runs, "NONE", "gpt-oss:120b", "workspace", ut, "none", "none", u, False)
    for ut, u in (("user_task_0", True), ("user_task_1", False), ("user_task_100", False), ("user_task_103", False)):
        _log(runs, "ADAPTIVE", "gpt-oss:120b", "workspace", ut, "none", "none", u, False)
    _log(runs, "ADAPTIVE", "gpt-oss:120b", "workspace", "user_task_0", "important_instructions", "injection_task_0",
         False, False)
    _log(runs, "ADAPTIVE", "gpt-oss:120b", "workspace", "user_task_101", "important_instructions", "injection_task_0",
         True, True)  # carrier: must not count as a successful attack
    rows = [{"provider": "ollama", "key": "A", "model": "gpt-oss:120b", "config": "ADAPTIVE", "est_usd": 0.5,
             "logdir": str(runs / "mad/ADAPTIVE/gpt-oss:120b")},
            {"provider": "ollama", "key": "B", "model": "gpt-oss:120b", "config": "ADAPTIVE", "est_usd": 0.25},
            {"provider": "openrouter", "model": "openai/gpt-4.1", "config": "ADAPTIVE", "est_usd": 1.0},
            {"model": "gpt-oss:20b", "config": "NONE", "est_usd": 9.9,      # old row: no provider/key/logdir;
             "prompt_tokens": 1e6, "completion_tokens": 0},                  # repriced from tokens (B.row_usd)
            {"model": "gpt-4.1", "config": "NONE", "est_usd": 0.2},          # old row: pre-C16 = OpenAI direct
            # reservation superseded by its final row (same run_id) -> dropped, as the gate does (B.live)
            {"provider": "openrouter", "model": "openai/gpt-4.1", "config": "STATIC", "est_usd": 5.0, "reserved": True,
             "run_id": "x", "ts": 1e12},
            {"provider": "openrouter", "model": "openai/gpt-4.1", "config": "STATIC", "est_usd": 0.5, "run_id": "x"}]
    (runs / "mad" / "spend.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows) + "not json\n")
    return runs


def test_retention_exclusion_spend_missing_vs_fail(tmp_path):
    import yaml
    from loop import compare, metrics
    m = metrics.compute(_tree_v4(tmp_path), "mad", tmp_path / "res")
    a = m["runs"]["ADAPTIVE"]["gpt-oss:120b"]
    assert a["n_user_tasks"] == 2 and a["n_injected"] == 1 and a["asr"] == 0.0  # user_task_10x excluded
    assert a["utility_no_attack"] == 50.0 and a["utility_retention"] == 50.0 and a["est_usd"] == 0.75
    assert m["runs"]["NONE"]["gpt-oss:120b"]["utility_retention"] == 100.0
    from bench import budget as B
    bud = yaml.safe_load(metrics.BUDGET.read_text())
    rows = [json.loads(x) for x in (tmp_path / "runs/mad/spend.jsonl").read_text().splitlines()[:-1]]
    for prov, usd in m["spend"]["by_provider"].items():  # same numbers as the budget gate
        assert usd == round(B.spent(rows, prov, bud), 4)
    assert m["spend"]["by_provider"]["openrouter"] == 1.5 and m["spend"]["by_ollama_key"]["A"] == 0.5
    assert m["spend"]["by_ollama_key"]["unknown"] == round(B.price("gpt-oss:20b", bud)[0], 4)  # repriced, not 9.9
    tg = yaml.safe_load(compare.TARGETS.read_text())["targets"]
    st = {r["id"]: r["status"] for r in compare.check(m, tg)}
    assert st["asr_adaptive"] == "MISSING" and st["util_retention"] == "MISSING"  # only workspace run, targets need 4
    a["suites"] = ["banking", "slack", "travel", "workspace"]
    st = {r["id"]: r["status"] for r in compare.check(m, tg)}
    assert st["asr_adaptive"] == "PASS" and st["util_retention"] == "FAIL"
    assert st["h3_deepseek"] == "MISSING" and st["anchor_util"] == "MISSING" and st["decider_f1"] == "MISSING"
    # anchor ASR needs >= 100 injected episodes -> MISSING (not PASS) on a small sample
    m["runs"]["ADAPTIVE"]["gpt-4.1"] = {"asr": 0.0, "n_injected": 5}
    assert {r["id"]: r["status"] for r in compare.check(m, compare.yaml.safe_load(compare.TARGETS.read_text())["targets"])
            }["anchor_asr"] == "MISSING"
    # compare.run on a metrics.json with no runs at all: all MISSING, no crash
    (tmp_path / "empty.json").write_text(json.dumps({"runs": {}, "decider": {}}))
    assert compare.run(tmp_path / "empty.json", tmp_path / "it") is False
    assert json.loads((tmp_path / "it" / "compare.json").read_text())["counts"]["FAIL"] == 0


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


def test_retention_needs_same_suites(tmp_path):
    from loop import metrics
    runs = _tree_v4(tmp_path)
    _log(runs, "ADAPTIVE", "gpt-oss:120b", "banking", "user_task_0", "none", "none", True, False)
    a = metrics.compute(runs, "mad", tmp_path / "res")["runs"]["ADAPTIVE"]["gpt-oss:120b"]
    assert a["suites"] == ["banking", "workspace"] and a["utility_retention"] is None and a["utility_delta_vs_none"] is None


def test_tag_events_only_new_bytes(tmp_path):
    from loop import loop as L
    src = tmp_path / "events-workspace.jsonl"
    src.write_text("mixed-old-1\nmixed-old-2\n")  # supervise.py's mixed-attack lines: must stay untagged
    off = L.events_size(tmp_path, "workspace")
    with src.open("a") as f:
        f.write("new\n")
    L.tag_events(tmp_path, "workspace", "none", off)
    assert (tmp_path / "events-workspace.none.jsonl").read_text() == "new\n"
    assert src.read_text() == "mixed-old-1\nmixed-old-2\n"


def test_gate_error_is_failure_not_skip(tmp_path, monkeypatch):
    from loop import loop as L

    class R:
        def __init__(self, rc, out, err=""):
            self.returncode, self.stdout, self.stderr = rc, out, err

    res = {"crash": R(1, "", "Traceback ...\n"), "nokey": R(2, "", "REFUSE no key\n"),
           "budget": R(2, "GATE REFUSE allowed=False reason=cap\n")}
    monkeypatch.setattr(L.subprocess, "run", lambda cmd, **k: res[cmd[1]])
    assert L.gate(["py", "crash"]) is None and L.gate(["py", "nokey"]) is None and L.gate(["py", "budget"]) is False
    monkeypatch.setattr(L, "gate", lambda cmd: None)
    monkeypatch.setattr(L.subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("launched")))
    bad = L.suites_parallel("NONE", {"model": "gpt-oss:20b", "suites": ["workspace"], "attacks": ["none"]}, tmp_path)
    assert bad == ["NONE/gpt-oss:20b/workspace/none (gate error)"]


def test_retention_gates_on_benign_suites(tmp_path):
    # NONE: injected in banking+slack but benign only in banking -> STATIC (benign in both) has no like-for-like base
    from loop import metrics
    runs = tmp_path / "runs"
    _log(runs, "NONE", "m", "banking", "user_task_0", "none", "none", True, False)
    for su in ("banking", "slack"):
        _log(runs, "NONE", "m", su, "user_task_0", "important_instructions", "injection_task_0", True, True)
        _log(runs, "STATIC", "m", su, "user_task_0", "none", "none", True, False)
    _log(runs, "STATIC", "m", "slack", "user_task_0", "important_instructions", "injection_task_0", True, False)
    s = metrics.compute(runs, "mad", tmp_path / "res")["runs"]["STATIC"]["m"]
    assert s["suites"] == ["banking", "slack"] and s["benign_suites"] == ["banking", "slack"]
    assert s["utility_retention"] is None and s["utility_delta_vs_none"] is None


def test_orchestrator_kill_dangling_sink(tmp_path):
    # top-level KILL: log ends on the assistant's sink call, no tool result, error None -> killed under ADAPTIVE*
    from loop import metrics
    runs = tmp_path / "runs"
    for cfg in ("ADAPTIVE_RULES", "NONE"):
        _log(runs, cfg, "m", "banking", "user_task_0", "important_instructions", "injection_task_4", False, False)
        f = next((runs / "mad" / cfg).rglob("injection_task_4.json"))
        d = json.loads(f.read_text())
        d["messages"][-1] = {"role": "assistant", "content": None, "tool_calls": [
            {"function": "update_scheduled_transaction", "args": {}, "id": "c9", "placeholder_args": None}]}
        f.write_text(json.dumps(d))
    m = metrics.compute(runs, "mad", tmp_path / "res")["runs"]
    assert m["ADAPTIVE_RULES"]["m"]["killed_runs"] == 1 and m["NONE"]["m"]["killed_runs"] == 0  # NONE: cutoff


# --- decider v3 sub-steps (PLAN §5 stages 6-7, §8a) ---

def test_dry_run_lists_v3_substeps(tmp_path, monkeypatch, capsys):
    from loop import loop as L
    monkeypatch.setattr(L, "gate", lambda cmd: True)
    monkeypatch.setattr(L.subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("launched")))
    monkeypatch.setattr(L.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ran")))
    monkeypatch.setattr(L, "remaining_usd", lambda prov, runs: 9.5)
    monkeypatch.delenv("SG_DECIDER_HOST", raising=False)
    L.main(["--dry-run", "--iter", "2", "--runs", str(tmp_path / "runs"), "--loopdir", str(tmp_path / "loop")])
    out = capsys.readouterr().out
    for s in ("[harvest] FN/FP", "-m train.from_mad_runs", "--configs NONE STATIC ADAPTIVE_RULES", "rows_iter_2_mad.jsonl",
              "[retrain/dataset] $", "-m train.merge_v3", "--extra train/rows_iter_2_fnfp.jsonl",
              "[retrain/box] tag swarmguard-decider:v3", "ollama create swarmguard-decider:v3", "data_v3/train.jsonl",
              "[retrain/calibrate] $", "--endpoint $SG_DECIDER_HOST", "--calibrate-from", "iter_2/risk_map.yaml"):
        assert s in out, s
    assert out.index("[harvest]") < out.index("[retrain/dataset]") < out.index("[retrain/box]") < out.index("[retrain/calibrate]")
    assert not (tmp_path / "loop").exists()  # dry-run writes nothing


def test_harvest_runs_mad_converter(tmp_path, monkeypatch):
    from loop import harvest as H
    runs, calls = fake_tree(tmp_path), []

    def fake_run(cmd, cwd, check):
        calls.append(cmd)
        Path(cmd[cmd.index("--out") + 1]).write_text('{"row": {}, "cls": "benign"}\n')

    monkeypatch.setattr(H.subprocess, "run", fake_run)
    H.main(["--runs", str(runs), "--iter", "3", "--out-dir", str(tmp_path / "train"), "--mad-configs", "NONE", "STATIC"])
    (cmd,) = calls
    assert cmd[1:3] == ["-m", "train.from_mad_runs"] and cmd[cmd.index("--runs") + 1] == str(runs / "mad")
    assert cmd[cmd.index("--configs") + 1: cmd.index("--out")] == ["NONE", "STATIC"]
    assert cmd[cmd.index("--stats") + 1].endswith("rows_iter_3_mad.stats.json")
    assert (tmp_path / "train/rows_iter_3_mad.jsonl").exists() and (tmp_path / "train/rows_iter_3.jsonl").exists()
    calls.clear()  # no --mad-configs -> converter not called
    H.main(["--runs", str(runs), "--iter", "4", "--out-dir", str(tmp_path / "train")])
    assert calls == []


def _retrain_args(tmp_path, sub=None):
    return type("A", (), {"iter": 2, "train_dir": str(tmp_path / "train"), "results": str(tmp_path / "results"),
                          "loopdir": str(tmp_path / "loop"), "runs": str(tmp_path / "runs"), "dry_run": False,
                          "sub": sub})()


def test_retrain_dataset_wraps_fnfp_and_merges(tmp_path, monkeypatch):
    from loop import loop as L
    td = tmp_path / "train"
    td.mkdir()
    (td / "data_v3").mkdir()
    (td / "data_v3/synth_rows.jsonl").write_text("")
    ev = Event(run_id="r", agent_id="a", step=0, kind=EventKind.TOOL_CALL, tool="send_money")
    row = TrainRow(task="t", role={"task_id": "t", "tools": ["send_money"]}, window=[ev], source="mad:x",
                   output={"risk": 9, "category": "prompt_injection", "first_bad_step": 0, "rationale": "r"})
    (td / "rows_iter_1.jsonl").write_text(row.model_dump_json() + "\n")
    (td / "rows_iter_1_mad.jsonl").write_text("not a TrainRow\n")  # converter output: not wrapped
    cmds = []
    monkeypatch.setattr(L, "sh", cmds.append)
    L.stage_retrain(_retrain_args(tmp_path, "dataset"))
    (cmd,) = cmds
    assert cmd[1:3] == ["-m", "train.merge_v3"] and cmd[cmd.index("--mad") + 1] == str(td / "rows_iter_2_mad.jsonl")
    assert cmd[cmd.index("--synth") + 1] == str(td / "data_v3/synth_rows.jsonl")
    (line,) = (td / "rows_iter_2_fnfp.jsonl").read_text().splitlines()
    w = json.loads(line)
    assert w["cls"] == "hijacked" and TrainRow.model_validate(w["row"]).output.risk == 9


def _eval_json(path, splits, risk_map, sweep):
    path.write_text(json.dumps({"model": "swarmguard-decider:v3", "splits": splits,
                                "calibration": {"risk_map": risk_map, "sweep": sweep}}))


def test_calibrate_writes_risk_map_and_summary(tmp_path, monkeypatch):
    from loop import loop as L, compare
    a = _retrain_args(tmp_path, "calibrate")
    res = tmp_path / "results"
    res.mkdir()
    monkeypatch.delenv("SG_DECIDER_HOST", raising=False)
    cmds = []
    monkeypatch.setattr(L, "sh", cmds.append)
    L.stage_retrain(a)  # pending: not served, no eval JSON -> nothing written, nothing run
    assert cmds == [] and not (tmp_path / "loop/iter_2/risk_map.yaml").exists()

    sw = [{"cutoff": c / 2, "recall": 1.0, "fpr": max(0.0, 0.5 - c / 10)} for c in range(21)]
    _eval_json(res / "decider_eval_v3_val.json", {}, [[0, 0], [2, 3.9], [5, 6.0], [7, 8.0], [10, 10]], sw)
    _eval_json(res / "decider_eval_v3_test.json",
               {"test_ood.jsonl": {"f1@risk>=8": 0.9, "fpr@95recall": 0.05},
                "test_mad_ood.jsonl": {"f1@risk>=8": None, "sweep": sw}}, [], [])

    class R:
        returncode, stdout, stderr = 0, "  risk_map: [[0, 0], [10, 10]]\n", ""

    monkeypatch.setattr(L.subprocess, "run", lambda cmd, **k: R)
    monkeypatch.setenv("SG_DECIDER_HOST", "http://box:11434/v1")
    L.stage_retrain(a)
    assert cmds == []  # eval JSONs already exist -> not re-run
    rm = (tmp_path / "loop/iter_2/risk_map.yaml").read_text()
    assert "risk_map: [[0, 0], [10, 10]]" in rm and "bench/configs/ADAPTIVE.yaml" in rm and "v3" in rm
    s = json.loads((res / "decider_eval.json").read_text())
    assert s["attenuate_raw_cutoff"] == 5 and s["benign_fpr_attenuate"] == 0.0  # fpr at cutoff 5.0 on test_mad_ood
    assert s["f1"] == 0.9 and s["test_mad_ood_f1"] is None
    st = {t["id"]: t["status"] for t in compare.check({"decider": s}, compare.yaml.safe_load(
        compare.TARGETS.read_text())["targets"])}
    assert st["decider_f1"] == "PASS" and st["decider_fpr_attenuate"] == "PASS" and st["decider_mad_ood_f1"] == "MISSING"


def test_calibrate_runs_eval_when_served(tmp_path, monkeypatch):
    from loop import loop as L
    monkeypatch.setenv("SG_DECIDER_HOST", "http://box:11434/v1")
    cmds = []
    monkeypatch.setattr(L, "sh", cmds.append)
    L.stage_calibrate(_retrain_args(tmp_path))
    assert len(cmds) == 2 and all(c[c.index("--endpoint") + 1] == "http://box:11434/v1" for c in cmds)
    assert cmds[0][cmds[0].index("--model") + 1] == "swarmguard-decider:v3"
    assert not (tmp_path / "loop/iter_2/risk_map.yaml").exists()  # sh mocked -> no val JSON -> pending
