import json
import time
from types import SimpleNamespace

import yaml

from bench import budget as B
from bench import providers as P

BUD = {"providers": {"ollama": {"base_url": "https://ollama.com/v1", "cap_usd_total": 10, "reserve_usd": 2},
                     "commandcode": {"base_url": "https://cc/v1", "key_env": "COMMAND_CODE_API", "window_5h_usd": 1,
                                     "window_7d_usd": 50, "month_usd": 100, "reserve_usd": 5},
                     "openrouter": {"base_url": "https://openrouter.ai/api/v1", "key_env": "OPENROUTER_API_KEY",
                                    "cap_usd": 9.5, "allowed_models": ["openai/gpt-4.1"]},
                     "openai": {"allowed": False}},
       "prices": {"gpt-oss:120b": {"input": 0.15, "output_est": 0.6},
                  "deepseek/deepseek-v4.1-flash": {"input": 0.15, "output": 0.6, "provider": "commandcode"},
                  "openai/gpt-4.1": {"input": 2, "output": 8, "provider": "openrouter"},
                  "gpt-4o": {"input": 1, "output": 1, "provider": "openai"}}}


def test_allows_under_cap():
    d = B.gate("gpt-oss:120b", 100, BUD, [{"provider": "ollama", "est_usd": 1, "key": "A"}], key="A")
    assert d["allowed"] and d["remaining_usd"] == 7 and d["spent_key_usd"] == 1


def test_refuses_over_cap():
    d = B.gate("openai/gpt-4.1", 1000, BUD, [])  # 1000 * (6000*2 + 2000*8)/1e6 = $28
    assert not d["allowed"] and "remaining" in d["reason"]


def test_refuses_commandcode_5h_window():
    rows = [{"provider": "commandcode", "est_usd": 0.9, "ts": time.time() - 3600},
            {"provider": "commandcode", "est_usd": 30, "ts": time.time() - 86400 * 10}]  # outside both windows
    d = B.gate("deepseek/deepseek-v4.1-flash", 100, BUD, rows)  # proj $0.21; 0.9 + 0.21 > 1
    assert not d["allowed"] and "window_5h" in d["reason"]
    assert B.gate("deepseek/deepseek-v4.1-flash", 100, BUD, rows[1:])["allowed"]


def test_refuses_disallowed_provider():
    d = B.gate("gpt-4o", 1, BUD, [])
    assert not d["allowed"] and "not allowed" in d["reason"]


def test_projection_uses_measured_tokens():
    row = {"model": "gpt-oss:120b", "attack": "important_instructions", "n_tasks": 1, "n_episodes": 10,
           "prompt_tokens": 10000, "completion_tokens": 0, "est_usd": 0}
    assert B.tokens_per_episode([row] * 2, "gpt-oss:120b") == (6000, 2000, False)
    assert B.tokens_per_episode([row] * 3, "gpt-oss:120b") == (1000, 0, True)
    assert B.gate("gpt-oss:120b", 1000, BUD, [row] * 3)["projected_usd"] == 0.15
    legacy_attack = {**row, "n_episodes": None}  # pre-gate injected rows: episodes unknown -> ignored
    assert not B.tokens_per_episode([legacy_attack] * 3, "gpt-oss:120b")[2]


def test_plan_pairs_and_missing(tmp_path):
    pairs = B.plan_pairs(["user_task_10", "user_task_2"], ["injection_task_1", "injection_task_0"], "x",
                         max_episodes=3)
    assert pairs == [("user_task_2", "injection_task_0"), ("user_task_2", "injection_task_1"),
                     ("user_task_10", "injection_task_0")]
    f = tmp_path / "pipe/workspace/user_task_2/x/injection_task_0.json"
    f.parent.mkdir(parents=True)
    f.write_text("{}")
    assert len(B.missing(pairs, tmp_path, "pipe", "workspace", "x")) == 2
    assert B.plan_pairs(["user_task_1"], ["i_0"], "none") == [("user_task_1", None)]


def _env(tmp_path, monkeypatch, cap):
    bud = {**BUD, "providers": {**BUD["providers"], "ollama": {**BUD["providers"]["ollama"], "cap_usd_total": cap}}}
    (tmp_path / "b.yaml").write_text(yaml.safe_dump(bud))
    monkeypatch.setattr(P, "BUDGET", tmp_path / "b.yaml")
    monkeypatch.setattr(B, "SPEND", tmp_path / "spend.jsonl")


def test_dry_run_exit_codes_no_network(tmp_path, monkeypatch, capsys):
    from bench import run
    monkeypatch.setattr(run, "run_suite", lambda *a: (_ for _ in ()).throw(AssertionError("model call")))
    monkeypatch.setattr(run.subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("spawn")))
    args = ["--config", "NONE", "--model", "gpt-oss:120b", "--suite", "workspace", "--attack", "none", "--key", "A",
            "--logdir", str(tmp_path / "logs"), "--dry-run"]
    _env(tmp_path, monkeypatch, cap=100)
    assert run.main(args) == 0 and "GATE ALLOW" in capsys.readouterr().out
    _env(tmp_path, monkeypatch, cap=2)  # remaining 0
    assert run.main(args) == 2 and "GATE REFUSE" in capsys.readouterr().out
    assert run.main(args[:-1] + ["--suite", "all"]) == 2  # parent gate refuses before any spawn
    assert not (tmp_path / "spend.jsonl").exists()


def test_spend_record_fields(tmp_path, monkeypatch):
    from bench import run
    monkeypatch.setattr(B, "SPEND", tmp_path / "spend.jsonl")
    a = SimpleNamespace(model="gpt-4.1", config="ADAPTIVE", suite="workspace", attack="none", logdir="L",
                        res=P.resolve("gpt-4.1", budget=BUD), _run_id="r")
    rec = run.spend_record(a, "pipe", 2, 2, {"prompt_tokens": 1e6, "completion_tokens": 1e6, "estimated": False}, BUD)
    B.record(rec)
    got = json.loads((tmp_path / "spend.jsonl").read_text())
    want = {"ts", "provider", "key", "model", "config", "suite", "attack", "n_tasks", "n_episodes", "prompt_tokens",
            "completion_tokens", "tokens_estimated", "est_usd", "logdir", "pipeline"}
    assert want <= got.keys() and got["provider"] == "openrouter" and got["est_usd"] == 10
    assert got["price_is_estimate"] is False and got["run_id"] == "r-workspace"
    assert B.spent(B.read_spend(), "openrouter", BUD) == 10


def test_legacy_rows_without_provider():
    assert B.row_provider({"model": "gpt-oss:20b"}, BUD) == "ollama"
    assert B.row_provider({"model": "gpt-4.1"}, BUD) == "openai"


def test_no_gate_and_suite_all_key_split(tmp_path, monkeypatch, capsys):
    from bench import run
    _env(tmp_path, monkeypatch, cap=2)  # gate would refuse
    cmds = []

    class FakeProc:
        def __init__(self, cmd):
            cmds.append(cmd)

        def wait(self):
            return 0

    monkeypatch.setattr(run.subprocess, "Popen", FakeProc)
    args = ["--config", "NONE", "--model", "gpt-oss:120b", "--attack", "none", "--logdir", str(tmp_path), "--no-gate"]
    assert run.main(args) == 0 and "BYPASSED" in capsys.readouterr().err
    keys = {c[c.index("--suite") + 1]: c[c.index("--key") + 1] for c in cmds}
    assert keys == run.KEY_SPLIT and all("--_gated" in c for c in cmds)
    cmds.clear()  # explicit --key A is ignored with --suite all (max 3 concurrent per key)
    assert run.main(args + ["--key", "A"]) == 0
    assert {c[c.index("--suite") + 1]: c[c.index("--key") + 1] for c in cmds} == run.KEY_SPLIT
    assert all(c.count("--key") == 1 for c in cmds)
    res = [r for r in B.read_spend() if r.get("reserved")]  # parent reserved one row per suite for its children
    rid = cmds[0][cmds[0].index("--_run_id") + 1]
    assert {r["run_id"] for r in res} >= {f"{rid}-{s}" for s in run.SUITES}


def test_resumed_zero_token_rows_do_not_dilute_average():
    real = {"model": "gpt-oss:120b", "attack": "none", "n_tasks": 10, "n_episodes": 10,
            "prompt_tokens": 60000, "completion_tokens": 20000}
    resumed = {**real, "n_episodes": 0, "prompt_tokens": 0, "completion_tokens": 0}
    legacy_resumed = {"model": "gpt-oss:120b", "attack": "none", "n_tasks": 16, "prompt_tokens": 0,
                      "completion_tokens": 0}
    crashed = {**real, "prompt_tokens": 10, "crashed": True}
    want = B.tokens_per_episode([real] * 3, "gpt-oss:120b")
    assert want == (6000, 2000, True)
    assert B.tokens_per_episode([real] * 3 + [resumed, legacy_resumed, crashed] * 3, "gpt-oss:120b") == want


def test_reservation_counts_until_final_row():
    res = {"provider": "openrouter", "reserved": True, "run_id": "x-workspace", "est_usd": 5, "ts": time.time()}
    assert B.spent([res], "openrouter", BUD) == 5
    assert not B.gate("openai/gpt-4.1", 200, BUD, [res])["allowed"]  # 200 eps = $5.6 > 9.5 - 5
    assert B.gate("openai/gpt-4.1", 200, BUD, [])["allowed"]
    final = {"provider": "openrouter", "run_id": "x-workspace", "est_usd": 1, "ts": time.time()}
    assert B.spent([res, final], "openrouter", BUD) == 1
    assert B.spent([{**res, "ts": time.time() - B.RESERVE_TTL - 1}], "openrouter", BUD) == 0


def test_legacy_rows_repriced_at_budget_prices():
    old = {"model": "gpt-oss:120b", "prompt_tokens": 1e6, "completion_tokens": 1e6, "est_usd": 0.6}
    assert B.spent([old], "ollama", BUD) == 0.75  # 0.15 + 0.60, not the stale stored 0.6


def test_run_suite_books_spend_when_pipeline_crashes(tmp_path, monkeypatch):
    import sys
    import types

    from bench import run
    monkeypatch.setattr(B, "SPEND", tmp_path / "spend.jsonl")

    class Boom:
        name = "p"
        llm_counter = SimpleNamespace(total={"prompt_tokens": 1e6, "completion_tokens": 0, "estimated": False})
    monkeypatch.setitem(sys.modules, "bench.mad_guard", types.SimpleNamespace(make_pipeline=lambda *a, **k: Boom()))
    monkeypatch.setattr(run.P, "provider_env", lambda res: {})
    import agentdojo.benchmark as ab
    monkeypatch.setattr(ab, "run_task_without_injection_tasks", lambda *a: (_ for _ in ()).throw(RuntimeError("500")))
    a = run.main.__globals__["argparse"].Namespace(
        model="openai/gpt-4.1", config="NONE", suite="banking", attack="none", n=1, inj=None, max_episodes=None,
        force=True, name=None, logdir=str(tmp_path / "logs"), res=P.resolve("openai/gpt-4.1", budget=BUD),
        _run_id="r")
    import pytest
    with pytest.raises(RuntimeError):
        run.run_suite(a, BUD)
    (row,) = B.read_spend()
    assert row["crashed"] and row["est_usd"] == 2 and row["run_id"] == "r-banking"
