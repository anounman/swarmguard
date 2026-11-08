import json
import sys
from collections import Counter

from train import merge_v3 as M

TPL = json.loads(open("train/data_v3/mad_rows.jsonl").readline())["row"]


def rec(task, risk, run, source="gpt-oss:120b", cls=None, **kw):
    row = json.loads(json.dumps(TPL))
    row["task"], row["source"] = task, source
    row["output"].update(risk=risk, category="benign" if risk <= 2 else "prompt_injection")
    for e in row["window"]:
        e["run_id"] = run
    return {"row": row, "cls": cls or {1: "benign", 4: "resisted", 9: "hijack"}[risk], **kw}


def write(p, rows):
    p.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return str(p)


def test_merge_holds_out_dedupes_and_bans(tmp_path, monkeypatch):
    v2, out = tmp_path / "v2", tmp_path / "v3"
    v2.mkdir(), out.mkdir()
    write(v2 / "train.jsonl", [rec(f"v2 {i}", r, f"v2r{i}", pipeline="agentdrift") for i, r in enumerate([1, 4, 9] * 4)])
    write(v2 / "val.jsonl", [rec(f"v2v {i}", r, f"v2v{i}", pipeline="agentdrift") for i, r in enumerate([1, 4, 9])])
    write(v2 / "test_ood.jsonl", [rec("banned task", 9, "t0")])
    write(v2 / "test_drift.jsonl", [])
    mad = [rec(f"mad {i}", r, f"m{i}", meta={"config": "NONE"}) for i, r in enumerate([1, 4, 9] * 3)]
    mad += [mad[0], rec("banned task", 9, "t0"), rec("ds 1", 1, "d1", source="deepseek-v4.1-flash", meta={"config": "NONE"})]
    synth = [rec(f"syn {i}", r, f"s{i}", pipeline="synth-x") for i, r in enumerate([9, 1])]
    mad += [rec("conflict", 4, "c1"), rec("conflict", 9, "c1")]  # same prompt, two labels -> higher risk kept once
    extra = [rec("loop ds", 9, "x1", pipeline="mad:ADAPTIVE:deepseek-v4.1-flash")]  # loop harvest of held-out model
    args = ["x", "--v2", str(v2), "--mad", write(tmp_path / "mad.jsonl", mad), "--synth", write(tmp_path / "s.jsonl", synth),
            "--extra", write(tmp_path / "x.jsonl", extra), "--out", str(out)]
    monkeypatch.setattr(sys, "argv", args)
    M.main()
    load = lambda n: [json.loads(l) for l in open(out / f"{n}.jsonl")]
    tr, va, te = load("train"), load("val"), load("test_mad_ood")
    tasks = [r["row"]["task"] for r in tr + va]
    assert [r["row"]["task"] for r in te] == ["ds 1"] and "ds 1" not in tasks  # held out, never in train/val
    assert "banned task" not in tasks and len(tasks) == len(set(tasks))  # v2 test prompt banned; duplicate kept once
    assert "loop ds" not in tasks  # held-out model never leaks in via --extra
    assert [r["row"]["output"]["risk"] for r in tr + va if r["row"]["task"] == "conflict"] in ([], [9])
    assert tr[0]["messages"][-1]["role"] == "assistant" and "output" in tr[0]["row"]  # chat + raw, as splits.emit
    s = json.load(open(out / "stats.json"))["splits"]
    assert s["test_mad_ood"]["by_source"] == {"deepseek-v4.1-flash": 1} and s["train"]["synth_share"] <= 0.3


def test_shape_caps_synth_and_ratio_dropping_v2_first():
    rows = [M.norm(rec(f"b{i}", 1, f"b{i}"), "v2") for i in range(20)] \
        + [M.norm(rec(f"m{i}", 1, f"m{i}"), "mad") for i in range(5)] \
        + [M.norm(rec(f"h{i}", 9, f"h{i}"), "synth") for i in range(10)] \
        + [M.norm(rec(f"f{i}", 4, f"f{i}"), "v2") for i in range(6)]
    out = M.shape(rows)
    c = Counter(M.grp(r) for r in out)
    assert max(c.values()) <= 2 * min(c.values())
    assert sum(r["origin"] == "synth" for r in out) <= 0.3 * len(out) + 1e-9
    assert sum(r["origin"] == "mad" for r in out) == 5  # new-source rows survive, v2 benign cut instead


def test_winners_keeps_higher_risk_per_prompt():
    a, b = M.norm(rec("same", 4, "r"), "mad"), M.norm(rec("same", 9, "r"), "mad")
    top = M.winners([a, b])
    assert M.dedup([a, b], top) == [b]
