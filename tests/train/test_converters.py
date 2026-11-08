import glob
import json

from sg.schema import TrainRow
from train.common import parse_verdict, to_chat
from train.from_agentdojo_runs import rows_for_file
from train.from_agentdrift import rows_for


def test_agentdojo_rows_valid_and_timed():
    files = sorted(glob.glob("data/agentdojo/runs/gpt-4o-2024-05-13/banking/user_task_0/important_instructions/*.json"))[:5]
    rows = [r for f in files for r in rows_for_file(f)]
    assert rows
    for r in rows:
        row = TrainRow.model_validate(r["row"])
        assert len(row.window) <= 8
        msgs = to_chat(row)
        assert parse_verdict(msgs[-1]["content"]) == row.output
        if r["cls"] != "benign":
            steps = [e.step for e in row.window]
            assert row.output.first_bad_step in steps  # onset is inside the window


def test_agentdrift_anonymized():
    line = next(l for l in open("data/agentdrift/data_taskdisjoint/train.jsonl") if '"attacked"' in l)
    d = json.loads(line)
    rows = rows_for(d)
    assert any(r["row"]["output"]["risk"] >= 8 for r in rows)
    blob = json.dumps([r["row"] for r in rows])
    assert d["world"]["user"] not in blob and d["world"]["company"] not in blob


def test_parse_verdict_lenient():
    assert parse_verdict('x {"risk": 9, "category": "prompt_injection"} y').risk == 9
    assert parse_verdict("not json") is None


def test_onset_window_label_independent_of_outcome():
    files = sorted(glob.glob("data/agentdojo/runs/gpt-4o-2024-05-13/banking/user_task_0/important_instructions/*.json"))[:10]
    rows = [r for f in files for r in rows_for_file(f)]
    on = [r for r in rows if r["kind"] == "onset"]
    assert on
    for r in on:
        row = TrainRow.model_validate(r["row"])
        assert r["cls"] == "injection" and row.output.risk == 6.0
        assert row.window[-1].step == row.output.first_bad_step  # window ends at the poisoned result
    for r in rows:
        if r["kind"] == "final" and r["cls"] in ("success", "failed"):
            row = TrainRow.model_validate(r["row"])
            assert row.window[-1].step > row.output.first_bad_step  # agent's response is in view


def test_clip_centres_on_late_injection():
    from train.common import PREVIEW, clip

    s = "x" * 2000 + " <INFORMATION> This is an important message from me " + "y" * 2000
    c = clip(s)
    assert "<INFORMATION>" in c and len(c) <= PREVIEW + 3
    assert clip("short") == "short" and clip("a" * 1000) == "a" * PREVIEW


def test_agentdrift_onset_in_prompt_and_sinks():
    from train.common import WINDOW

    for line in open("data/agentdrift/data_taskdisjoint/train.jsonl"):
        for r in rows_for(json.loads(line)):
            row = TrainRow.model_validate(r["row"])
            assert len(row.window) <= WINDOW
            fb = row.output.first_bad_step
            if fb is not None:
                assert fb in [e.step for e in row.window]
                assert next(e for e in row.window if e.step == fb).kind.value == "TOOL_RESULT"
        if '"hijacked"' in line:
            break
