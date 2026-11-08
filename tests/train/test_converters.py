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
