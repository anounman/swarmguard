import json
import time

import pytest

from sg.schema import (
    Action,
    Conf,
    Event,
    EventKind,
    Label,
    Role,
    TokenClaims,
    TrainRow,
    Verdict,
    action_for,
)


def test_action_thresholds():
    assert action_for(0) is Action.ALLOW
    assert action_for(3.9) is Action.ALLOW
    assert action_for(4) is Action.FLAG
    assert action_for(5.9) is Action.FLAG
    assert action_for(6) is Action.ATTENUATE
    assert action_for(7.9) is Action.ATTENUATE
    assert action_for(8) is Action.KILL
    assert action_for(99) is Action.KILL
    assert action_for(-5) is Action.ALLOW


def test_label_join_and_flow():
    a = Label(trusted=True, conf=Conf.PUBLIC, sources=["user"])
    b = Label(trusted=False, conf=Conf.CONFIDENTIAL, sources=["read_file"])
    j = a.join(b)
    assert j.trusted is False and j.conf is Conf.CONFIDENTIAL
    assert j.sources == ["read_file", "user"]
    assert j.flows_to(Conf.SECRET) and not j.flows_to(Conf.INTERNAL)
    assert Label.join_all([]).trusted is True


def parent():
    return Role(
        task_id="t", tools=["read_file", "send_email", "search"], paths_ro=["/data/**"], paths_rw=["/work/**"],
        egress_sinks=["send_email"], egress_allow={"send_email": {"to": ["*@corp.com"]}},
        domains=["corp.com"], allow_cmds=["ls", "cat"], deny_patterns=[r"\brm\b"],
        clearance=Conf.CONFIDENTIAL, max_depth=2, budget_calls=50, ttl_s=600,
    )


def test_role_subset_positive():
    c = Role(
        task_id="t", tools=["read_file", "send_email"], paths_ro=["/data/q3/**"], paths_rw=[],
        egress_sinks=["send_email"], egress_allow={"send_email": {"to": ["alice@corp.com"]}},
        domains=[], allow_cmds=["ls"], deny_patterns=[r"\brm\b", "curl"],
        clearance=Conf.INTERNAL, max_depth=1, budget_calls=20, ttl_s=300,
    )
    assert c.is_subset_of(parent())


@pytest.mark.parametrize(
    "change",
    [
        {"tools": ["read_file", "delete_file"]},
        {"paths_ro": ["/etc/**"]},
        {"paths_rw": ["/data/**"]},
        {"egress_allow": {"send_email": {"to": ["eve@evil.com"]}}},
        {"egress_allow": {}},  # drops parent's constraint on `to`
        {"deny_patterns": []},
        {"clearance": Conf.SECRET},
        {"max_depth": 2},
        {"budget_calls": 51},
        {"ttl_s": 601},
        {"domains": ["evil.com"]},
        {"allow_cmds": ["rm"]},
    ],
)
def test_role_subset_negative(change):
    base = dict(
        task_id="t", tools=["read_file", "send_email"], paths_ro=["/data/q3/**"], paths_rw=["/work/x"],
        egress_sinks=["send_email"], egress_allow={"send_email": {"to": ["alice@corp.com"]}},
        domains=["corp.com"], allow_cmds=["ls"], deny_patterns=[r"\brm\b"],
        clearance=Conf.INTERNAL, max_depth=1, budget_calls=20, ttl_s=300,
    )
    base.update(change)
    assert not Role(**base).is_subset_of(parent())


def test_intersect_always_subset():
    greedy = Role(
        task_id="t", tools=["read_file", "delete_file", "send_email"], paths_ro=["/etc/**", "/data/a"],
        paths_rw=["/data/**", "/work/y"], egress_sinks=["send_email", "post"],
        egress_allow={"send_email": {"to": ["eve@evil.com", "bob@corp.com"]}},
        domains=["evil.com", "corp.com"], allow_cmds=["rm", "ls"], deny_patterns=[],
        clearance=Conf.SECRET, max_depth=9, budget_calls=999, ttl_s=99999,
    )
    c = greedy.intersect(parent())
    assert c.is_subset_of(parent())
    assert c.tools == ["read_file", "send_email"]
    assert c.egress_allow == {"send_email": {"to": ["bob@corp.com"]}}
    assert c.max_depth == 1 and c.clearance is Conf.CONFIDENTIAL
    assert c.paths_rw == ["/work/y"] and c.paths_ro == ["/data/a"]


def test_role_checks():
    r = parent()
    assert r.allows_tool("search") and not r.allows_tool("nuke")
    assert r.denied_by_pattern({"cmd": "rm -rf /"}) == r"\brm\b"
    assert r.denied_by_pattern({"cmd": "ls"}) is None
    assert r.egress_violation("send_email", {"to": "alice@corp.com"}) is None
    assert r.egress_violation("send_email", {"to": ["alice@corp.com", "eve@evil.com"]})
    assert r.egress_violation("read_file", {"path": "x"}) is None


def test_token_claims_expiry():
    r = parent()
    r.ttl_s = 1
    tc = TokenClaims.for_role(r, run_id="r1", agent_id="a1")
    assert not tc.expired()
    assert tc.expired(now=time.time() + 2)
    # round-trip through JSON (what the JWT carries)
    back = TokenClaims.model_validate(json.loads(tc.model_dump_json()))
    assert back == tc


def test_event_and_trainrow_roundtrip():
    e = Event(run_id="r", agent_id="a", step=1, kind=EventKind.TOOL_CALL, tool="send_email", args={"to": "x"})
    v = Verdict(risk=8.5, category="exfiltration", first_bad_step=1, rationale="untrusted -> sink")
    assert v.action is Action.KILL
    row = TrainRow(task="t", role=parent(), window=[e], output=v, source="test")
    back = TrainRow.model_validate_json(row.model_dump_json())
    assert back.window[0].kind is EventKind.TOOL_CALL and back.output.risk == 8.5
    with pytest.raises(Exception):
        Verdict(risk=11)
