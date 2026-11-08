"""SwarmGuard shared contract (PLAN.md §4). FROZEN.

Every stream imports from here. Nobody forks or redefines these types.
Additive changes only, via the orchestrator.
"""
from __future__ import annotations

import fnmatch
import json
import re
import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def _uid(n: int = 12) -> str:
    return uuid.uuid4().hex[:n]


# ---------------------------------------------------------------- configs
class GuardConfig(str, Enum):
    """Benchmark configurations (PLAN.md §2)."""

    NONE = "NONE"  # vanilla MAD
    STATIC = "STATIC"  # role designer -> signed token, deny-list, labels + egress
    ADAPTIVE_RULES = "ADAPTIVE_RULES"  # STATIC + RulesMonitor -> attenuate/kill
    ADAPTIVE = "ADAPTIVE"  # STATIC + trained decider
    ADAPTIVE_AUDIT = "ADAPTIVE_AUDIT"  # ADAPTIVE + cloud auditor on flagged band


# ---------------------------------------------------------------- labels
class Conf(str, Enum):
    """Confidentiality level of data / clearance of an agent or sink. Ordered."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"

    @property
    def rank(self) -> int:
        return _CONF_RANK[self]


_CONF_RANK = {Conf.PUBLIC: 0, Conf.INTERNAL: 1, Conf.CONFIDENTIAL: 2, Conf.SECRET: 3}


def max_conf(*confs: Conf) -> Conf:
    return max(confs, key=lambda c: c.rank)


def min_conf(*confs: Conf) -> Conf:
    return min(confs, key=lambda c: c.rank)


class Label(BaseModel):
    """Information-flow label on a value.

    trusted=False for anything produced by a tool / external source (the injection
    channel). conf = highest confidentiality of any source that flowed into the value.
    """

    trusted: bool = True
    conf: Conf = Conf.INTERNAL
    sources: list[str] = Field(default_factory=list)  # event ids or tool names

    def join(self, other: "Label") -> "Label":
        return Label(
            trusted=self.trusted and other.trusted,
            conf=max_conf(self.conf, other.conf),
            sources=sorted(set(self.sources) | set(other.sources)),
        )

    @staticmethod
    def join_all(labels: list["Label"]) -> "Label":
        out = Label(trusted=True, conf=Conf.PUBLIC)
        for lb in labels:
            out = out.join(lb)
        return out

    def flows_to(self, clearance: Conf) -> bool:
        """Egress rule: data may reach a sink whose clearance >= data confidentiality."""
        return self.conf.rank <= clearance.rank


# ---------------------------------------------------------------- roles
def _covered(pattern: str, parents: list[str]) -> bool:
    # ponytail: glob-on-glob approximated by fnmatch(child, parent); exact for
    # literal children, permissive for wildcard children. Tighten if attacks exploit it.
    return any(pattern == p or fnmatch.fnmatch(pattern, p) for p in parents)


class Role(BaseModel):
    """IAM-style per-task role (ARCHITECTURE.md 'How a role works')."""

    task_id: str
    name: str = "agent"
    tools: list[str] = Field(default_factory=list)
    paths_ro: list[str] = Field(default_factory=list)  # globs
    paths_rw: list[str] = Field(default_factory=list)  # globs
    egress_sinks: list[str] = Field(default_factory=list)  # tools that move data out
    # sink -> arg name -> allowed values (exact or glob). Missing arg => unconstrained.
    egress_allow: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    domains: list[str] = Field(default_factory=list)
    allow_cmds: list[str] = Field(default_factory=list)
    deny_patterns: list[str] = Field(default_factory=list)  # regex over json(args)
    clearance: Conf = Conf.INTERNAL
    max_depth: int = 0  # further delegation levels this role may spawn
    budget_calls: int = 50
    ttl_s: int = 600

    # -- set semantics --------------------------------------------------
    def is_subset_of(self, parent: "Role") -> bool:
        if not set(self.tools) <= set(parent.tools):
            return False
        if not set(self.egress_sinks) <= set(parent.egress_sinks):
            return False
        if not set(self.domains) <= set(parent.domains):
            return False
        if not set(self.allow_cmds) <= set(parent.allow_cmds):
            return False
        if not set(parent.deny_patterns) <= set(self.deny_patterns):
            return False  # child must keep every parent deny
        if not all(_covered(p, parent.paths_ro + parent.paths_rw) for p in self.paths_ro):
            return False
        if not all(_covered(p, parent.paths_rw) for p in self.paths_rw):
            return False
        for sink, args in self.egress_allow.items():
            pargs = parent.egress_allow.get(sink, {})
            for arg, vals in args.items():
                if arg in pargs and not all(_covered(v, pargs[arg]) for v in vals):
                    return False
        # child may not constrain less than parent: every parent-constrained arg must be constrained in child
        for sink, pargs in parent.egress_allow.items():
            if sink in self.egress_sinks:
                cargs = self.egress_allow.get(sink, {})
                if not set(pargs) <= set(cargs):
                    return False
        if self.clearance.rank > parent.clearance.rank:
            return False
        if self.max_depth > parent.max_depth - 1:
            return False
        if self.budget_calls > parent.budget_calls or self.ttl_s > parent.ttl_s:
            return False
        return True

    def intersect(self, parent: "Role") -> "Role":
        """Clamp self into parent. Result always satisfies is_subset_of(parent)."""
        keep = lambda xs, ps: [x for x in xs if x in set(ps)]  # noqa: E731
        egress_allow: dict[str, dict[str, list[str]]] = {}
        sinks = keep(self.egress_sinks, parent.egress_sinks)
        for sink in sinks:
            cargs = dict(self.egress_allow.get(sink, {}))
            pargs = parent.egress_allow.get(sink, {})
            merged: dict[str, list[str]] = {}
            for arg in set(cargs) | set(pargs):
                if arg in cargs and arg in pargs:
                    merged[arg] = [v for v in cargs[arg] if _covered(v, pargs[arg])]
                else:
                    merged[arg] = list(cargs.get(arg, pargs.get(arg, [])))
            if merged:
                egress_allow[sink] = merged
        return Role(
            task_id=self.task_id,
            name=self.name,
            tools=keep(self.tools, parent.tools),
            paths_ro=[p for p in self.paths_ro if _covered(p, parent.paths_ro + parent.paths_rw)],
            paths_rw=[p for p in self.paths_rw if _covered(p, parent.paths_rw)],
            egress_sinks=sinks,
            egress_allow=egress_allow,
            domains=keep(self.domains, parent.domains),
            allow_cmds=keep(self.allow_cmds, parent.allow_cmds),
            deny_patterns=sorted(set(self.deny_patterns) | set(parent.deny_patterns)),
            clearance=min_conf(self.clearance, parent.clearance),
            max_depth=max(0, min(self.max_depth, parent.max_depth - 1)),
            budget_calls=min(self.budget_calls, parent.budget_calls),
            ttl_s=min(self.ttl_s, parent.ttl_s),
        )

    # -- cheap deterministic checks (used by the gateway) ------------------
    def allows_tool(self, tool: str) -> bool:
        return tool in self.tools

    def denied_by_pattern(self, args: dict[str, Any] | None) -> str | None:
        blob = json.dumps(args or {}, sort_keys=True, default=str)
        for pat in self.deny_patterns:
            if re.search(pat, blob):
                return pat
        return None

    def egress_violation(self, tool: str, args: dict[str, Any] | None) -> str | None:
        rules = self.egress_allow.get(tool)
        if not rules:
            return None
        for arg, allowed in rules.items():
            if arg not in (args or {}):
                continue
            vals = (args or {})[arg]
            vals = vals if isinstance(vals, list) else [vals]
            for v in vals:
                if not _covered(str(v), allowed):
                    return f"{tool}.{arg}={v!r} not in {allowed}"
        return None


# ---------------------------------------------------------------- tokens
class TokenClaims(BaseModel):
    """Payload of the Ed25519-signed JWT the gateway mints. Agents cannot sign."""

    jti: str = Field(default_factory=lambda: _uid(16))
    run_id: str
    agent_id: str
    parent_id: str | None = None
    depth: int = 0
    role: Role
    iat: float = Field(default_factory=time.time)
    exp: float

    @classmethod
    def for_role(cls, role: Role, run_id: str, agent_id: str, parent_id: str | None = None, depth: int = 0) -> "TokenClaims":
        now = time.time()
        return cls(run_id=run_id, agent_id=agent_id, parent_id=parent_id, depth=depth, role=role, iat=now, exp=now + role.ttl_s)

    def expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.exp


# ---------------------------------------------------------------- events
class EventKind(str, Enum):
    SPAWN = "SPAWN"
    TOOL_CALL = "TOOL_CALL"  # a call the gateway allowed (pre-exec)
    TOOL_RESULT = "TOOL_RESULT"
    DENY = "DENY"
    DELEGATE = "DELEGATE"
    LLM_TEXT = "LLM_TEXT"  # agent's final / intermediate text
    VERDICT = "VERDICT"  # monitor scored a window
    ATTENUATE = "ATTENUATE"
    KILL = "KILL"
    INCIDENT = "INCIDENT"
    END = "END"


class Event(BaseModel):
    """One line of the append-only event log (JSONL). Decider input + training rows."""

    eid: str = Field(default_factory=_uid)
    run_id: str
    agent_id: str
    step: int
    ts: float = Field(default_factory=time.time)
    kind: EventKind
    tool: str | None = None
    args: dict[str, Any] | None = None
    result_preview: str | None = None  # truncated tool output / text
    labels_in: list[Label] = Field(default_factory=list)
    label_out: Label | None = None
    risk: float | None = None
    latency_ms: float | None = None
    reason: str | None = None  # deny reason / verdict rationale
    meta: dict[str, Any] = Field(default_factory=dict)
    prev: str | None = None  # sha256 of this run's previous JSONL line (sg.log hash chain)


# ---------------------------------------------------------------- verdicts
class Action(str, Enum):
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    ATTENUATE = "ATTENUATE"
    KILL = "KILL"


def action_for(risk: float) -> Action:
    """Risk -> action (ARCHITECTURE.md): 0-3 allow · 4-5 flag · 6-7 attenuate · 8-10 kill."""
    r = max(0.0, min(10.0, float(risk)))
    if r < 4:
        return Action.ALLOW
    if r < 6:
        return Action.FLAG
    if r < 8:
        return Action.ATTENUATE
    return Action.KILL


CATEGORIES = (
    "benign",
    "prompt_injection",
    "exfiltration",
    "unauthorized_action",
    "privilege_escalation",
    "impersonation",
    "replay",
    "laundering",
    "log_tamper",
    "poisoning",
    "unknown",
)


class Verdict(BaseModel):
    """Monitor / decider output. Strict JSON the trained model must emit."""

    risk: float = Field(ge=0, le=10)
    category: str = "benign"
    first_bad_step: int | None = None
    rationale: str = ""

    @property
    def action(self) -> Action:
        return action_for(self.risk)


class Decision(BaseModel):
    """Gateway.check() result."""

    allow: bool
    deny_reason: str | None = None
    risk: float | None = None
    action: Action = Action.ALLOW
    event_id: str = ""
    latency_ms: float = 0.0


class Incident(BaseModel):
    run_id: str
    agent_id: str
    action: Action
    verdict: Verdict
    event_ids: list[str] = Field(default_factory=list)
    ts: float = Field(default_factory=time.time)


# ---------------------------------------------------------------- training
class TrainRow(BaseModel):
    """One supervised example for the decider: (task, role, window) -> Verdict."""

    task: str
    role: Role
    window: list[Event]
    output: Verdict
    source: str = ""  # dataset / model the row came from (for OOD splits)
