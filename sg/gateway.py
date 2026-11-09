"""sg Gateway: the only door. spawn -> signed token; check -> Decision; every check logged."""
from __future__ import annotations

import time
from typing import Any

from sg.identity import Identity, TokenError
from sg.labels import SINKS, TaintTracker
from sg.log import EventLog
from sg.monitors import Monitor, injection_hits, is_injection, monitor_failed
from sg.roles import design_role, egress_check
from sg.schema import Action, Decision, Event, EventKind, GuardConfig, Label, TokenClaims, Verdict

ADAPTIVE = {GuardConfig.ADAPTIVE_RULES, GuardConfig.ADAPTIVE, GuardConfig.ADAPTIVE_AUDIT}


class Gateway:
    def __init__(self, config: GuardConfig, run_id: str, monitor: Monitor | None = None, log_path: str | None = None):
        self.config = GuardConfig(config)
        self.run_id = run_id
        self.monitor = monitor
        self.id = Identity()
        self.log = EventLog(log_path, key=self.id._sk)  # each write also signs the run's chain head
        self.taint = TaintTracker()  # run-wide: catches values laundered across agents
        self.tokens: dict[str, str] = {}  # agent_id -> current token
        self.killed: set[str] = set()
        self.halted: str | None = None  # set by kill(): KILL is run-wide (see kill())
        self.step = 0
        self._n = 0

    # ------------------------------------------------------------ helpers
    def _event(self, **kw: Any) -> Event:
        self.step += 1
        return self.log.append(Event(run_id=self.run_id, step=self.step, **kw))

    def verify(self, token: str) -> TokenClaims:
        c = self.id.verify(token)
        if c.run_id != self.run_id or c.agent_id in self.killed:
            raise TokenError(f"invalid token: agent {c.agent_id} killed or foreign run")
        return c

    # ------------------------------------------------------------ lifecycle
    def spawn(self, parent_token: str | None, spec_name: str, tool_names: list[str], task: str):
        """-> (agent_id, token, role). Child role is clamped into the parent's (child <= parent)."""
        if self.halted:
            raise TokenError(f"run stopped by SwarmGuard: {self.halted}")
        parent = self.verify(parent_token) if parent_token else None
        if parent is not None and parent.role.max_depth < 1:
            raise TokenError(f"{parent.agent_id} may not delegate (max_depth=0)")
        self._n += 1
        agent_id = f"{spec_name}-{self._n}"
        role = design_role(spec_name, tool_names, task, parent.role if parent else None, task_id=self.run_id)
        claims = TokenClaims.for_role(role, self.run_id, agent_id, parent.agent_id if parent else None,
                                      parent.depth + 1 if parent else 0)
        token = self.id.mint(claims)
        self.tokens[agent_id] = token
        self._event(agent_id=agent_id, kind=EventKind.SPAWN, reason=task[:500],
                    meta={"parent": claims.parent_id, "tools": role.tools, "egress_allow": role.egress_allow})
        return agent_id, token, role

    def attenuate(self, token: str, drop_tools: list[str]) -> str:
        c = self.id.verify(token)
        role = c.role.model_copy(update={
            "tools": [t for t in c.role.tools if t not in drop_tools],
            "egress_sinks": [t for t in c.role.egress_sinks if t not in drop_tools],
            "egress_allow": {k: v for k, v in c.role.egress_allow.items() if k not in drop_tools},
        })
        new = TokenClaims(run_id=c.run_id, agent_id=c.agent_id, parent_id=c.parent_id, depth=c.depth, role=role, exp=c.exp)
        self.id.calls[new.jti] = self.id.calls[c.jti]
        self.id.revoke(c.jti)
        tok = self.id.mint(new)
        self.tokens[c.agent_id] = tok
        self._event(agent_id=c.agent_id, kind=EventKind.ATTENUATE, reason=f"dropped {drop_tools}")
        return tok

    def kill(self, agent_id: str, reason: str = "") -> None:
        """KILL stops the whole run, not just the agent: inside a MAD sub-agent the fork's
        FunctionsRuntime swallows AbortAgentError, so the orchestrator would otherwise just
        re-delegate. After a kill every check (orchestrator included) returns Action.KILL, and
        GuardedToolsExecutor raises AbortAgentError at that level."""
        self.killed.add(agent_id)
        self.halted = self.halted or f"agent {agent_id} killed: {reason}"[:300]
        self._event(agent_id=agent_id, kind=EventKind.KILL, reason=reason)

    def ingest(self, agent_id: str, tool: str, result_text: str) -> None:
        """Record an (untrusted) tool result: taint + TOOL_RESULT event."""
        hits = injection_hits(result_text or "")
        if self.config != GuardConfig.NONE:
            self.taint.ingest(tool, result_text, injected=is_injection(hits))
        self._event(agent_id=agent_id, kind=EventKind.TOOL_RESULT, tool=tool, result_preview=(result_text or "")[:4000],
                    label_out=Label(trusted=False, sources=[tool]), meta={"inj": hits})

    def window(self, agent_id: str, n: int = 30) -> list[Event]:
        """Last n events of the agent plus every earlier injected TOOL_RESULT of it, so a
        delayed 'inject now, act later' attack stays visible to the monitor."""
        w = self.log.window(agent_id, n)
        old = [e for e in self.log.events[:-n] if e.agent_id == agent_id and e.kind == EventKind.TOOL_RESULT
               and is_injection(e.meta.get("inj") or [])]
        return [e for e in old if e not in w] + w

    # ------------------------------------------------------------ the check
    def check(self, token: str, tool: str, args: dict[str, Any] | None, task_text: str) -> Decision:
        t0 = time.perf_counter()
        agent_id, label, verdict = "?", None, None

        def done(allow: bool, reason: str | None = None, action: Action = Action.ALLOW) -> Decision:
            ms = (time.perf_counter() - t0) * 1000
            ev = self._event(agent_id=agent_id, kind=EventKind.TOOL_CALL if allow else EventKind.DENY, tool=tool,
                             args=args, label_out=label, risk=verdict.risk if verdict else None, latency_ms=ms,
                             reason=reason, meta={"action": action.value, "config": self.config.value})
            return Decision(allow=allow, deny_reason=reason, risk=ev.risk, action=action, event_id=ev.eid, latency_ms=ms)

        if self.config == GuardConfig.NONE:
            return done(True)
        if self.halted:
            return done(False, f"run stopped by SwarmGuard: {self.halted}", Action.KILL)
        try:
            c = self.verify(token)
        except TokenError as e:
            return done(False, str(e))
        agent_id, role = c.agent_id, c.role
        if not role.allows_tool(tool):
            return done(False, f"tool {tool!r} not in role {role.name}")
        if (pat := role.denied_by_pattern(args)) is not None:
            return done(False, f"args match deny pattern {pat!r}")
        adaptive = self.config in ADAPTIVE and self.monitor is not None
        egress = egress_check(role, tool, args)
        if egress is not None and not (adaptive and tool in SINKS):  # ADAPTIVE: the monitor judges egress misses
            return done(False, f"egress not allowed: {egress}")
        if tool in SINKS:
            label = self.taint.label_args(tool, args, task_text)
            if adaptive:
                pending = Event(run_id=self.run_id, agent_id=agent_id, step=self.step + 1, kind=EventKind.TOOL_CALL,
                                tool=tool, args=args, label_out=label, meta={"egress": egress} if egress else {})
                verdict = self.monitor.score(self.window(agent_id) + [pending], role, task_text)
                self._event(agent_id=agent_id, kind=EventKind.VERDICT, tool=tool, risk=verdict.risk,
                            reason=verdict.rationale, meta={"category": verdict.category})
                if monitor_failed(verdict) and (egress or not label.trusted):  # never fail open on a hit
                    why = f"egress not allowed: {egress}" if egress else f"untrusted value in {tool} args (from {label.sources}, not in task)"
                    return done(False, f"{why}; monitor unavailable ({verdict.rationale})")
                act = verdict.action
                if act == Action.KILL:
                    self.kill(agent_id, verdict.rationale)
                    return done(False, f"killed (risk {verdict.risk}): {verdict.rationale}", Action.KILL)
                if act == Action.ATTENUATE:
                    self.attenuate(token, [tool])
                    return done(False, f"attenuated, {tool} revoked (risk {verdict.risk}): {verdict.rationale}",
                                Action.ATTENUATE)
                # ALLOW / FLAG fall through; FLAG is logged via risk + action
            elif not label.trusted:  # STATIC, or adaptive without a monitor
                return done(False, f"untrusted value in {tool} args (from {label.sources}, not in task)")
        if self.id.spend(c.jti) > role.budget_calls:
            return done(False, f"call budget {role.budget_calls} exhausted")
        return done(True, action=verdict.action if verdict else Action.ALLOW)
