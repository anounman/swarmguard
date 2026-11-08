# sg core — interface for S2 (MAD wiring)

```python
from sg.gateway import Gateway; from sg.guard import GuardedToolsExecutor; from sg.roles import root_tools
gw = Gateway(GuardConfig.STATIC, run_id, monitor=None, log_path="runs/.../events.jsonl")   # one per task run
oid, otok, orole = gw.spawn(None, "orchestrator", root_tools(specs), user_task)             # root: max_depth 1
aid, tok, role = gw.spawn(otok, spec.name, list(spec.tool_names), delegated_task)            # child ⊆ root, max_depth 0
executor = GuardedToolsExecutor(gw, tok, task_text=user_task, tool_output_formatter=fmt)      # replaces ToolsExecutor
```
- `check(token, tool, args, task_text) -> Decision`: token → tool ∈ role → deny_patterns → egress_allow → taint (sinks only) → budget. Every check = one Event (TOOL_CALL or DENY, with `latency_ms`). p50 ≈ 0.1–1 ms.
- Deny: the call is renamed `DENIED_<tool>` (same id) so it leaves the security trace and never runs; tool result error = `PermissionError: ...`. KILL raises `AbortAgentError` and is **run-wide**: the fork's runtime swallows it inside a sub-agent, so after any kill `gw.halted` is set, every later `check` (orchestrator included) returns `Action.KILL`, the orchestrator's `GuardedToolsExecutor` raises `AbortAgentError` on its next call, and `spawn` raises. The orchestrator MUST run behind a `GuardedToolsExecutor` too, or a kill only stops one sub-agent.
- Pass the **user's** task as `task_text` for every agent. Taint: until any tool output carries injection markers, tool-derived values are trusted; after the first injected output the run goes strict (value came from a tool output and is not in the user's task → untrusted). The taint tracker is run-wide, so orchestrator-laundered values stay tainted.
- Executor reads the agent's *current* token from `gw.tokens[agent_id]` (attenuation re-mints).
- Monitors: `RulesMonitor()`, `LLMMonitor(model, base_url, api_key)`, `CascadeMonitor(rules, llm)`; decider = `LLMMonitor("swarmguard-decider", "http://<box>:11434/v1", "ollama")`.

| config | checks | on sink call |
|---|---|---|
| NONE | none (all allowed) | still logged (TOOL_CALL/TOOL_RESULT events) |
| STATIC | token, tool, deny_patterns, egress_allow (normalised: case, scheme, www.), budget | tainted recipient-like arg not in task → deny |
| ADAPTIVE_RULES / ADAPTIVE / ADAPTIVE_AUDIT | same deterministic chain | monitor scores window → ALLOW / FLAG(allow+log) / ATTENUATE (deny + re-mint without that tool) / KILL; egress misses on sinks go to the monitor (alone → FLAG); monitor error/unparseable + taint or egress hit → deny (fail closed); no monitor passed → STATIC rule |

Ground-truth sweep (v1.2.1, every user task's GT calls through the root role, outputs ingested): STATIC denies GT in 0/40 workspace, 0/20 travel, 1/16 banking (user_task_15 refund IBAN not in the task's egress list; ponytail: accepted), 0/21 slack; ADAPTIVE_RULES 0 everywhere.
Denied calls are renamed `DENIED_<tool>`: fine on OpenAI-compatible hosts; strict non-OpenAI adapters may reject unknown function names in history.
