"""GuardedToolsExecutor: the fork's ToolsExecutor with the gateway in front of every call.

Reused: agentdojo ToolsExecutor (execution, formatting, 'Invalid tool' error path), AbortAgentError.
Deny = rename the call to DENIED_<tool> with the SAME id (scout SC1): the original name leaves the
security trace, the env is untouched, the base class appends the error result, and the OpenAI
tool_call_id pairing stays valid (dropping the call while answering its id is an API 400).
"""
from __future__ import annotations

from collections.abc import Callable, Sequence

from agentdojo.agent_pipeline.errors import AbortAgentError
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, get_text_content_as_str

from sg.gateway import Gateway
from sg.schema import Action

DENIED_PREFIX = "DENIED_"


class GuardedToolsExecutor(ToolsExecutor):
    def __init__(self, gateway: Gateway, token: str, task_text: str,
                 tool_output_formatter: Callable = tool_result_to_str) -> None:
        super().__init__(tool_output_formatter)
        self.gw, self.task_text = gateway, task_text
        self.agent_id = gateway.verify(token).agent_id

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        calls, denied = [], {}
        for i, tc in enumerate(messages[-1]["tool_calls"]):
            token = self.gw.tokens[self.agent_id]  # latest (attenuation re-mints)
            d = self.gw.check(token, tc.function, dict(tc.args or {}), self.task_text)
            if d.action == Action.KILL:
                raise AbortAgentError(f"SwarmGuard stopped this agent: {d.deny_reason}", list(messages), env)
            if d.allow:
                calls.append(tc)
            else:
                denied[i] = d.deny_reason
                calls.append(tc.model_copy(update={"function": DENIED_PREFIX + tc.function}))
        last = {**messages[-1], "tool_calls": calls}
        base = [*messages[:-1], last]
        query, runtime, env, out, extra_args = super().query(query, runtime, env, base, extra_args)
        results = list(out[len(base):])
        for i, res in enumerate(results):  # base appends one result per call, in order
            if i in denied:
                results[i] = {**res, "error": (f"PermissionError: {denied[i]}. Please try other tools or "
                                               f"arguments and continue to finish the user task.")}
            else:
                text = res["error"] or get_text_content_as_str(res["content"])
                self.gw.ingest(self.agent_id, calls[i].function, text)
        return query, runtime, env, [*base, *results], extra_args
