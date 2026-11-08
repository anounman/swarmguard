"""S2: SwarmGuard wiring into MultiAgentDojo (PLAN §3a, §9 S2).

Reused: agentdojo MultiAgentPipeline (fork), OpenAILLM, AgentPipeline. Only seams here:
per-delegation spawn + GuardedToolsExecutor swap, root token, token-usage counter.
"""
from __future__ import annotations

import itertools
import os
import warnings
from collections.abc import Sequence

import openai
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.llms.openai_llm import (
    OpenAILLM,
    _function_to_openai,
    _message_to_openai,
    _openai_to_assistant_message,
    chat_completion_request,
)
from agentdojo.agent_pipeline.multi_agent import MultiAgentPipeline, SubAgentSpec, _run_elements
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
from agentdojo.functions_runtime import EmptyEnv, Function, FunctionsRuntime, TaskEnvironment
from agentdojo.logging import Logger
from agentdojo.types import ChatMessage, get_text_content_as_str

from sg.schema import GuardConfig


def load_gateway():
    """(Gateway, GuardedToolsExecutor) from sg. The allow-all Noop pair only with SG_ALLOW_NOOP=1
    (otherwise a guarded config would silently report NONE numbers)."""
    if os.environ.get("SG_ALLOW_NOOP") == "1":
        from bench.noop_gateway import NoopGateway, NoopGuardedToolsExecutor

        warnings.warn("SG_ALLOW_NOOP=1: NoopGateway allows everything")
        return NoopGateway, NoopGuardedToolsExecutor
    from sg.gateway import Gateway
    from sg.guard import GuardedToolsExecutor

    return Gateway, GuardedToolsExecutor


def build_monitor(config: GuardConfig, monitor_cfg: dict | None):
    """ADAPTIVE_RULES: rules · ADAPTIVE: rules -> decider on grey band · ADAPTIVE_AUDIT: + auditor on grey band."""
    from sg.monitors import CascadeMonitor, LLMMonitor, RulesMonitor

    def llm(c):
        return LLMMonitor(c["model"], c["base_url"], os.environ[c.get("key_env", "OLLAMA_API_KEY")])

    cfg = monitor_cfg or {}
    if config == GuardConfig.ADAPTIVE_RULES:
        return RulesMonitor()
    if config == GuardConfig.ADAPTIVE:
        return CascadeMonitor(RulesMonitor(), llm(cfg["monitor"]))
    if config == GuardConfig.ADAPTIVE_AUDIT:
        return CascadeMonitor(CascadeMonitor(RulesMonitor(), llm(cfg["monitor"])), llm(cfg["auditor"]))
    return None


class UsageOpenAILLM(OpenAILLM):
    """OpenAILLM that counts tokens (fork drops completion.usage). One object is shared by
    orchestrator + sub-agents, so totals cover the whole run; per-task usage goes to the log."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.total = {"prompt_tokens": 0, "completion_tokens": 0, "estimated": False}
        self._lg, self.task = None, None

    def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args={}):
        # copy of OpenAILLM.query (8 lines) that keeps completion.usage
        completion = chat_completion_request(
            self.client, self.model, [_message_to_openai(x, self.model) for x in messages],
            [_function_to_openai(t) for t in runtime.functions.values()], self.reasoning_effort, self.temperature,
        )
        out = (query, runtime, env, [*messages, _openai_to_assistant_message(completion.choices[0].message)], extra_args)
        u = getattr(completion, "usage", None)
        if u is not None:
            p, c, est = u.prompt_tokens or 0, u.completion_tokens or 0, False
        else:  # ponytail: chars/4 estimate when provider omits usage
            p = sum(len(str(x.get("content"))) for x in messages) // 4
            c = len(str(out[3][-1].get("content"))) // 4
            est = True
        lg = Logger.get()
        if lg is not self._lg:  # new TraceLogger = new task
            self._lg, self.task = lg, {"prompt_tokens": 0, "completion_tokens": 0, "estimated": False}
        for d in (self.total, self.task):
            d["prompt_tokens"] += p
            d["completion_tokens"] += c
            d["estimated"] |= est
        if hasattr(lg, "set_contextarg"):
            lg.set_contextarg("usage", dict(self.task))
        return out


class GuardedMultiAgentPipeline(MultiAgentPipeline):
    def __init__(self, llm, base_system_message, make_gateway, executor_cls, **kw):
        super().__init__(llm, base_system_message, **kw)
        self.make_gateway, self.executor_cls = make_gateway, executor_cls
        self.gateway, self.root_token = None, None

    def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args={}):
        self.gateway = self.make_gateway()  # fresh per task: taint/killed/step must not leak across tasks
        # root role: orchestrator may (transitively) use every sub-agent tool of the suite
        self.root_token = self.gateway.spawn(None, "orchestrator", sorted(runtime.functions), query)[1]
        return super().query(query, runtime, env, messages, extra_args)

    def _make_subagent_tool(
        self, spec: SubAgentSpec, tools: Sequence[Function], records: list[tuple[str, list[ChatMessage]]]
    ) -> Function:
        fn = super()._make_subagent_tool(spec, tools, records)  # reuse schema/description/deps
        system_message = self._subagent_system_message(spec)

        def run_subagent(task: str, env: TaskEnvironment) -> str:
            _, token, _ = self.gateway.spawn(self.root_token, spec.name, [t.name for t in tools], task)
            executor = self.executor_cls(self.gateway, token, task, self.tool_output_formatter)
            loop = ToolsExecutionLoop([executor, self.llm], max_iters=self.max_iters)
            elements = [SystemMessage(system_message), InitQuery(), self.llm, loop]
            _, _, _, sub_messages, _ = _run_elements(elements, task, FunctionsRuntime(tools), env, [], {})
            records.append((spec.name, list(sub_messages)))
            last = sub_messages[-1] if sub_messages else None
            if last is None or last["role"] != "assistant" or last["content"] is None:
                return f"The {spec.name} finished the task without providing a final answer."
            return get_text_content_as_str(last["content"])

        return fn.model_copy(update={"run": run_subagent})


def pipeline_name(config, model_id: str) -> str:
    # '/' breaks fork resume (load_task_results doesn't sanitize); ':' -> '-' for tidy paths.
    # No MODEL_NAMES key is a substring, so attacks address "AI assistant" like the MAD baseline.
    return f"{model_id.replace('/', '-').replace(':', '-')}-{GuardConfig(config).value}-multi-agent"


def make_pipeline(config, model_id: str, provider_env: dict, monitor_cfg: dict | None = None,
                  log_path=None, run_id: str = "run", client=None, llm=None):
    """provider_env: {'OPENAI_COMPATIBLE_BASE_URL', 'OPENAI_COMPATIBLE_API_KEY'}."""
    config = GuardConfig(config)
    if llm is None:
        client = client or openai.OpenAI(
            base_url=provider_env["OPENAI_COMPATIBLE_BASE_URL"], api_key=provider_env["OPENAI_COMPATIBLE_API_KEY"]
        )
        llm = UsageOpenAILLM(client, model_id)
    sysmsg = load_system_message(None)
    if config == GuardConfig.NONE:
        mad = MultiAgentPipeline(llm, sysmsg)  # vanilla MAD baseline
    else:
        Gateway, Exec = load_gateway()
        monitor = build_monitor(config, monitor_cfg)
        if config != GuardConfig.STATIC and monitor is None:
            raise ValueError(f"{config.value} needs a monitor")
        n = itertools.count()
        mad = GuardedMultiAgentPipeline(
            llm, sysmsg, lambda: Gateway(config, f"{run_id}-{next(n)}", monitor=monitor, log_path=log_path), Exec)
    pipe = AgentPipeline([mad])
    pipe.name = pipeline_name(config, model_id)
    pipe.llm_counter = llm
    return pipe
