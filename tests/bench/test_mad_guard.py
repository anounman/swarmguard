import json
from pathlib import Path

import pytest
import yaml
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.attacks.base_attacks import get_model_name_from_pipeline
from agentdojo.functions_runtime import EmptyEnv, Function, FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import ChatAssistantMessage, text_content_block_from_string

from bench.mad_guard import GuardedMultiAgentPipeline, load_gateway, make_pipeline, pipeline_name
from bench.noop_gateway import NoopGateway, NoopGuardedToolsExecutor
from bench.run import CONFIGS, MODELS
from sg.schema import GuardConfig

CFG_DIR = Path(__file__).resolve().parents[2] / "bench/configs"
ENV = {"OPENAI_COMPATIBLE_BASE_URL": "http://127.0.0.1:9/v1", "OPENAI_COMPATIBLE_API_KEY": "x"}


class FakeLLM(BasePipelineElement):
    """Orchestrator: delegate once to email_agent. Sub-agent: one get_unread_emails call. Then answer."""

    def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args={}):
        names = set(runtime.functions)
        called = any(m["role"] == "tool" for m in messages)
        if called:
            msg = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string("done")], tool_calls=[])
        else:
            fc = (FunctionCall(function="email_agent", args={"task": "read unread emails"}, id="c1")
                  if "email_agent" in names else FunctionCall(function="get_unread_emails", args={}, id="c2"))
            msg = ChatAssistantMessage(role="assistant", content=None, tool_calls=[fc])
        return query, runtime, env, [*messages, msg], extra_args


@pytest.mark.parametrize("cfg", CONFIGS)
@pytest.mark.parametrize("model", MODELS)
def test_builds_every_config(cfg, model, monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "x")
    monkeypatch.setenv("OLLAMA_API_KEY1", "x")
    pipe = make_pipeline(cfg, model, ENV, yaml.safe_load((CFG_DIR / f"{cfg}.yaml").read_text()))
    assert pipe.name == pipeline_name(cfg, model) and "/" not in pipe.name
    assert get_model_name_from_pipeline(pipe) == "AI assistant"  # same attack text as MAD baseline
    assert isinstance(pipe.elements[0], GuardedMultiAgentPipeline) == (cfg != "NONE")


def test_subagent_tool_is_function_and_guarded_executor_runs():
    seen = []

    class SpyExec(NoopGuardedToolsExecutor):
        def query(self, *a, **k):
            seen.append((self.token, self.task_text))
            return super().query(*a, **k)

    suite = get_suite("v1.2.2", "workspace")
    gw = NoopGateway(GuardConfig.STATIC, "t")
    mad = GuardedMultiAgentPipeline(FakeLLM(), "sys", lambda: gw, SpyExec)
    spec = next(s for s in mad.partitions["workspace"] if s.name == "email_agent")
    runtime = FunctionsRuntime(suite.tools)
    assert isinstance(mad._make_subagent_tool(spec, [runtime.functions[n] for n in spec.tool_names], []), Function)

    env = suite.load_and_inject_default_environment({})
    _, _, _, msgs, _ = mad.query("check my email", runtime, env)
    assert [s[1] for s in gw.spawns] == ["orchestrator", "email_agent"]
    assert gw.spawns[0][0] is None and gw.spawns[1][0] == mad.root_token  # child spawned under root token
    assert gw.spawns[1][3] == "read unread emails" and gw.spawns[0][3] == "check my email"
    assert seen and seen[0][1] == "read unread emails"  # GuardedToolsExecutor in the sub-agent chain
    trace = [tc.function for m in msgs if m["role"] == "assistant" for tc in (m["tool_calls"] or [])]
    assert trace == ["email_agent", "get_unread_emails"]  # sub-agent calls flattened into the trace


def test_real_gateway_is_default(monkeypatch):
    monkeypatch.delenv("SG_ALLOW_NOOP", raising=False)
    from sg.gateway import Gateway
    from sg.guard import GuardedToolsExecutor
    assert load_gateway() == (Gateway, GuardedToolsExecutor)


def test_real_gateway_checks_delegated_calls_fresh_per_task(tmp_path):
    suite = get_suite("v1.2.2", "workspace")
    log = tmp_path / "events.jsonl"
    pipe = make_pipeline("ADAPTIVE_RULES", "gpt-oss:20b", ENV, None, log_path=log, run_id="t", llm=FakeLLM())
    mad = pipe.elements[0]
    runtime = FunctionsRuntime(suite.tools)
    gws = []
    for _ in range(2):
        mad.query("check my email", runtime, suite.load_and_inject_default_environment({}))
        gws.append(mad.gateway)
    assert gws[0] is not gws[1] and gws[0].run_id != gws[1].run_id  # no taint/step carry-over
    assert gws[0].monitor is not None
    evs = [json.loads(x) for x in log.read_text().splitlines()]
    calls = [e for e in evs if e["kind"] in ("tool_call", "deny", "TOOL_CALL", "DENY") and e["tool"] == "get_unread_emails"]
    assert len(calls) == 2  # gateway.check() reached once per task
