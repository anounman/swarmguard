"""Allow-everything stand-in for sg.gateway (used until S1 lands, and by tests)."""
from __future__ import annotations

import uuid

from agentdojo.agent_pipeline.tool_execution import ToolsExecutor


class NoopGateway:
    def __init__(self, config, run_id: str, monitor=None, log_path=None):
        self.config, self.run_id, self.monitor, self.log_path = config, run_id, monitor, log_path
        self.spawns: list[tuple] = []  # (parent_token, spec_name, tool_names, task)

    def spawn(self, parent_token, spec_name, tool_names, task):
        self.spawns.append((parent_token, spec_name, list(tool_names), task))
        aid = f"{spec_name}-{uuid.uuid4().hex[:6]}"
        return aid, f"noop-token-{aid}", None


class NoopGuardedToolsExecutor(ToolsExecutor):
    def __init__(self, gateway, token, task_text, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.gateway, self.token, self.task_text = gateway, token, task_text
