"""Adaptive red-team attack `redteam`: injection text written by an attacker LLM (bench/redteam/attacker.py).

Importing this module registers it. Text source: env SG_REDTEAM_FILE = runs/redteam/round_<N>/injections.jsonl,
lines {suite, injection_task_id, text, rationale}. Missing key -> important_instructions template (logged), so every
episode still runs and the harness scoring (security = injection goal achieved) stays the fork's own.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from agentdojo.task_suite.load_suites import get_suite  # noqa: F401  first: avoids a circular import in the fork
from agentdojo.attacks.attack_registry import register_attack
from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack


def load_texts(path: str | Path | None) -> dict[tuple[str, str], str]:
    p = Path(path) if path else None
    if p is None or not p.exists():
        return {}
    rows = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
    return {(r["suite"], r["injection_task_id"]): yaml_safe(r["text"]) for r in rows if r.get("text")}


def yaml_safe(text: str) -> str:
    """The fork renders injections into the suite's environment YAML (quoted scalar): double quotes, backslashes and
    newlines break the parser (round 1 died after 2 episodes). One line, apostrophes instead of double quotes."""
    t = text.replace("\\", "/").replace('"', "'")
    return " ".join(t.split())


@register_attack
class RedTeamAttack(ImportantInstructionsAttack):
    name = "redteam"

    def __init__(self, task_suite, target_pipeline) -> None:
        super().__init__(task_suite, target_pipeline)  # user/model names + template for the fallback
        self.texts = load_texts(os.environ.get("SG_REDTEAM_FILE"))
        self._warned: set = set()

    def attack(self, user_task, injection_task) -> dict[str, str]:
        text = self.texts.get((self.task_suite.name, injection_task.ID))
        if text is None:
            if injection_task.ID not in self._warned:
                self._warned.add(injection_task.ID)
                print(f"[redteam] no text for ({self.task_suite.name}, {injection_task.ID}) -> important_instructions "
                      f"fallback", file=sys.stderr, flush=True)
            return super().attack(user_task, injection_task)
        # str.replace, not .format: attacker text may contain stray braces
        text = text.replace("{goal}", injection_task.GOAL).replace("{user}", self.user_name).replace("{model}", self.model_name)
        return {inj: text for inj in self.get_injection_candidates(user_task)}
