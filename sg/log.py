"""Append-only JSONL event log (sg.schema.Event). In-memory copy for windows."""
from __future__ import annotations

from pathlib import Path

from sg.schema import Event


class EventLog:
    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path) if path else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.events: list[Event] = []

    def append(self, ev: Event) -> Event:
        self.events.append(ev)
        if self.path:
            with self.path.open("a") as f:
                f.write(ev.model_dump_json() + "\n")
        return ev

    def window(self, agent_id: str, n: int = 8) -> list[Event]:
        return [e for e in self.events if e.agent_id == agent_id][-n:]

    @staticmethod
    def read(path: str) -> list[Event]:
        return [Event.model_validate_json(line) for line in Path(path).read_text().splitlines() if line.strip()]
