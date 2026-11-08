"""Append-only JSONL event log (sg.schema.Event). In-memory copy for windows.

Tamper evidence (added 2026-11-08): each event carries `prev` = sha256 of the previous line of
the same run, so editing, inserting or deleting a line breaks the chain; `verify(path)` finds it.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from sg.schema import Event


def _h(line: str) -> str:
    return hashlib.sha256(line.encode()).hexdigest()


class EventLog:
    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path) if path else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.events: list[Event] = []
        self.head: str | None = None  # hash of the last line this gateway wrote (keep it outside agent reach)

    def append(self, ev: Event) -> Event:
        ev.prev = self.head
        line = ev.model_dump_json()
        self.head = _h(line)
        self.events.append(ev)
        if self.path:
            with self.path.open("a") as f:
                f.write(line + "\n")
        return ev

    def window(self, agent_id: str, n: int = 8) -> list[Event]:
        return [e for e in self.events if e.agent_id == agent_id][-n:]

    @staticmethod
    def read(path: str) -> list[Event]:
        return [Event.model_validate_json(line) for line in Path(path).read_text().splitlines() if line.strip()]


def verify(path: str, heads: dict[str, str] | None = None) -> int | None:
    """Index of the first line that breaks its run's hash chain, else None. A line with prev=None
    starts a new chain (one Gateway = one chain; several may share a file).
    ponytail: the chain alone cannot see a truncated tail; pass `heads` ({run_id: EventLog.head})
    kept by the gateway process to catch that (len(lines) is returned)."""
    lines = [x for x in Path(path).read_text().splitlines() if x.strip()]
    last: dict[str, str] = {}
    for i, line in enumerate(lines):
        try:
            ev = Event.model_validate_json(line)
        except ValueError:
            return i
        if ev.prev is not None and last.get(ev.run_id) != ev.prev:
            return i
        last[ev.run_id] = _h(line)
    if heads and any(last.get(r) != h for r, h in heads.items()):
        return len(lines)
    return None
