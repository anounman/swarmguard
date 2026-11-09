"""Append-only JSONL event log (sg.schema.Event). In-memory copy for windows.

Tamper evidence: each event carries `prev` = sha256 of the previous line of the same run, so
editing, inserting or deleting a line breaks the chain. The chain itself is unkeyed, so after every
write the gateway also signs the run's chain head with its Ed25519 identity key and appends
{run_id, head, n_events, pk, sig} to the sidecar `<log>.heads.jsonl`. `verify(path)` checks the
chain AND the last signed head of every run, so append / truncate / re-hash without the private
key is caught, and a missing sidecar or head is reported, never a silent pass.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sg.schema import Event


def _h(line: str) -> str:
    return hashlib.sha256(line.encode()).hexdigest()


def _msg(run_id: str, n: int, head: str) -> bytes:
    return f"{run_id}\n{n}\n{head}".encode()


def heads_path(path: str | Path) -> Path:
    return Path(f"{path}.heads.jsonl")


def pk_hex(pk: Ed25519PublicKey) -> str:
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


class EventLog:
    def __init__(self, path: str | None = None, key: Ed25519PrivateKey | None = None) -> None:
        self.path = Path(path) if path else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.key = key  # gateway identity key; signs the chain head (agents never see it)
        self.events: list[Event] = []
        self.head: str | None = None  # hash of the last line this gateway wrote

    def append(self, ev: Event) -> Event:
        ev.prev = self.head
        line = ev.model_dump_json()
        self.head = _h(line)
        self.events.append(ev)
        if self.path:
            with self.path.open("a") as f:
                f.write(line + "\n")
            if self.key:
                n = len(self.events)
                rec = {"run_id": ev.run_id, "head": self.head, "n_events": n, "pk": pk_hex(self.key.public_key()),
                       "sig": self.key.sign(_msg(ev.run_id, n, self.head)).hex()}
                with heads_path(self.path).open("a") as f:
                    f.write(json.dumps(rec) + "\n")
        return ev

    def window(self, agent_id: str, n: int = 8) -> list[Event]:
        return [e for e in self.events if e.agent_id == agent_id][-n:]

    @staticmethod
    def read(path: str) -> list[Event]:
        return [Event.model_validate_json(line) for line in Path(path).read_text().splitlines() if line.strip()]


def verify(path: str, heads: dict[str, str] | None = None, pubkeys: dict[str, str] | None = None,
           signed: bool = True) -> str | None:
    """First problem found, as text ("line 3: ..." / "run X: ..."), else None.

    Chain: a line with prev=None starts a new chain (one Gateway = one chain; several may share a file).
    signed=True: every run needs a validly signed head in `<path>.heads.jsonl` that matches its last
    line and its line count. `pubkeys` ({run_id: hex}) pins the gateway key out-of-band; without it the
    key recorded in the sidecar is trusted (a key-swap + full re-sign then passes).
    `heads` ({run_id: EventLog.head}) still lets a live gateway process check against its in-memory head.
    """
    lines = [x for x in Path(path).read_text().splitlines() if x.strip()]
    last: dict[str, str] = {}
    count: dict[str, int] = {}
    for i, line in enumerate(lines):
        try:
            ev = Event.model_validate_json(line)
        except ValueError:
            return f"line {i}: not a valid event"
        if ev.prev is not None and last.get(ev.run_id) != ev.prev:
            return f"line {i}: hash chain broken"
        count[ev.run_id] = 1 if ev.prev is None else count.get(ev.run_id, 0) + 1
        last[ev.run_id] = _h(line)
    for r, h in (heads or {}).items():
        if last.get(r) != h:
            return f"run {r}: head mismatch vs gateway memory"
    if not signed:
        return None
    hp = heads_path(path)
    if not hp.exists():
        return f"head missing: no {hp.name}"
    signed_heads: dict[str, dict] = {}
    for j, x in enumerate(hp.read_text().splitlines()):
        if not x.strip():
            continue
        try:
            rec = json.loads(x)
            pk = (pubkeys or {}).get(rec["run_id"], rec["pk"])
            if rec["pk"] != pk:
                return f"run {rec['run_id']}: head signed by unexpected key"
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk)).verify(
                bytes.fromhex(rec["sig"]), _msg(rec["run_id"], rec["n_events"], rec["head"]))
        except (ValueError, KeyError, TypeError, InvalidSignature):
            return f"heads line {j}: bad head signature"
        signed_heads[rec["run_id"]] = rec
    for r in last:
        rec = signed_heads.get(r)
        if rec is None:
            return f"run {r}: head missing"
        if rec["head"] != last[r] or rec["n_events"] != count[r]:
            return f"run {r}: log differs from signed head ({count[r]} lines vs {rec['n_events']} signed)"
    for r in signed_heads.keys() - last.keys():
        return f"run {r}: signed head but no lines (run deleted)"
    return None
