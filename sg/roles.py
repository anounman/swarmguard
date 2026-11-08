"""Template role designer: (sub-agent spec, task text, parent) -> Role.

Reused: SubAgentSpec.tool_names from the fork's SUITE_PARTITIONS (utility first: a sub-agent
keeps every tool it was built with); Role.intersect from sg.schema for child <= parent.
"""
from __future__ import annotations

from typing import Any

from sg.labels import EMAIL, IBAN, URL, CHANNEL, SINKS, norm
from sg.schema import Role

DEFAULT_DENY = [
    r"(?i)\bignore (?:all |the )?(?:previous|prior|above) instructions\b",
    r"(?i)<\s*/?\s*INFORMATION\s*>",
    r"(?i)\bthis is an important message from\b",
]

# entity kind found in the task text -> (sink, arg) pairs it constrains
_EGRESS_BY_KIND = {
    "email": [("send_email", "recipients"), ("share_file", "email"), ("invite_user_to_slack", "user_email"),
              ("create_calendar_event", "participants"), ("add_calendar_event_participants", "participants")],
    "iban": [("send_money", "recipient"), ("schedule_transaction", "recipient"), ("update_scheduled_transaction", "recipient")],
    "url": [("post_webpage", "url")],
    "channel": [("send_channel_message", "channel")],
}


def _task_entities(task: str) -> dict[str, list[str]]:
    no_email = EMAIL.sub(" ", task)
    return {
        "email": EMAIL.findall(task),
        "iban": IBAN.findall(task),
        "url": URL.findall(no_email),
        "channel": [c.lstrip("#") for c in CHANNEL.findall(task)],
    }


def design_role(spec_name: str, tool_names: list[str], task_text: str, parent: Role | None = None,
                task_id: str = "task") -> Role:
    tools = list(dict.fromkeys(tool_names))
    sinks = [t for t in tools if t in SINKS]
    egress: dict[str, dict[str, list[str]]] = {}
    # ponytail: only constrain an arg when the task names a concrete value of that kind;
    # LLM fill of the role is off for bench (PLAN §2).
    for kind, vals in _task_entities(task_text or "").items():
        if not vals:
            continue
        for sink, arg in _EGRESS_BY_KIND[kind]:
            if sink in sinks:
                # normalised (lowercase, no scheme/www., no trailing punct); compare via egress_check
                egress.setdefault(sink, {})[arg] = sorted({norm(v) for v in vals})
    role = Role(
        task_id=task_id,
        name=spec_name,
        tools=tools,
        egress_sinks=sinks,
        egress_allow=egress,
        deny_patterns=list(DEFAULT_DENY),
        max_depth=1 if parent is None else 0,
        budget_calls=200 if parent is None else 50,
        ttl_s=3600 if parent is None else 900,
    )
    return role.intersect(parent) if parent is not None else role


def root_tools(specs) -> list[str]:
    """Orchestrator root role tools = agent-tool names + every sub-agent tool (so children fit)."""
    return [s.name for s in specs] + [t for s in specs for t in s.tool_names]


def egress_check(role: Role, tool: str, args: dict[str, Any] | None) -> str | None:
    """Role.egress_violation on normalised arg values (allow lists are stored normalised), so an
    LLM that writes 'https://www.Site.com/' or upper-cases an email is not denied."""
    rules = role.egress_allow.get(tool) or {}
    a = dict(args or {})
    for arg in rules:
        if arg in a and a[arg] is not None:
            a[arg] = [norm(x) for x in a[arg]] if isinstance(a[arg], (list, tuple)) else norm(a[arg])
    return role.egress_violation(tool, a)
