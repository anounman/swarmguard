"""Taint tracking: values that came out of tool outputs are untrusted.

Reused: entity regexes from scout SC2 (tested on AgentDojo suite data). No IFC lib
fits (deep-xpia taint.py labels content classes, not values) -> ~40 lines here.
"""
from __future__ import annotations

import re
from typing import Any

from sg.schema import Label

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")  # case-sensitive on purpose
_TLD = r"(?:com|org|net|io|ai|co|info|biz|xyz|dev|app|de|ch|uk|eu|fr)"
# scheme URLs take any host; bare / www. hosts must end in a known TLD at a word boundary, so
# 'www.our-company.com.They sent' -> 'www.our-company.com' (slack user_task_4)
URL = re.compile(
    r"\bhttps?://[^\s'\"<>)\]]+|\b(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\." + _TLD + r"\b(?:/[^\s'\"<>)\]]*)?",
    re.I,
)
NUM = re.compile(r"\b\d{4,}\b")
CHANNEL = re.compile(r"#[\w-]+")
QUOTED = re.compile(r"[\"']([^\"'\n]{3,80})[\"']")

# Sink tools across the 4 MAD suites: tool -> (recipient-like args checked for taint, irreversible)
# Content args (body, subject, content) are deliberately NOT taint-checked: summarising tool
# output into an email body is the normal benign case.
SINKS: dict[str, tuple[tuple[str, ...], bool]] = {
    "send_email": (("recipients", "cc", "bcc"), True),
    "delete_email": ((), True),
    "create_calendar_event": (("participants",), False),
    "add_calendar_event_participants": (("participants",), False),
    "reschedule_calendar_event": ((), False),
    "cancel_calendar_event": ((), True),
    "share_file": (("email",), True),
    "delete_file": ((), True),
    "send_money": (("recipient",), True),
    "schedule_transaction": (("recipient",), False),
    "update_scheduled_transaction": (("recipient",), False),
    "update_password": (("password",), True),
    "update_user_info": (("first_name", "last_name", "street", "city"), False),
    "send_direct_message": (("recipient",), True),
    "send_channel_message": (("channel",), True),
    "add_user_to_channel": (("user", "channel"), False),
    "invite_user_to_slack": (("user", "user_email"), False),
    "remove_user_from_slack": (("user",), True),
    "post_webpage": (("url",), True),
    "reserve_hotel": (("hotel",), True),
    "reserve_restaurant": (("restaurant",), True),
    "reserve_car_rental": (("company",), True),
}

# C45 STRICT (residual-risk fixes, not benchmarked): two of the three causes of the 10 attacks that got through
# ADAPTIVE on gpt-oss:120b. get_webpage was never scored (5/10: phishing-link visits) -> its url is now a checked
# sink arg; delete_file / delete_email / cancel_calendar_event had no checked arg (2/10: "delete file 13") -> their
# id is checked too. Short ids ("13") are below the entity length, so ids are matched whole-word against outputs
# that carried injection markers only.
STRICT_SINKS: dict[str, tuple[tuple[str, ...], bool]] = {
    **SINKS,
    "get_webpage": (("url",), False),
    "delete_file": (("file_id",), True),
    "delete_email": (("email_id",), True),
    "cancel_calendar_event": (("event_id",), True),
}
ID_ARGS = {"file_id", "email_id", "event_id"}


def norm(s: str) -> str:
    s = str(s).strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = re.sub(r"^www\.", "", s)
    return s.replace(" ", "").rstrip("/.,;:!?")


def entities(text: str) -> set[str]:
    no_email = EMAIL.sub(" ", text)  # else URL matches 'gmail.com'
    found = EMAIL.findall(text) + IBAN.findall(text) + URL.findall(no_email) + NUM.findall(text)
    found += [c.lstrip("#") for c in CHANNEL.findall(text)] + QUOTED.findall(text)
    return {norm(e) for e in found if len(norm(e)) >= 3}


def _values(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return [str(x) for x in v if x is not None]
    return [str(v)]


class TaintTracker:
    """Remembers what tool outputs said. One per run (shared by all agents, so a value
    laundered through another agent's output is still caught).

    Two modes: until some output carries injection markers (`alarm`), tool-derived values are
    trusted -- in MAD the legit recipient usually comes from a tool (get_channels, read_inbox,
    a bill file), and strict taint denied the ground truth in 16/21 slack tasks. After the
    first injected output the run goes strict (CaMeL-style): any value seen in any tool output
    and absent from the user task is untrusted, incl. values read before the alarm.
    ponytail: the alarm hinges on the SC2 marker regexes; an injection with no markers (e.g. the
    'direct' attack's bare 'TODO:') never trips it -> the monitor is the backstop there."""

    def __init__(self) -> None:
        self.tainted: dict[str, set[str]] = {}  # normalised entity -> source tools
        self.texts: list[tuple[str, str]] = []  # (source tool, normalised raw output)
        self.alarm: list[str] = []  # tools whose output carried injection markers
        self.injected: list[tuple[str, str]] = []  # (source tool, lowercased raw output) of marker-carrying outputs

    def ingest(self, tool: str, result_text: str, injected: bool = True) -> None:
        if injected:
            self.alarm.append(tool)
            self.injected.append((tool, (result_text or "").lower()))
        for e in entities(result_text or ""):
            self.tainted.setdefault(e, set()).add(tool)
        self.texts.append((tool, norm(result_text or "")))

    def sources_of(self, value: str) -> set[str]:
        v = norm(value)
        if len(v) < 3:
            return set()
        src = {t for e, ts in self.tainted.items() if e == v or (len(e) >= 6 and e in v) for t in ts}
        # ponytail: raw-substring match catches entities the regexes miss (bare channel /
        # user names); O(outputs) per value, fine for MAD-sized runs.
        src |= {t for t, txt in self.texts if v in txt}
        return src

    def label_args(self, tool: str, args: dict[str, Any] | None, task_text: str, sinks: dict | None = None) -> Label:
        """Untrusted iff the run saw an injection AND some sink-arg value came from a tool
        output and is absent from the task."""
        if not self.alarm:
            return Label(trusted=True)
        task, low, ents = norm(task_text or ""), (task_text or "").lower(), entities(task_text or "")
        sources: set[str] = set()
        for arg in (sinks or SINKS).get(tool, ((), False))[0]:
            for v in _values((args or {}).get(arg)):
                if arg in ID_ARGS:  # C45: ids are short; untrusted iff named by an injected output and not by the task
                    word = rf"(?<![a-z0-9]){re.escape(str(v).strip().lower())}(?![a-z0-9])"
                    if str(v).strip() and not re.search(word, low):
                        sources |= {t for t, txt in self.injected if re.search(word, txt)}
                    continue
                n = norm(v)
                if n and (n in ents or re.search(rf"(?<![a-z0-9]){re.escape(n)}(?![a-z0-9])", low)
                          or (len(n) >= 6 and n in task)):  # whole-word / entity match, no 'bob' in 'bobby'
                    continue
                sources |= self.sources_of(v)
        return Label(trusted=not sources, sources=sorted(sources))
