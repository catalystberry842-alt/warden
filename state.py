"""In-memory per-turn state. Nothing is written to disk or sent anywhere."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any

_lock = threading.Lock()
MAX_TURNS = 500


@dataclass
class ToolRun:
    tool: str
    text: str  # command / code text, truncated
    status: str  # ok | error | unknown
    ts: float


@dataclass
class Turn:
    key: str
    session_id: str
    runs: list[ToolRun] = field(default_factory=list)
    flagged: bool = False


_turns: OrderedDict[str, Turn] = OrderedDict()
_latest_by_session: dict[str, str] = {}
_events: deque[dict[str, Any]] = deque(maxlen=50)
_counts = {"gated": 0, "blocked": 0, "logged": 0, "claims_flagged": 0, "nudges": 0}


def turn_key(session_id: str = "", turn_id: str = "", task_id: str = "") -> str:
    if turn_id:
        return f"t:{turn_id}"
    if session_id and session_id in _latest_by_session:
        return _latest_by_session[session_id]
    return f"s:{session_id or task_id or 'default'}"


def _get(key: str, session_id: str) -> Turn:
    t = _turns.get(key)
    if t is None:
        t = Turn(key=key, session_id=session_id)
        _turns[key] = t
        while len(_turns) > MAX_TURNS:
            old_key, old = _turns.popitem(last=False)
            if _latest_by_session.get(old.session_id) == old_key:
                _latest_by_session.pop(old.session_id, None)
    else:
        _turns.move_to_end(key)
    if session_id:
        _latest_by_session[session_id] = key
    return t


def record_tool(*, session_id: str, turn_id: str, task_id: str, tool: str, text: str, status: str) -> None:
    with _lock:
        key = f"t:{turn_id}" if turn_id else turn_key(session_id, "", task_id)
        _get(key, session_id).runs.append(ToolRun(tool, text[:2000], status, time.time()))


def runs_for(session_id: str = "", turn_id: str = "", task_id: str = "") -> list[ToolRun]:
    with _lock:
        t = _turns.get(turn_key(session_id, turn_id, task_id))
        return list(t.runs) if t else []


def mark_flagged(session_id: str, turn_id: str, claims: list[str], note: str) -> None:
    with _lock:
        key = turn_key(session_id, turn_id)
        _get(key, session_id).flagged = True
        _counts["claims_flagged"] += 1
        _events.append({"kind": "claim", "ts": time.time(), "session_id": session_id,
                        "turn_id": turn_id, "claims": claims, "note": note})


def note_nudge() -> None:
    with _lock:
        _counts["nudges"] += 1


def record_gate(*, session_id: str, turn_id: str, tool: str, rule_id: str, reason: str,
                snippet: str, mode: str) -> None:
    with _lock:
        _counts[{"approve": "gated", "block": "blocked"}.get(mode, "logged")] += 1
        _events.append({"kind": "gate", "ts": time.time(), "session_id": session_id,
                        "turn_id": turn_id, "tool": tool, "rule_id": rule_id,
                        "reason": reason, "snippet": snippet, "mode": mode})


def snapshot() -> dict[str, Any]:
    with _lock:
        return {"counts": dict(_counts), "events": list(_events), "turns": len(_turns)}


def reset() -> None:
    with _lock:
        _turns.clear()
        _latest_by_session.clear()
        _events.clear()
        for k in _counts:
            _counts[k] = 0
