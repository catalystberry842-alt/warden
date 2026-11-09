"""Warden settings: defaults merged with live Hermes plugin settings. Never raises."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("warden.config")

DEFAULTS: dict[str, Any] = {
    "enabled": True,
    # Destructive-command gate
    "gate_enabled": True,
    "gate_mode": "approve",  # approve | block | log
    "approval_scope": "command",  # command | rule
    "allow_patterns": [],
    "deny_patterns": [],
    "extra_patterns": [],
    "disabled_rules": [],
    "bulk_delete_threshold": 5,
    # Fake-done check
    "claims_enabled": True,
    "claims_mode": "append",  # append | log | off
    "verify_nudge": True,
    "warn_on_failed_tests": True,
    "max_turns_tracked": 500,
}

_CHOICES = {
    "gate_mode": ("approve", "block", "log"),
    "approval_scope": ("command", "rule"),
    "claims_mode": ("append", "log", "off"),
}

_ctx: Any = None


def bind_ctx(ctx: Any) -> None:
    global _ctx
    _ctx = ctx


def _raw(key: str, default: Any) -> Any:
    if _ctx is None:
        return default
    try:
        return _ctx.get_config(key, default=default)
    except Exception:
        return default


def _coerce(key: str, value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(default, bool):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            low = value.strip().lower()
            if low in ("1", "true", "yes", "on"):
                return True
            if low in ("0", "false", "no", "off"):
                return False
        return default
    if isinstance(default, int):
        try:
            iv = int(value)
            return iv if iv > 0 else default
        except (TypeError, ValueError):
            return default
    if isinstance(default, list):
        if isinstance(value, str):
            value = [value]
        if isinstance(value, (list, tuple)):
            return [str(v) for v in value if isinstance(v, (str, int, float)) and str(v).strip()]
        return default
    if key in _CHOICES:
        low = str(value).strip().lower()
        return low if low in _CHOICES[key] else default
    return value


def settings() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, default in DEFAULTS.items():
        try:
            out[key] = _coerce(key, _raw(key, default), default)
        except Exception:
            out[key] = default
    return out
