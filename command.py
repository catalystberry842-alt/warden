"""/warden slash command: what the gate stopped and which claims were flagged."""

from __future__ import annotations

import time
from typing import Any

from . import config, state


def status_text(raw_args: str = "") -> str:
    try:
        cfg = config.settings()
        snap = state.snapshot()
        c = snap["counts"]
        lines = [
            "Warden status",
            f"  enabled: {cfg['enabled']}",
            f"  gate: {'on' if cfg['gate_enabled'] else 'off'} (mode {cfg['gate_mode']})",
            f"  claim check: {'on' if cfg['claims_enabled'] else 'off'} (mode {cfg['claims_mode']}, "
            f"verify nudge {'on' if cfg['verify_nudge'] else 'off'})",
            f"  sent for approval: {c['gated']}  hard blocked: {c['blocked']}  logged only: {c['logged']}",
            f"  unverified claims flagged: {c['claims_flagged']}  verify nudges: {c['nudges']}",
        ]
        events = snap["events"][-5:]
        if events:
            lines.append("  recent:")
        for e in reversed(events):
            ago = int(time.time() - e["ts"])
            if e["kind"] == "gate":
                lines.append(f"    {ago}s ago  {e['mode']}  {e['tool']}: {e['reason']}  `{e['snippet']}`")
            else:
                lines.append(f"    {ago}s ago  claim  " + "; ".join(e["claims"]))
        if (raw_args or "").strip().lower() in ("help", "?"):
            lines.append("  usage: /warden  (recent gate hits and flagged claims, this process only)")
        return "\n".join(lines)
    except Exception:
        return "Warden status unavailable (fail-open)."


def make_handler(ctx: Any = None):
    def handler(raw_args: str = "") -> str:
        return status_text(raw_args)

    return handler
