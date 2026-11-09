"""Offline demo (dev-only, uses private Hermes internals, so it lives under tests/): load Warden through the real Hermes plugin manager and show both guards.

Usage: HERMES_AGENT_ROOT=/path/to/hermes-agent python tests/dev/demo.py
No model, network or API key needed.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERMES = Path(os.environ.get("HERMES_AGENT_ROOT", "/workspace/hermes-agent"))

home = Path(tempfile.mkdtemp(prefix="warden-demo-"))
(home / "plugins").mkdir()
(home / "plugins" / "warden").symlink_to(ROOT)
(home / "config.yaml").write_text("plugins:\n  enabled:\n    - warden\n  disabled: []\n")
os.environ["HERMES_HOME"] = str(home)
sys.path.insert(0, str(HERMES))

from hermes_cli.lifecycle import invoke_hook  # noqa: E402
from hermes_cli.plugins import get_plugin_manager, get_pre_tool_call_directive  # noqa: E402

get_plugin_manager().discover_and_load()


def say(title: str) -> None:
    print(f"\n=== {title}")


say("1. Destructive-command gate (pre_tool_call)")
for cmd in ["ls -la", "rm -rf node_modules", "git push --force origin main",
            'psql -c "DELETE FROM users"', "npx prisma migrate reset", "terraform destroy"]:
    action, msg = get_pre_tool_call_directive("terminal", {"command": cmd})
    print(f"  {cmd:34} -> {action or 'runs'}")

say("2. Fake-done check (post_tool_call + transform_llm_output)")
invoke_hook("post_tool_call", tool_name="read_file", args={"path": "app.py"}, result="{}",
            task_id="", session_id="demo", tool_call_id="1", turn_id="turn-1", api_request_id="",
            duration_ms=3, status="ok", error_type=None, error_message=None, middleware_trace=[])
print("  tools that ran this turn: read_file")
reply = "I fixed the login bug and all tests pass. Committed and pushed."
print(f"  agent reply: {reply}")
for out in invoke_hook("transform_llm_output", response_text=reply, session_id="demo",
                       model="demo", platform="cli", turn_id="turn-1"):
    if out:
        print("  what the user sees:\n    " + out.replace("\n", "\n    "))
