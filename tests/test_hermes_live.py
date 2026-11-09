"""Load Warden through the real Hermes plugin manager and drive its real dispatch helpers.

Skipped when no Hermes checkout is found (set HERMES_AGENT_ROOT).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _find_hermes() -> Path | None:
    env = (os.environ.get("HERMES_AGENT_ROOT") or "").strip()
    for cand in [Path(env)] if env else [Path("/workspace/hermes-agent"), ROOT.parent / "hermes-agent"]:
        if (cand / "hermes_cli").is_dir():
            return cand.resolve()
    return None


HERMES = _find_hermes()
pytestmark = pytest.mark.skipif(HERMES is None, reason="Hermes checkout missing (set HERMES_AGENT_ROOT)")


@pytest.fixture
def hermes(tmp_path, monkeypatch):
    home = tmp_path / "hermes_home"
    (home / "plugins").mkdir(parents=True)
    (home / "plugins" / "warden").symlink_to(ROOT)
    (home / "config.yaml").write_text("plugins:\n  enabled:\n    - warden\n  disabled: []\n")
    monkeypatch.setenv("HERMES_HOME", str(home))
    if str(HERMES) not in sys.path:
        sys.path.insert(0, str(HERMES))
    import hermes_cli.plugins as plugins_mod

    for attr in ("_MANAGER", "_manager", "manager", "_plugin_manager"):
        if hasattr(plugins_mod, attr):
            monkeypatch.setattr(plugins_mod, attr, None, raising=False)
    mgr = plugins_mod.get_plugin_manager()
    mgr.discover_and_load()
    yield plugins_mod, mgr


def test_hooks_registered_in_real_manager(hermes):
    _, mgr = hermes
    for name in ("pre_tool_call", "post_tool_call", "transform_llm_output", "post_llm_call", "pre_verify"):
        assert mgr.has_hook(name), name


def test_real_pre_tool_call_directive_is_approve(hermes):
    plugins_mod, _ = hermes
    action, msg = plugins_mod.get_pre_tool_call_directive("terminal", {"command": "terraform destroy"})
    assert action == "approve" and "terraform destroy" in msg
    action, _ = plugins_mod.get_pre_tool_call_directive("terminal", {"command": "ls"})
    assert action is None


def test_real_gate_fails_closed_without_a_human(hermes):
    plugins_mod, _ = hermes
    block = plugins_mod.resolve_pre_tool_block("terminal", {"command": "git push --force"})
    assert block and "BLOCKED" in block


def test_real_transform_and_pre_verify(hermes):
    plugins_mod, _ = hermes
    from hermes_cli.lifecycle import invoke_hook

    invoke_hook("post_tool_call", tool_name="read_file", args={"path": "a"}, result="{}",
                task_id="", session_id="live", tool_call_id="1", turn_id="lt", api_request_id="",
                duration_ms=1, status="ok", error_type=None, error_message=None, middleware_trace=[])
    out = [r for r in invoke_hook("transform_llm_output", response_text="All tests pass.",
                                  session_id="live", model="m", platform="cli", turn_id="lt") if r]
    assert out and "Warden check:" in out[0]
    msg = plugins_mod.get_pre_verify_continue_message(session_id="live", final_response="Tests pass.",
                                                      coding=True, attempt=0)
    assert msg and msg.startswith("Warden:")
