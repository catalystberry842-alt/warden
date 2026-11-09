from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _manifest():
    """Tiny reader for plugin.yaml's shape (no PyYAML in the test venv)."""
    hooks, schema, section, key = [], {}, None, None
    for line in (ROOT / "plugin.yaml").read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            section = line.split(":")[0]
            continue
        if section == "provides_hooks":
            hooks.append(line.strip().lstrip("- ").strip())
        elif section == "config_schema":
            if line.startswith("  ") and not line.startswith("    "):
                key = line.strip().rstrip(":")
                schema[key] = {}
            else:
                k, _, v = line.strip().partition(":")
                schema[key][k] = _scalar(v.strip())
    return {"provides_hooks": hooks, "config_schema": schema}


def _scalar(v):
    if v in ("true", "false"):
        return v == "true"
    if v == "[]":
        return []
    try:
        return int(v)
    except ValueError:
        return v.strip('"')


def test_register_wires_all_hooks_and_command(w):
    from conftest import FakeCtx

    ctx = FakeCtx()
    w["pkg"].register(ctx)
    manifest = _manifest()
    assert set(ctx.hooks) == set(manifest["provides_hooks"])
    assert "warden" in ctx.commands
    assert "Warden status" in ctx.commands["warden"]("")


def test_hooks_fail_open(w, monkeypatch):
    from conftest import FakeCtx

    ctx = FakeCtx()
    w["pkg"].register(ctx)

    def boom(*a, **k):
        raise RuntimeError("bad")

    monkeypatch.setattr(w["config"], "settings", boom)
    for fn in ctx.hooks.values():
        assert fn(tool_name="terminal", args={"command": "rm -rf /"}, response_text="Tests pass.") is None


def test_register_survives_broken_ctx(w):
    class Broken:
        def register_hook(self, *a, **k):
            raise RuntimeError

        def register_command(self, *a, **k):
            raise RuntimeError

    w["pkg"].register(Broken())


def test_manifest_schema_matches_defaults(w):
    manifest = _manifest()
    assert set(manifest["config_schema"]) <= set(w["config"].DEFAULTS)
    for key, spec in manifest["config_schema"].items():
        assert spec["default"] == w["config"].DEFAULTS[key], key


def test_bad_settings_fall_back(w):
    w["ctx"].settings.update({"gate_mode": "explode", "bulk_delete_threshold": "x", "enabled": "maybe"})
    cfg = w["config"].settings()
    assert cfg["gate_mode"] == "approve" and cfg["bulk_delete_threshold"] == 5 and cfg["enabled"] is True


def test_status_command_shows_events(w):
    w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": "git reset --hard"})
    w["claims"].on_transform_llm_output(response_text="Tests pass.", session_id="s", turn_id="t")
    text = w["command"].status_text("")
    assert "sent for approval: 1" in text and "unverified claims flagged: 1" in text
    assert "git reset --hard" in text


def test_state_is_bounded(w):
    st = w["state"]
    for i in range(st.MAX_TURNS + 50):
        st.record_tool(session_id=f"s{i}", turn_id=f"t{i}", task_id="", tool="x", text="", status="ok")
    assert st.snapshot()["turns"] == st.MAX_TURNS
