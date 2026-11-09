"""Load Warden as a package (the way Hermes does) and reset state between tests."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PKG = "warden_under_test"


def _load():
    if PKG in sys.modules:
        return sys.modules[PKG]
    spec = importlib.util.spec_from_file_location(
        PKG, ROOT / "__init__.py", submodule_search_locations=[str(ROOT)]
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[PKG] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class FakeCtx:
    def __init__(self, settings=None):
        self.settings = dict(settings or {})
        self.hooks: dict[str, object] = {}
        self.commands: dict[str, object] = {}

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def register_hook(self, name, fn):
        self.hooks[name] = fn

    def register_command(self, name, fn, description=""):
        self.commands[name] = fn


@pytest.fixture
def w():
    pkg = _load()
    mods = {n: importlib.import_module(f"{PKG}.{n}") for n in ("gate", "claims", "state", "config", "command")}
    mods["state"].reset()
    ctx = FakeCtx()
    mods["config"].bind_ctx(ctx)
    mods["pkg"] = pkg
    mods["ctx"] = ctx
    yield mods
    mods["config"].bind_ctx(None)
    mods["state"].reset()
