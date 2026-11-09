"""Warden: a destructive-command gate and a fake-'done' check for Hermes Agent.

  Gate   pre_tool_call scans shell, Python and SQL a tool is about to run (rm -rf,
         git push --force, DROP TABLE, DELETE without WHERE, terraform destroy, ...)
         and sends it to Hermes' human approval gate (or hard-blocks it).
  Claims post_tool_call records what really ran this turn; transform_llm_output
         flags replies that say "tests pass", "committed", "fixed", "deployed"...
         when nothing matching ran. pre_verify sends the agent back once to run them.

Every hook is fail-open: an internal error never blocks Hermes. No network, no disk.
"""

from __future__ import annotations

import logging
from typing import Any

from . import claims, config, gate
from .command import make_handler

logger = logging.getLogger("warden")

HOOKS = {
    "pre_tool_call": gate.on_pre_tool_call,
    "post_tool_call": claims.on_post_tool_call,
    "transform_llm_output": claims.on_transform_llm_output,
    "post_llm_call": claims.on_post_llm_call,
    "pre_verify": claims.on_pre_verify,
}


def _safe(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            logger.debug("warden: hook %s failed open: %s", getattr(fn, "__name__", fn), exc)
            return None

    wrapped.__name__ = getattr(fn, "__name__", "warden_hook")
    wrapped.__doc__ = getattr(fn, "__doc__", None)
    return wrapped


def register(ctx: Any) -> None:
    """Wire hooks and the /warden command. Never raises."""
    try:
        config.bind_ctx(ctx)
    except Exception as exc:
        logger.debug("warden: bind_ctx failed: %s", exc)
    for name, fn in HOOKS.items():
        try:
            ctx.register_hook(name, _safe(fn))
        except Exception as exc:
            logger.warning("warden: failed to register hook %s: %s", name, exc)
    try:
        ctx.register_command("warden", make_handler(ctx),
                             description="Warden: gated commands and unverified claims")
    except Exception as exc:
        logger.debug("warden: register_command failed: %s", exc)
    logger.info("warden: registered (destructive-command gate + fake-done check)")
