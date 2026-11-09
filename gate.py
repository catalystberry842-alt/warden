"""Destructive-command gate.

Scans the text a tool is about to execute (shell commands, Python code, SQL) and any
file-delete tool call, and returns a Hermes pre_tool_call directive:

  {"action": "approve", "message", "rule_key"}  -> Hermes asks the human (default)
  {"action": "block", "message"}                -> hard veto, message becomes the tool result
  None                                           -> let it run
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Any

from . import state

logger = logging.getLogger("warden.gate")

F = re.IGNORECASE


@dataclass(frozen=True)
class Rule:
    rule_id: str
    pattern: re.Pattern[str]
    reason: str
    sql: bool = False  # SQL rules run on the raw text (SQL usually sits inside quotes)


def _r(rule_id: str, pattern: str, reason: str, *, sql: bool = False, flags: int = F) -> Rule:
    return Rule(rule_id, re.compile(pattern, flags), reason, sql)


# Command position: start of text, or after ; & | ( ` $( newline, optionally behind sudo/env.
_CMD = r"(?:^|[;&|(`\n]|\$\()\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\S+=\S*\s+)*)?(?:\S+=\S*\s+)*"

RULES: tuple[Rule, ...] = (
    # Filesystem
    _r("rm-recursive-force",
       _CMD + r"rm\s+(?:[^;&|\n]*\s)?(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|(?:-r|-R|--recursive)\s+(?:[^;&|\n]*\s)?(?:-f|--force)|(?:-f|--force)\s+(?:[^;&|\n]*\s)?(?:-r|-R|--recursive))\b",
       "recursive force delete (rm -rf)"),
    _r("find-delete", _CMD + r"find\s[^;&|\n]*(?:-delete\b|-exec\s+rm\b)", "find with -delete / -exec rm"),
    _r("xargs-rm", r"\|\s*xargs\s+(?:-\S+\s+)*rm\b", "piping a file list into rm"),
    _r("shred", _CMD + r"(?:shred|wipefs)\b", "shred / wipefs destroys data"),
    _r("disk-dd", _CMD + r"dd\s[^;&|\n]*\bof=/dev/", "dd writing to a raw device"),
    _r("mkfs", _CMD + r"mkfs(?:\.\w+)?\b", "formatting a filesystem (mkfs)"),
    _r("chmod-777-root", _CMD + r"chmod\s+(?:-\S+\s+)*-R\s+(?:-\S+\s+)*0?777\s+/(?:\s|$)|" + _CMD + r"chmod\s+(?:-\S+\s+)*0?777\s+-R\s+/(?:\s|$)",
       "chmod -R 777 on /"),
    _r("chown-root", _CMD + r"chown\s+(?:-\S+\s+)*-R\s+\S+\s+/(?:\s|$)", "recursive chown on /"),
    # Git
    _r("git-force-push", _CMD + r"git\s+(?:-\S+\s+)*push\b[^;&|\n]*(?:\s--force(?:-with-lease)?\b|\s-f\b|\s\+\S+)", "git force push rewrites remote history"),
    _r("git-reset-hard", _CMD + r"git\s+(?:-\S+\s+)*reset\b[^;&|\n]*\s--hard\b", "git reset --hard discards local work"),
    _r("git-clean", _CMD + r"git\s+(?:-\S+\s+)*clean\b[^;&|\n]*\s-[a-z]*f", "git clean -f deletes untracked files"),
    _r("git-checkout-discard", _CMD + r"git\s+(?:checkout|restore)\s+(?:--\s+)?\.(?:\s|$)", "git checkout/restore . discards all edits"),
    _r("git-branch-delete", _CMD + r"git\s+branch\s+(?:-\S+\s+)*-D\b", "force-deleting a git branch", flags=0),
    _r("git-history-rewrite", _CMD + r"git\s+(?:filter-branch|filter-repo)\b", "rewriting git history"),
    # SQL (raw text, so quoted psql -c "..." still counts)
    _r("sql-drop", r"\bdrop\s+(?:table|database|schema|view|index)\b", "SQL DROP", sql=True),
    _r("sql-truncate", r"\btruncate\s+(?:table\s+)?[\w\".`]+", "SQL TRUNCATE", sql=True),
    _r("sql-alter-drop", r"\balter\s+table\s+[\w\".`]+\s+drop\b", "SQL ALTER TABLE ... DROP", sql=True),
    # Migrations / ORMs
    _r("drizzle-force", r"\bdrizzle-kit\s+(?:push\b[^;&|\n]*--force|drop\b)", "drizzle-kit push --force / drop can lose data"),
    _r("prisma-reset", r"\bprisma\s+(?:migrate\s+reset|db\s+push\b[^;&|\n]*(?:--force-reset|--accept-data-loss))", "prisma reset / data-loss push"),
    _r("rails-db-drop", r"\brails\s+db:(?:drop|reset|schema:load)\b|\brake\s+db:(?:drop|reset)\b", "rails db drop/reset"),
    _r("django-flush", r"\bmanage\.py\s+(?:flush|reset_db)\b", "django flush wipes the database"),
    _r("supabase-reset", r"\bsupabase\s+db\s+reset\b", "supabase db reset"),
    _r("dropdb", _CMD + r"(?:dropdb|dropuser)\b", "dropdb / dropuser"),
    _r("redis-flush", r"\bflush(?:all|db)\b", "redis FLUSHALL / FLUSHDB"),
    _r("mongo-drop", r"\.(?:dropDatabase|drop)\(\s*\)|\.deleteMany\(\s*\{\s*\}\s*\)", "MongoDB drop / deleteMany({})", sql=True, flags=0),
    # Infra / cloud
    _r("kubectl-delete", r"\bkubectl\s+(?:-\S+\s+)*delete\b", "kubectl delete"),
    _r("helm-uninstall", r"\bhelm\s+(?:uninstall|delete)\b", "helm uninstall"),
    _r("terraform-destroy", r"\b(?:terraform|tofu)\s+(?:destroy\b|apply\b[^;&|\n]*-destroy\b)", "terraform destroy"),
    _r("pulumi-destroy", r"\bpulumi\s+destroy\b", "pulumi destroy"),
    _r("aws-s3-delete", r"\baws\s+s3\s+(?:rm\b[^;&|\n]*--recursive|rb\b)|\baws\s+s3api\s+delete-bucket\b", "deleting S3 data"),
    _r("cloud-delete", r"\b(?:gcloud|az)\s+[^;&|\n]*\bdelete\b", "cloud resource delete"),
    _r("docker-prune", r"\bdocker\s+(?:system\s+prune\b[^;&|\n]*-a|volume\s+(?:rm|prune)\b)", "docker volume / system prune"),
)

_SQL_DELETE = re.compile(r"\bdelete\s+from\s+[\w\".`]+(?P<rest>[^;]*)", F)
_SQL_UPDATE = re.compile(r"\bupdate\s+[\w\".`]+\s+set\b(?P<rest>[^;]*)", F)
_WHERE = re.compile(r"\bwhere\b", F)

# Python code that deletes trees or many files.
_PY_RULES: tuple[Rule, ...] = (
    _r("py-rmtree", r"\bshutil\.rmtree\s*\(", "shutil.rmtree deletes a directory tree"),
    _r("py-unlink-loop", r"\bfor\b[^\n]*:\s*\n?[^\n]*(?:os\.remove|os\.unlink|\.unlink\()", "deleting files in a loop"),
)

# Strip quoted data that is prose, not a command: commit messages and echo/printf args.
_PROSE = re.compile(
    r"""(?:(?:-m|--message)\s*=?\s*|\b(?:echo|printf)\s+)(?:"(?:[^"\\]|\\.)*"|'[^']*')""",
    F,
)

# Routine cleanup that never needs a prompt. User allow_patterns are added on top.
BUILTIN_ALLOW = (
    r"^\s*rm\s+-(?:rf|fr|r)\s+(?:\./)?(?:node_modules|dist|build|out|\.next|\.turbo|\.cache|__pycache__|"
    r"\.pytest_cache|\.ruff_cache|\.mypy_cache|coverage|target|tmp)/?\s*$",
)

_TEXT_KEYS = ("command", "cmd", "script", "code", "sql", "query", "statement", "input")
_DELETE_TOOL = re.compile(r"(?:^|[_\-.])(?:delete|remove|rm|unlink|trash|purge|destroy|drop)(?:$|[_\-.])", F)
_PATH_KEYS = ("paths", "files", "file_paths", "targets", "path", "file", "file_path", "target")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    reason: str
    snippet: str


def _texts(tool_name: str, args: dict[str, Any]) -> list[tuple[str, str]]:
    """(kind, text) pairs to scan. kind is 'shell', 'python' or 'sql'."""
    out: list[tuple[str, str]] = []
    lname = tool_name.lower()
    for key in _TEXT_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            if key in ("sql", "query", "statement"):
                kind = "sql"
            elif key == "code" or lname in ("execute_code", "python", "run_python"):
                kind = "python"
            else:
                kind = "shell"
            out.append((kind, val))
    return out


def _snip(text: str, m: re.Match[str] | None) -> str:
    if m is None:
        return text.strip()[:120]
    start = max(0, m.start() - 10)
    return text[start : m.end() + 30].strip().replace("\n", " ")[:120]


def _sql_unscoped(text: str) -> Finding | None:
    for rx, rid, why in ((_SQL_DELETE, "sql-delete-no-where", "SQL DELETE without WHERE"),
                         (_SQL_UPDATE, "sql-update-no-where", "SQL UPDATE without WHERE")):
        for m in rx.finditer(text):
            if not _WHERE.search(m.group("rest")):
                return Finding(rid, why, _snip(text, m))
    return None


def _scan_text(kind: str, text: str, disabled: set[str]) -> Finding | None:
    shell_view = _PROSE.sub('""', text)
    for rule in RULES:
        if rule.rule_id in disabled:
            continue
        target = text if rule.sql else shell_view
        m = rule.pattern.search(target)
        if m:
            return Finding(rule.rule_id, rule.reason, _snip(target, m))
    if not {"sql-delete-no-where", "sql-update-no-where"} <= disabled:
        f = _sql_unscoped(text)
        if f and f.rule_id not in disabled:
            return f
    if kind == "python":
        for rule in _PY_RULES:
            if rule.rule_id in disabled:
                continue
            m = rule.pattern.search(text)
            if m:
                return Finding(rule.rule_id, rule.reason, _snip(text, m))
    return None


def _bulk_delete(tool_name: str, args: dict[str, Any], threshold: int) -> Finding | None:
    if not _DELETE_TOOL.search(tool_name):
        return None
    count = 0
    for key in _PATH_KEYS:
        val = args.get(key)
        if isinstance(val, (list, tuple)):
            count += len(val)
        elif isinstance(val, str) and val.strip():
            count += 1
            if any(ch in val for ch in "*?") or val.strip() in ("/", "~", ".", ".."):
                return Finding("bulk-delete", f"{tool_name} on a wildcard or root path", val[:120])
    recursive = any(bool(args.get(k)) for k in ("recursive", "force", "all"))
    if count >= threshold:
        return Finding("bulk-delete", f"{tool_name} on {count} paths", f"{count} paths")
    if recursive and count:
        return Finding("bulk-delete", f"{tool_name} with recursive/force", str(args)[:120])
    return None


def _compile_user(patterns: list[str]) -> list[re.Pattern[str]]:
    out = []
    for p in patterns:
        try:
            out.append(re.compile(p, F | re.MULTILINE))
        except re.error as exc:
            logger.warning("warden: ignoring bad pattern %r: %s", p, exc)
    return out


def inspect(tool_name: str, args: Any, cfg: dict[str, Any]) -> tuple[str, Finding] | None:
    """Return ('deny'|'gate', finding) or None. Pure apart from logging."""
    name = str(tool_name or "")
    if not isinstance(args, dict):
        return None
    texts = _texts(name, args)
    for pat in _compile_user(cfg.get("deny_patterns") or []):
        for _, text in texts:
            m = pat.search(text)
            if m:
                return "deny", Finding("user-deny", f"matches deny pattern {pat.pattern!r}", _snip(text, m))
    allow = _compile_user(list(BUILTIN_ALLOW) + list(cfg.get("allow_patterns") or []))
    disabled = set(cfg.get("disabled_rules") or [])
    for kind, text in texts:
        if any(p.search(text) for p in allow):
            continue
        f = _scan_text(kind, text, disabled)
        if f:
            return "gate", f
        for pat in _compile_user(cfg.get("extra_patterns") or []):
            m = pat.search(text)
            if m:
                return "gate", Finding("user-extra", f"matches extra pattern {pat.pattern!r}", _snip(text, m))
    if "bulk-delete" not in disabled:
        f = _bulk_delete(name, args, int(cfg.get("bulk_delete_threshold") or 5))
        if f:
            return "gate", f
    return None


def _command_hash(tool_name: str, args: dict[str, Any]) -> str:
    raw = tool_name + "\x00" + "\x00".join(t for _, t in _texts(tool_name, args))
    if not _texts(tool_name, args):
        raw += repr(sorted((k, repr(v)) for k, v in args.items()))
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:12]


def on_pre_tool_call(tool_name=None, args=None, task_id="", session_id="", turn_id="", **_: Any):
    from . import config

    cfg = config.settings()
    if not cfg["enabled"] or not cfg["gate_enabled"]:
        return None
    hit = inspect(str(tool_name or ""), args, cfg)
    if hit is None:
        return None
    verdict, f = hit
    mode = "block" if verdict == "deny" else cfg["gate_mode"]
    msg = (
        f"Warden: '{tool_name}' looks destructive ({f.reason}): `{f.snippet}`. "
        "It needs a human yes before it runs."
    )
    state.record_gate(session_id=session_id or "", turn_id=turn_id or "", tool=str(tool_name),
                      rule_id=f.rule_id, reason=f.reason, snippet=f.snippet, mode=mode)
    logger.warning("warden: %s %s rule=%s snippet=%r", mode, tool_name, f.rule_id, f.snippet)
    if mode == "log":
        return None
    if mode == "block":
        return {"action": "block",
                "message": f"BLOCKED by Warden ({f.reason}): `{f.snippet}`. "
                           "Ask the user to run it themselves or change Warden's settings."}
    scope = f"warden:{f.rule_id}"
    if cfg["approval_scope"] == "command":
        scope += ":" + _command_hash(str(tool_name), args)
    return {"action": "approve", "message": msg, "rule_key": scope}
