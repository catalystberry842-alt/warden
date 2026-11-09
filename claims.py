"""Fake-'done' check.

post_tool_call records what actually ran this turn. When the final reply is ready, every
work claim in it ("tests pass", "I committed", "fixed", "deployed", ...) is matched against
that record. A claim with no matching tool run gets a short warning appended to the reply
(or logged, per claims_mode). pre_verify can also send the agent back once to actually run
the tests it claimed.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from . import state

logger = logging.getLogger("warden.claims")
F = re.IGNORECASE

NOTE_MARK = "Warden check:"

# Subject of a first-person claim: "I've ...", "we ...", or an elided "... and pushed".
_I = r"(?:\b(?:i|we)(?:'ve|\s+have|\s+just|\s+also|\s+now)*\s+|\b(?:and|then)\s+(?:also\s+)?)"

CLAIMS: dict[str, tuple[re.Pattern[str], ...]] = {
    "tests": tuple(re.compile(p, F) for p in (
        r"\b(?:all\s+(?:the\s+)?|the\s+)?(?:unit\s+|integration\s+|e2e\s+)?tests?\s+(?:now\s+|all\s+)?(?:pass(?:es|ed|ing)?|(?:are|is)\s+(?:all\s+)?(?:passing|green)|succeed(?:ed|s)?)\b",
        _I + r"(?:ran|run|executed)\s+(?:the\s+|all\s+(?:the\s+)?)?(?:unit\s+|integration\s+)?(?:tests?|test\s+suite|specs?)\b",
        _I + r"(?:tested|verified\s+(?:it\s+)?with\s+tests)\b",
        r"\b(?:it|this|everything|the\s+(?:fix|change|changes|code))\s+(?:is|are|has\s+been|have\s+been)\s+(?:fully\s+)?tested\b",
        r"\btest\s+suite\s+(?:is\s+)?(?:passes|passed|passing|green)\b",
        r"\bci\s+(?:is\s+)?(?:green|passes|passed|passing)\b",
    )),
    "lint": tuple(re.compile(p, F) for p in (
        r"\b(?:lint(?:ing|er)?|ruff|eslint|flake8|type-?check(?:s|ing|er)?|mypy|pyright|tsc|clippy)\s+(?:is\s+|are\s+|now\s+)*(?:clean|passes|passed|passing|green|happy)\b",
        r"\bno\s+(?:lint|type)\s+errors\b",
    )),
    "build": tuple(re.compile(p, F) for p in (
        r"\b(?:it\s+|the\s+project\s+|everything\s+)?(?:builds|compiles)\s+(?:cleanly|successfully|fine|without\s+errors)\b",
        r"\bbuild\s+(?:succeeded|succeeds|is\s+green|passes|passed|is\s+clean)\b",
    )),
    "commit": tuple(re.compile(p, F) for p in (
        _I + r"committed\b",
        r"^\s*committed\b",
        r"\b(?:changes|fix|work)\s+(?:is|are|was|were|has\s+been|have\s+been)\s+committed\b",
    )),
    "push": tuple(re.compile(p, F) for p in (
        _I + r"pushed\b",
        r"^\s*pushed\b",
        r"\b(?:changes|branch|commits?)\s+(?:is|are|was|were|has\s+been|have\s+been)\s+pushed\b",
    )),
    "deploy": tuple(re.compile(p, F) for p in (
        r"\b(?:deployed|redeployed|shipped\s+to\s+prod(?:uction)?)\b",
        r"\b(?:is|it's|now)\s+live\s+(?:at|on)\b",
    )),
    "edit": tuple(re.compile(p, F) for p in (
        _I + r"(?:fixed|patched|edited|modified|updated|changed|implemented|refactored)\b",
        r"^\s*(?:fixed|patched)\b",
        r"\b(?:bug|issue|error|problem|it)\s+(?:is|has\s+been|was|are|have\s+been)\s+(?:now\s+)?(?:fixed|patched|resolved)\b",
    )),
    "verify": tuple(re.compile(p, F) for p in (
        _I + r"(?:checked|verified|confirmed|inspected|reviewed|double-checked|looked\s+(?:at|into|through))\b",
    )),
    "done": tuple(re.compile(p, F) for p in (
        r"\b(?:all\s+done|it'?s\s+done|i'?m\s+done|task\s+(?:is\s+)?(?:complete|completed|done)|everything\s+is\s+(?:done|working))\b",
        r"^\s*done\s*[.!]*\s*$",
    )),
}

LABELS = {
    "tests": "tests passed", "lint": "lint/type check passed", "build": "build succeeded",
    "commit": "committed", "push": "pushed", "deploy": "deployed", "edit": "fixed/changed code",
    "verify": "checked/verified", "done": "done",
}

NEEDS = {
    "tests": "a test command", "lint": "a lint or type-check command", "build": "a build command",
    "commit": "a git commit", "push": "a git push", "deploy": "a deploy command",
    "edit": "a file-editing tool", "verify": "any tool", "done": "any tool",
}

_HEDGE = re.compile(
    r"\b(?:not|never|no|haven't|hasn't|didn't|don't|won't|can't|cannot|couldn't|without|unable|"
    r"yet|will|i'll|we'll|going\s+to|gonna|should|could|would|might|may|please|let\s+me|"
    r"need\s+to|needs\s+to|want\s+to|try\s+to|if|once|until|unless|you\s+(?:can|should|could|may|might|need)|"
    r"you'll|make\s+sure|to\s+be|plan\s+to|next|whether)\b|n't\b",
    F,
)

TEST_RX = re.compile(
    r"\b(?:pytest|py\.test|unittest|nose2|tox|nox|jest|vitest|mocha|ava|karma|"
    r"playwright\s+test|cypress\s+run|rspec|phpunit|minitest|go\s+test|cargo\s+(?:test|nextest)|"
    r"mvn\s+(?:\S+\s+)*(?:test|verify)|gradlew?\s+(?:\S+\s+)*(?:test|check)|dotnet\s+test|"
    r"swift\s+test|mix\s+test|deno\s+test|bun\s+test|ctest|make\s+(?:test|check)|"
    r"(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test(?::\S+)?|gh\s+(?:run\s+(?:view|watch|list)|pr\s+checks))\b",
    F,
)
LINT_RX = re.compile(
    r"\b(?:ruff|eslint|flake8|pylint|mypy|pyright|tsc|clippy|golangci-lint|rubocop|biome|"
    r"prettier\s+--check|black\s+--check|(?:npm|pnpm|yarn)\s+(?:run\s+)?(?:lint|typecheck|check))\b",
    F,
)
BUILD_RX = re.compile(
    r"\b(?:(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?build|cargo\s+build|go\s+build|make\b|cmake\s+--build|"
    r"mvn\s+(?:\S+\s+)*(?:package|install|compile)|gradlew?\s+(?:\S+\s+)*(?:build|assemble)|"
    r"dotnet\s+build|tsc|vite\s+build|next\s+build|docker\s+build|python\s+-m\s+build|uv\s+build|"
    r"xcodebuild|swift\s+build)\b",
    F,
)
COMMIT_RX = re.compile(r"\bgit\s+(?:-\S+\s+)*commit\b", F)
PUSH_RX = re.compile(r"\bgit\s+(?:-\S+\s+)*push\b|\bgh\s+pr\s+(?:create|merge)\b", F)
DEPLOY_RX = re.compile(
    r"\b(?:deploy|vercel|netlify|flyctl|fly\s+deploy|wrangler|railway\s+up|heroku|serverless|sls\s+deploy|"
    r"kubectl\s+(?:apply|rollout)|helm\s+(?:install|upgrade)|terraform\s+apply|pulumi\s+up|"
    r"docker\s+push|gcloud\s+[^\n]*deploy|firebase\s+deploy|eb\s+deploy|cdk\s+deploy)\b",
    F,
)
SHELL_EDIT_RX = re.compile(r"(?:\bsed\s+-i|\bperl\s+-[a-z]*i|\bgit\s+apply\b|\bpatch\s+-p|[^2&]>>?\s*[\w./~-]|\btee\s+)", F)
EDIT_TOOL_RX = re.compile(r"(?:write|edit|patch|replace|create_file|insert|apply_diff|str_replace|notebook)", F)
DELEGATE_RX = re.compile(r"(?:delegate|subagent|spawn_agent|task_agent)", F)


@dataclass(frozen=True)
class Claim:
    category: str
    sentence: str


def _strip_code(text: str) -> tuple[str, bool]:
    has_block = "```" in text
    text = re.sub(r"```.*?(?:```|$)", " ", text, flags=re.S)
    text = re.sub(r"`[^`\n]*`", " CODE ", text)
    text = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith(">"))
    return text, has_block


def _sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    return [p.strip() for p in parts if p and p.strip()]


def find_claims(text: str) -> list[Claim]:
    if not isinstance(text, str) or not text.strip():
        return []
    body, has_block = _strip_code(text.split(NOTE_MARK)[0])
    found: dict[str, Claim] = {}
    for sent in _sentences(body):
        if sent.endswith("?"):
            continue
        for cat, patterns in CLAIMS.items():
            if cat in found or (cat == "edit" and has_block):
                continue
            for rx in patterns:
                m = rx.search(sent)
                if not m:
                    continue
                before = re.split(r"[,;:]|\b(?:and|but|so|then)\b", sent[: m.start()], flags=F)[-1]
                # Hedges right before the claim ("I haven't tested", "you should run tests")
                # or right after ("tested? not yet") cancel it.
                if _HEDGE.search(before) or re.match(r"\s*(?:yet|later|soon|next)\b", sent[m.end():], F):
                    continue
                if re.search(r"\b(?:not|n't|never)\b", sent[m.start(): m.end()], F):
                    continue
                found[cat] = Claim(cat, sent[:160])
                break
    return list(found.values())


def _text_of(args: Any) -> str:
    if not isinstance(args, dict):
        return ""
    parts = [str(args[k]) for k in ("command", "cmd", "script", "code", "input") if isinstance(args.get(k), str)]
    return "\n".join(parts)


def _status_of(result: Any, status: Any) -> str:
    head = result[:300] if isinstance(result, str) else ""
    if "BLOCKED" in head or "requires approval" in head.lower() and "denied" in head.lower():
        return "blocked"
    if isinstance(status, str) and status:
        return status
    try:
        parsed = json.loads(result) if isinstance(result, str) else result
        if isinstance(parsed, dict):
            if parsed.get("error"):
                return "error"
            code = parsed.get("exit_code", parsed.get("returncode"))
            if isinstance(code, int):
                return "ok" if code == 0 else "error"
    except Exception:
        pass
    return "unknown"


def on_post_tool_call(tool_name=None, args=None, result=None, task_id="", session_id="",
                      turn_id="", status=None, **_: Any) -> None:
    from . import config

    cfg = config.settings()
    if not cfg["enabled"] or not cfg["claims_enabled"]:
        return None
    state.record_tool(session_id=session_id or "", turn_id=turn_id or "", task_id=task_id or "",
                      tool=str(tool_name or ""), text=_text_of(args),
                      status=_status_of(result, status))
    return None


def _matching(runs: list[state.ToolRun], pred: Callable[[state.ToolRun], bool]) -> list[state.ToolRun]:
    return [r for r in runs if r.status != "blocked" and pred(r)]


EVIDENCE: dict[str, Callable[[state.ToolRun], bool]] = {
    "tests": lambda r: bool(TEST_RX.search(r.text)) or bool(re.search(r"test", r.tool, F)),
    "lint": lambda r: bool(LINT_RX.search(r.text)) or bool(re.search(r"lint|typecheck", r.tool, F)),
    "build": lambda r: bool(BUILD_RX.search(r.text)) or bool(re.search(r"build|compile", r.tool, F)),
    "commit": lambda r: bool(COMMIT_RX.search(r.text)) or bool(re.search(r"commit", r.tool, F)),
    "push": lambda r: bool(PUSH_RX.search(r.text)) or bool(re.search(r"push|create_or_update_file|merge", r.tool, F)),
    "deploy": lambda r: bool(DEPLOY_RX.search(r.text)) or bool(re.search(r"deploy|release|publish", r.tool, F)),
    "edit": lambda r: bool(EDIT_TOOL_RX.search(r.tool)) or bool(SHELL_EDIT_RX.search(r.text))
    or r.tool in ("execute_code", "skill_manage"),
    "verify": lambda r: True,
    "done": lambda r: True,
}


def evaluate(text: str, runs: list[state.ToolRun], cfg: dict[str, Any]) -> list[str]:
    """Problems with the reply's claims, as short plain sentences. Empty means fine."""
    claims = find_claims(text)
    if not claims:
        return []
    if any(DELEGATE_RX.search(r.tool) for r in runs):
        return []  # a subagent may have done the work out of our sight
    problems: list[str] = []
    for c in claims:
        hits = _matching(runs, EVIDENCE[c.category])
        if not hits:
            problems.append(f"reply says {LABELS[c.category]}, but {NEEDS[c.category]} never ran this turn")
        elif c.category == "tests" and cfg.get("warn_on_failed_tests", True):
            last = hits[-1]
            if last.status == "error":
                problems.append("reply says tests passed, but the last test run this turn failed")
    return problems


def note_for(problems: list[str]) -> str:
    return f"\n\n> {NOTE_MARK} " + "; ".join(problems) + ". Treat those claims as unverified."


def on_transform_llm_output(response_text=None, session_id="", turn_id="", **_: Any):
    from . import config

    cfg = config.settings()
    if not cfg["enabled"] or not cfg["claims_enabled"] or cfg["claims_mode"] == "off":
        return None
    if not isinstance(response_text, str) or NOTE_MARK in response_text:
        return None
    problems = evaluate(response_text, state.runs_for(session_id or "", turn_id or ""), cfg)
    if not problems:
        return None
    note = note_for(problems)
    state.mark_flagged(session_id or "", turn_id or "", problems, note.strip())
    logger.warning("warden: unverified claims session=%s turn=%s: %s", session_id, turn_id, problems)
    if cfg["claims_mode"] == "append":
        return response_text + note
    return None


def on_post_llm_call(session_id="", turn_id="", assistant_response=None, **_: Any) -> None:
    """Fallback for paths where transform_llm_output did not see the reply: log only."""
    from . import config

    cfg = config.settings()
    if not cfg["enabled"] or not cfg["claims_enabled"] or cfg["claims_mode"] == "off":
        return None
    if not isinstance(assistant_response, str) or NOTE_MARK in assistant_response:
        return None
    runs = state.runs_for(session_id or "", turn_id or "")
    problems = evaluate(assistant_response, runs, cfg)
    if problems:
        state.mark_flagged(session_id or "", turn_id or "", problems, "(logged from post_llm_call)")
        logger.warning("warden: unverified claims (post_llm_call) session=%s: %s", session_id, problems)
    return None


_NUDGE_CATS = ("tests", "lint", "build")


def on_pre_verify(session_id="", final_response="", attempt=0, **_: Any):
    """After code edits, send the agent back once if it claims checks it never ran."""
    from . import config

    cfg = config.settings()
    if not cfg["enabled"] or not cfg["claims_enabled"] or not cfg["verify_nudge"]:
        return None
    try:
        if int(attempt or 0) > 0:
            return None
    except (TypeError, ValueError):
        return None
    runs = state.runs_for(session_id or "")
    problems = [p for p in evaluate(final_response or "", runs, cfg)
                if any(LABELS[c] in p for c in _NUDGE_CATS)]
    if not problems:
        return None
    state.note_nudge()
    return {
        "action": "continue",
        "message": (
            "Warden: your reply claims checks that did not run this turn ("
            + "; ".join(problems)
            + "). Run them now and report the real result, or say plainly that they were not run."
        ),
    }
