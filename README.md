# Warden

A Hermes Agent plugin with two guards for the two agent failures people complain about most:

1. **Destructive-command gate.** Before a tool runs, Warden reads the shell command, Python code or SQL it is about to execute. If it looks destructive (`rm -rf`, `git push --force`, `git reset --hard`, `DROP TABLE`, `DELETE` with no `WHERE`, `prisma migrate reset`, `drizzle-kit push --force`, `kubectl delete`, `terraform destroy`, `dd of=/dev/...`, `mkfs`, `chmod -R 777 /`, a delete tool on many files, and more), Warden sends it to the Hermes human approval prompt instead of letting it run.
2. **Fake "done" check.** Warden records which tools actually ran in the turn. When the final reply says "tests pass", "I committed", "pushed", "fixed", "deployed", "lint is clean", "I checked" or "done", Warden matches each claim against that record. A claim with nothing behind it gets a short note appended to the reply. After code edits, Warden can also send the agent back once to actually run the tests it claimed.

```
=== Destructive-command gate
  ls -la                             -> runs
  rm -rf node_modules                -> runs
  git push --force origin main       -> approve
  psql -c "DELETE FROM users"        -> approve
  terraform destroy                  -> approve

=== Fake-done check (only read_file ran this turn)
  I fixed the login bug and all tests pass. Committed and pushed.

  > Warden check: reply says tests passed, but a test command never ran this turn;
  > reply says fixed/changed code, but a file-editing tool never ran this turn; ...
```

## Why

Real incidents: an agent deleted a production database during a code freeze, another wiped 60+ tables, and agents routinely report "all tests pass" when no test ran. Hermes already prompts for some dangerous shell patterns. Warden adds the database, migration and cloud commands those patterns miss, looks inside `execute_code` Python and SQL tool arguments, and adds the honesty check, which Hermes has no equivalent for.

## Install

```bash
git clone https://github.com/catalystberry842-alt/warden ~/.hermes/plugins/warden
hermes plugins enable warden
```

Then restart Hermes. Type `/warden` in a chat to see what was gated and which claims were flagged.

## How it hooks into Hermes

| Hook | What Warden does |
|---|---|
| `pre_tool_call` | Scans the call. Returns `{"action": "approve", "message", "rule_key"}` so Hermes asks the human, or `{"action": "block"}` in block mode. |
| `post_tool_call` | Records tool name, command text and ok/error status for the turn (in memory). |
| `transform_llm_output` | Checks the final reply's claims and appends a `Warden check:` note when one is unsupported. |
| `post_llm_call` | Fallback: logs unsupported claims on paths where the transform did not run. |
| `pre_verify` | After code edits, if the reply claims tests, lint or a build that never ran, returns `continue` once so the agent runs them. |

## Settings

Set under `plugins.entries.warden.settings` in `config.yaml`, or in the Hermes plugin settings UI.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Master switch. |
| `gate_enabled` | `true` | Turn the destructive-command gate on or off. |
| `gate_mode` | `approve` | `approve` asks the human, `block` refuses outright, `log` only records. |
| `approval_scope` | `command` | What "always allow" covers: this exact command, or every command on the same rule. |
| `allow_patterns` | `[]` | Extra regexes that never need approval (added to the built-in cleanup list: `rm -rf node_modules`, `dist`, `build`, caches). Matched against the whole command, so anchor them. |
| `deny_patterns` | `[]` | Regexes that are always hard-blocked. |
| `extra_patterns` | `[]` | Your own regexes that also go to approval. |
| `disabled_rules` | `[]` | Built-in rule ids to switch off, e.g. `git-branch-delete`, `sql-drop`. |
| `bulk_delete_threshold` | `5` | A delete tool touching this many paths is gated. |
| `claims_enabled` | `true` | Turn the fake-done check on or off. |
| `claims_mode` | `append` | `append` adds a note to the reply, `log` only writes a warning, `off` disables. |
| `verify_nudge` | `true` | Send the agent back once to run claimed tests, lint or build. |
| `warn_on_failed_tests` | `true` | Also flag "tests pass" when the last test run this turn failed. |

Example:

```yaml
plugins:
  entries:
    warden:
      settings:
        gate_mode: approve
        deny_patterns: ['curl[^|]*\|\s*(ba)?sh']
        disabled_rules: [git-branch-delete]
```

## How the claim check decides

- Claims are matched sentence by sentence. Questions, hedges ("I haven't run the tests", "you should run the tests", "once tests pass", "I'll deploy next"), quoted lines and code are ignored.
- Each claim needs matching evidence from this turn: a test command (`pytest`, `npm test`, `go test`, `cargo test`, `gh pr checks`, ...) for test claims, `ruff`/`eslint`/`tsc`/`mypy` for lint, a build command for build, `git commit` / `git push` for those, a deploy command for deploys, an edit tool (`write_file`, `patch`, `sed -i`, ...) for "fixed", and any tool at all for "I checked" or "done".
- Tool calls Warden or another plugin blocked do not count as evidence.
- If the turn delegated work to a subagent, Warden stays quiet, since it cannot see the subagent's tools.
- An "I've updated the function" reply that shows the code inline in a code block is not flagged.

## Limits

- **YOLO / approvals off.** The `approve` action goes through the same Hermes approval gate as its own dangerous-command checks, so `--yolo` or `approvals.mode: off` lets it through. Use `gate_mode: block` or `deny_patterns` if you want a stop that YOLO cannot skip.
- **No human present.** In a non-interactive context with no approval bridge, Hermes fails closed and blocks the call. Cron follows `approvals.cron_mode`.
- **Pattern matching, not a parser.** A determined model can obfuscate a command. Warden catches the ordinary, accidental cases. SQL rules read the raw text, so `grep "drop table"` also asks for approval.
- **One transform wins.** Hermes uses the first plugin that rewrites a reply. If another plugin rewrites first, Warden falls back to logging the claim.
- **`pre_verify` only fires after code edits**, so the nudge only applies to coding turns. The appended note covers every turn.
- State lives in memory for the current process. It resets when Hermes restarts.

## Disclosure

- No network calls, no telemetry, no credentials read or stored.
- No files written. All state is in memory and bounded (500 turns, 50 recent events).
- Every hook is fail-open: if Warden itself errors, Hermes carries on as if Warden were not installed. (The approval prompt, once Warden asks for it, is Hermes' own gate and fails closed by design.)
- MIT licensed.

## Development

```bash
python -m pytest -q          # 108 tests; tests/test_hermes_live.py needs a Hermes checkout (HERMES_AGENT_ROOT)
uvx ruff check .
HERMES_AGENT_ROOT=../hermes-agent python scripts/demo.py   # offline demo, no model needed
```
