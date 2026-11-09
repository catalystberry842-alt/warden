# Warden demo script (under 90 seconds)

Target: one take, about 75 seconds. Two beats, one per guard, then `/warden`.

## Setup before recording

1. Hermes with Warden enabled: `hermes plugins enable warden`, then restart.
2. Default settings (`gate_mode: approve`, `claims_mode: append`).
3. A throwaway git repo with a failing or missing test, open in the Hermes CLI or Desktop.
4. Backup plan if a live model is slow: `python scripts/demo.py` shows both guards offline in two seconds.

## Beat sheet

| Time | On screen | Say |
|---|---|---|
| 0 to 8 s | README title and the two bullets | "Agents delete databases and say tests pass when nothing ran. Warden is a Hermes plugin that stops both." |
| 8 to 30 s | Ask the agent: "clean up the repo and force push it to main". The Hermes approval prompt appears with "Warden: 'terminal' looks destructive (git force push rewrites remote history)". Press deny. | "Before any tool runs, Warden reads the command. Force push, rm -rf, DROP TABLE, DELETE without WHERE, prisma reset, terraform destroy: they all wait for a human yes." |
| 30 to 38 s | Ask: "rm -rf node_modules". It runs with no prompt. | "Routine cleanup still runs. No prompt fatigue." |
| 38 to 62 s | Ask: "fix the typo in app.py and tell me when it's done", with a model that skips testing. The reply ends with the "Warden check: reply says tests passed, but a test command never ran this turn" note. Or show the agent being sent back to run pytest by the verify nudge. | "Warden also records which tools really ran. If the reply claims tests passed, a commit or a deploy that never happened, you see it right in the reply. After code edits it sends the agent back once to actually run them." |
| 62 to 75 s | Type `/warden`: counts plus the last few gated commands and flagged claims. | "One command shows what was stopped and what was flagged. No network, no telemetry, and it fails open if it ever breaks." |

## Closing line

"Warden: ask before you destroy, and prove it before you say done."

## X post draft

> Built Warden for the @NousResearch Hermes Agent plugin hackathon.
>
> 1. Destructive commands (rm -rf, force push, DROP TABLE, terraform destroy) wait for your yes
> 2. "All tests pass" with no test run gets flagged in the reply
>
> github.com/catalystberry842-alt/warden
