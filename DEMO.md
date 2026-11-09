# Warden demo script (under 90 seconds)

Target: one take, about 78 seconds (under 90). Two beats, one per guard, then `/warden`.

## Setup before recording

1. Hermes with Warden enabled: `hermes plugins enable warden`, then restart.
2. Default settings (`gate_mode: approve`, `claims_mode: append`).
3. A throwaway git repo with a failing or missing test, open in the Hermes CLI or Desktop.
4. Backup plan if a live model is slow: `python tests/dev/demo.py` shows both guards offline in two seconds.

## Beat sheet

Lead with what only Warden catches. Hermes core already prompts for the classic `rm -rf` / `DROP` / disk-format patterns, so the video spends its time on force pushes, ORM resets, infra teardown and the fake-done note.

| Time | On screen | Say |
|---|---|---|
| 0 to 8 s | README title and the two bullets | "Agents wipe prod and say tests pass when nothing ran. Warden is a Hermes plugin that stops both." |
| 8 to 24 s | Ask the agent: "squash everything and force push it to main". The Hermes approval prompt appears with "Warden: 'terminal' looks destructive (git force push rewrites remote history)". Press deny. | "Before any tool runs, Warden reads the command. A force push waits for a human yes." |
| 24 to 38 s | Ask: "reset the dev database with prisma", then "tear down the staging stack". Two prompts: `prisma migrate reset`, then `terraform destroy`. Deny both. | "Migration resets and infra teardown, even wrapped in `bash -c` or `subprocess`, all stop at the prompt." |
| 38 to 44 s | Ask: "rm -rf node_modules". It runs with no prompt. | "Routine cleanup still runs. No prompt fatigue." |
| 44 to 68 s | Ask: "fix the typo in app.py and tell me when it's done", with a model that skips testing. The reply ends with "Warden check: reply says tests passed, but a test command never ran this turn". Or show the agent being sent back to run pytest by the verify nudge. | "Warden records which tools really ran. If the reply claims tests passed, a commit or a deploy that never happened, you see it right in the reply. After code edits it sends the agent back once to actually run them." |
| 68 to 78 s | Type `/warden`: counts plus the last few gated commands and flagged claims. | "One command shows what was stopped and what was flagged. No network, no telemetry, and it fails open if it ever breaks." |

## Closing line

"Warden: ask before you destroy, and prove it before you say done."

## X post draft

Draft only. Not posted.

> Built Warden for the @NousResearch Hermes Agent plugin hackathon.
>
> 1. Force pushes, prisma migrate reset, terraform destroy and other wipe-outs wait for your yes, even inside bash -c or subprocess
> 2. "All tests pass" with no test run gets flagged right in the reply
>
> github.com/catalystberry842-alt/warden
