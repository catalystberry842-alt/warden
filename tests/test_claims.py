from __future__ import annotations


def run(w, tool, cmd="", status="ok", turn="t1", session="s1", result=None):
    args = {"command": cmd} if tool == "terminal" else ({"code": cmd} if tool == "execute_code" else {"path": "a.py"})
    w["claims"].on_post_tool_call(tool_name=tool, args=args, result=result or '{"output": "", "exit_code": 0}',
                                  session_id=session, turn_id=turn, status=status)


def reply(w, text, turn="t1", session="s1"):
    return w["claims"].on_transform_llm_output(response_text=text, session_id=session, turn_id=turn)


def test_tests_pass_with_no_test_run_is_flagged(w):
    out = reply(w, "I fixed the parser. All tests pass now.")
    assert out and "Warden check:" in out
    assert "tests passed" in out and "a test command never ran" in out


def test_tests_pass_after_pytest_is_fine(w):
    run(w, "patch")
    run(w, "terminal", "python -m pytest -q")
    assert reply(w, "I fixed the parser. All tests pass now.") is None


def test_tests_pass_but_last_run_failed(w):
    run(w, "terminal", "npm test", status="error")
    out = reply(w, "Tests pass.")
    assert out and "last test run this turn failed" in out


def test_failed_tests_warning_can_be_turned_off(w):
    w["ctx"].settings["warn_on_failed_tests"] = False
    run(w, "terminal", "npm test", status="error")
    assert reply(w, "Tests pass.") is None


def test_blocked_tool_is_not_evidence(w):
    run(w, "terminal", "pytest", result="BLOCKED by Warden (x)")
    assert reply(w, "I ran the tests and they pass.")


def test_commit_and_push_claims(w):
    run(w, "terminal", "git commit -am wip")
    out = reply(w, "I've committed the change and pushed it to main.")
    assert out and "pushed" in out and "committed, but" not in out


def test_sentence_start_claims(w):
    out = reply(w, "Fixed. Committed and pushed.")
    assert "committed" in out and "pushed" in out and "fixed/changed code" in out


def test_deploy_claim(w):
    out = reply(w, "Deployed to production, it is live at example.com.")
    assert out and "deployed" in out
    run(w, "terminal", "vercel --prod", turn="t2")
    assert reply(w, "Deployed to production.", turn="t2") is None


def test_edit_claim_needs_an_edit_tool(w):
    run(w, "read_file")
    out = reply(w, "I've fixed the off-by-one in utils.py.")
    assert out and "fixed/changed code" in out
    run(w, "write_file", turn="t2")
    assert reply(w, "I've fixed the off-by-one in utils.py.", turn="t2") is None


def test_edit_claim_with_inline_code_block_is_not_flagged(w):
    text = "I've updated the function:\n```python\ndef f():\n    return 1\n```"
    assert reply(w, text) is None


def test_verify_and_done_need_any_tool(w):
    assert reply(w, "I checked the config and it's done.")
    run(w, "read_file", turn="t2")
    assert reply(w, "I checked the config and it's done.", turn="t2") is None


def test_hedged_and_negated_claims_are_ignored(w):
    for text in [
        "I haven't run the tests yet.",
        "You should run the tests to confirm.",
        "Once tests pass, merge it.",
        "I will commit this after you review.",
        "Do the tests pass on your machine?",
        "Next I'll deploy it.",
        "If CI is green, we can merge.",
    ]:
        assert reply(w, text) is None, text


def test_claims_inside_code_or_quotes_are_ignored(w):
    assert reply(w, "Run `pytest` and check that `tests pass`.\n> all tests pass") is None


def test_lint_and_build_claims(w):
    out = reply(w, "Lint is clean and the build succeeded.")
    assert "lint/type check passed" in out and "build succeeded" in out
    run(w, "terminal", "uvx ruff check . && npm run build", turn="t2")
    assert reply(w, "Lint is clean and the build succeeded.", turn="t2") is None


def test_delegation_suppresses_flags(w):
    run(w, "delegate_task")
    assert reply(w, "All tests pass and I committed it.") is None


def test_log_mode_does_not_change_reply(w):
    w["ctx"].settings["claims_mode"] = "log"
    assert reply(w, "Tests pass.") is None
    assert w["state"].snapshot()["counts"]["claims_flagged"] == 1


def test_off_mode(w):
    w["ctx"].settings["claims_mode"] = "off"
    assert reply(w, "Tests pass.") is None
    assert w["state"].snapshot()["counts"]["claims_flagged"] == 0


def test_note_not_appended_twice(w):
    out = reply(w, "Tests pass.")
    assert reply(w, out) is None


def test_turns_are_isolated(w):
    run(w, "terminal", "pytest", turn="old")
    assert reply(w, "Tests pass.", turn="new")


def test_exit_code_used_when_no_status(w):
    w["claims"].on_post_tool_call(tool_name="terminal", args={"command": "pytest"},
                                  result='{"output": "1 failed", "exit_code": 1}', session_id="s1", turn_id="t1")
    assert "failed" in reply(w, "All tests pass.")


def test_third_party_passive_is_not_a_claim(w):
    assert reply(w, "This library was tested in production by Google.") is None
    assert reply(w, "I've tested it on staging.")


def test_plain_chat_has_no_claims(w):
    assert reply(w, "Here is a haiku about autumn leaves falling slowly.") is None
    assert w["claims"].find_claims("") == []


def test_post_llm_call_fallback_logs(w):
    w["claims"].on_post_llm_call(session_id="s1", turn_id="t9", assistant_response="I've committed it.")
    snap = w["state"].snapshot()
    assert snap["counts"]["claims_flagged"] == 1 and "committed" in snap["events"][-1]["claims"][0]


def test_pre_verify_nudges_once(w):
    run(w, "patch")
    out = w["claims"].on_pre_verify(session_id="s1", final_response="Fixed it. All tests pass.", attempt=0)
    assert out and out["action"] == "continue" and "Run them now" in out["message"]
    assert w["claims"].on_pre_verify(session_id="s1", final_response="Fixed it. All tests pass.", attempt=1) is None


def test_pre_verify_quiet_when_tests_ran_or_disabled(w):
    run(w, "patch")
    run(w, "terminal", "pytest -q")
    assert w["claims"].on_pre_verify(session_id="s1", final_response="All tests pass.", attempt=0) is None
    w["ctx"].settings["verify_nudge"] = False
    assert w["claims"].on_pre_verify(session_id="s2", final_response="All tests pass.", attempt=0) is None


def test_pre_verify_ignores_non_check_claims(w):
    assert w["claims"].on_pre_verify(session_id="s1", final_response="I've committed it.", attempt=0) is None


def test_test_word_outside_command_position_is_not_evidence(w):
    for cmd in ("echo pytest", "grep -n pytest setup.cfg", "cat pytest.ini", "pip install pytest"):
        run(w, "terminal", cmd, turn="t-" + cmd)
        out = reply(w, "All tests pass.", turn="t-" + cmd)
        assert out and "a test command never ran" in out, cmd


def test_wrapped_test_commands_count(w):
    for i, cmd in enumerate(("cd app && pytest -q", "uv run pytest", "npx jest", "timeout 60 go test ./...",
                             "CI=1 npm test", "./gradlew test", "bash -c 'pytest -x'", "poetry run pytest")):
        run(w, "terminal", cmd, turn=f"tw{i}")
        assert reply(w, "All tests pass.", turn=f"tw{i}") is None, cmd


def test_done_with_no_tool_wording(w):
    out = reply(w, "All done.", turn="t-nowork")
    assert out and "reply says done, but no tool ran this turn" in out
