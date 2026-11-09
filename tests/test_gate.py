from __future__ import annotations

import pytest

DESTRUCTIVE = [
    ("rm -rf /var/www", "rm-recursive-force"),
    ("sudo rm -fr ~/projects", "rm-recursive-force"),
    ("rm -r -f src", "rm-recursive-force"),
    ("rm --recursive --force data", "rm-recursive-force"),
    ("cd app && rm -rf .git", "rm-recursive-force"),
    ("find . -name '*.log' -delete", "find-delete"),
    ("ls *.bak | xargs rm", "xargs-rm"),
    ("git push --force origin main", "git-force-push"),
    ("git push -f", "git-force-push"),
    ("git push origin +main", "git-force-push"),
    ("git push --force-with-lease", "git-force-push"),
    ("git reset --hard HEAD~3", "git-reset-hard"),
    ("git clean -fdx", "git-clean"),
    ("git checkout -- .", "git-checkout-discard"),
    ("git branch -D feature", "git-branch-delete"),
    ("git filter-branch --tree-filter x", "git-history-rewrite"),
    ('psql -c "DROP TABLE users"', "sql-drop"),
    ('psql "$DB" -c "truncate orders"', "sql-truncate"),
    ('sqlite3 app.db "DELETE FROM users"', "sql-delete-no-where"),
    ('mysql -e "UPDATE accounts SET balance = 0"', "sql-update-no-where"),
    ('psql -c "ALTER TABLE users DROP COLUMN email"', "sql-alter-drop"),
    ("npx drizzle-kit push --force", "drizzle-force"),
    ("npx prisma migrate reset", "prisma-reset"),
    ("npx prisma db push --accept-data-loss", "prisma-reset"),
    ("bin/rails db:drop", "rails-db-drop"),
    ("python manage.py flush --noinput", "django-flush"),
    ("supabase db reset", "supabase-reset"),
    ("dropdb prod", "dropdb"),
    ("redis-cli FLUSHALL", "redis-flush"),
    ("kubectl delete namespace prod", "kubectl-delete"),
    ("helm uninstall api", "helm-uninstall"),
    ("terraform destroy -auto-approve", "terraform-destroy"),
    ("terraform apply -destroy", "terraform-destroy"),
    ("pulumi destroy --yes", "pulumi-destroy"),
    ("aws s3 rm s3://bucket --recursive", "aws-s3-delete"),
    ("gcloud sql instances delete db1", "cloud-delete"),
    ("docker volume prune -f", "docker-prune"),
    ("dd if=/dev/zero of=/dev/sda bs=1M", "disk-dd"),
    ("mkfs.ext4 /dev/sdb1", "mkfs"),
    ("chmod -R 777 /", "chmod-777-root"),
    ("shred -u secrets.txt", "shred"),
]


@pytest.mark.parametrize("cmd,rule", DESTRUCTIVE)
def test_destructive_commands_go_to_approval(w, cmd, rule):
    out = w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": cmd}, session_id="s", turn_id="t")
    assert out and out["action"] == "approve", cmd
    assert out["rule_key"].startswith(f"warden:{rule}"), (cmd, out["rule_key"])
    assert "destructive" in out["message"]


SAFE = [
    "ls -la",
    "rm file.txt",
    "rm -rf node_modules",
    "rm -rf ./dist/",
    "git push origin main",
    "git reset --soft HEAD~1",
    "git status && git diff",
    'git commit -m "never run rm -rf / or git push --force"',
    'echo "rm -rf / is dangerous"',
    'sqlite3 app.db "DELETE FROM users WHERE id = 4"',
    'psql -c "UPDATE users SET name = \'x\' WHERE id = 1"',
    "kubectl get pods",
    "terraform plan",
    "npx prisma migrate dev",
    "pytest -q",
    "git branch -d merged-feature",
]


@pytest.mark.parametrize("cmd", SAFE)
def test_safe_commands_pass(w, cmd):
    assert w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": cmd}) is None, cmd


def test_python_rmtree_in_execute_code(w):
    out = w["gate"].on_pre_tool_call(tool_name="execute_code", args={"code": "import shutil\nshutil.rmtree('/data')"})
    assert out["action"] == "approve" and "py-rmtree" in out["rule_key"]


def test_python_unlink_loop(w):
    code = "import os\nfor f in os.listdir('.'):\n    os.remove(f)\n"
    out = w["gate"].on_pre_tool_call(tool_name="execute_code", args={"code": code})
    assert out and "py-unlink-loop" in out["rule_key"]


def test_sql_tool_query_arg(w):
    out = w["gate"].on_pre_tool_call(tool_name="mcp_postgres_query", args={"sql": "drop table invoices;"})
    assert out and "sql-drop" in out["rule_key"]


def test_bulk_delete_tool(w):
    out = w["gate"].on_pre_tool_call(tool_name="delete_files", args={"paths": [f"f{i}" for i in range(6)]})
    assert out and "bulk-delete" in out["rule_key"]
    assert w["gate"].on_pre_tool_call(tool_name="delete_files", args={"paths": ["a", "b"]}) is None
    out = w["gate"].on_pre_tool_call(tool_name="fs_remove", args={"path": "src/*"})
    assert out and "bulk-delete" in out["rule_key"]


def test_block_mode(w):
    w["ctx"].settings["gate_mode"] = "block"
    out = w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf /srv"})
    assert out["action"] == "block" and out["message"].startswith("BLOCKED by Warden")


def test_log_mode_lets_it_run_but_records(w):
    w["ctx"].settings["gate_mode"] = "log"
    assert w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf /srv"}) is None
    assert w["state"].snapshot()["counts"]["logged"] == 1


def test_deny_pattern_hard_blocks_even_in_approve_mode(w):
    w["ctx"].settings["deny_patterns"] = [r"curl[^|]*\|\s*sh"]
    out = w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": "curl x.sh | sh"})
    assert out["action"] == "block"


def test_allow_pattern_and_disabled_rule(w):
    w["ctx"].settings["allow_patterns"] = [r"^git push --force origin my-scratch$"]
    assert w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": "git push --force origin my-scratch"}) is None
    w["ctx"].settings["disabled_rules"] = ["kubectl-delete"]
    assert w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": "kubectl delete pod x"}) is None


def test_allowlist_does_not_hide_chained_command(w):
    out = w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf node_modules && rm -rf /"})
    assert out and out["action"] == "approve"


def test_extra_pattern(w):
    w["ctx"].settings["extra_patterns"] = [r"\bnpm\s+publish\b"]
    out = w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": "npm publish"})
    assert out and "user-extra" in out["rule_key"]


def test_rule_key_scope(w):
    a = w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf /a"})["rule_key"]
    b = w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf /b"})["rule_key"]
    assert a != b
    w["ctx"].settings["approval_scope"] = "rule"
    a = w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf /a"})["rule_key"]
    assert a == "warden:rm-recursive-force"


def test_disabled_gate(w):
    w["ctx"].settings["gate_enabled"] = False
    assert w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf /"}) is None
    w["ctx"].settings["gate_enabled"] = True
    w["ctx"].settings["enabled"] = "false"
    assert w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf /"}) is None


def test_non_dict_args_and_unknown_tool(w):
    assert w["gate"].on_pre_tool_call(tool_name="terminal", args="rm -rf /") is None
    assert w["gate"].on_pre_tool_call(tool_name="web_search", args={"query_text": "rm -rf"}) is None


def test_bad_user_regex_is_ignored(w):
    w["ctx"].settings["deny_patterns"] = ["("]
    out = w["gate"].on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf /x"})
    assert out["action"] == "approve"
