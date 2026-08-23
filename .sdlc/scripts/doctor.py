#!/usr/bin/env python3
# What this is: a self-contained health check for this shipshape-managed
# repository, suitable for local use and the scheduled GitHub workflow.
# Safe to edit: yes — shipshape will ask before overwriting your edits.
# managed-by: shipshape v0.2.1
"""Health check for a shipshape-managed repo (ADR 0002: stdlib only).

Emits one JSON scorecard on stdout: sections in priority order (security
first), each check PASS / WARN / FAIL with a plain-detail string, plus a
single suggested next_action. Callers translate this for people; this script
never prints prose.

The embedded kit version is compared with the version recorded in
``.sdlc/state.json``. This consumer copy cannot know the currently installed
shipshape plugin version because the plugin may not be installed here.

When ``GITHUB_ACTIONS`` is exactly ``"true"``, the ``secret guard installed``
check verifies the secret-scan workflow because a per-clone pre-commit hook is
not available on the runner. Local runs continue to check the clone's hook.

Usage:
    python3 doctor.py <repo-path>

The workflow-permissions and test-retry audits are deliberately naive text
checks. Permissions looks for a ``permissions:`` line anywhere in a workflow;
test retries looks for a short list of known action names and shell markers.
They flag common cases without claiming to parse YAML or shell.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

KIT_VERSION = "0.2.1"
PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
RETRY_ACTIONS = ("nick-fields/retry", "nick-invision/retry", "wandalen/wretry.action")
SHELL_LOOP_SCAN_LIMIT = 1000
UNUSED_SETTING_MESSAGE = (
    "Remove features.project_board; this setting has never changed what shipshape installs."
)
TEST_RETRY_NEXT_ACTION = (
    "Remove the retry and fix or quarantine the flaky test so one green run means the test passed."
)
AGENT_CONTROL_LAYER_MARKER = "# layer 3: agent control files"
AGENT_CONTROL_REVIEW_MARKERS = (
    "are security findings: report purpose and consequence.",
    'Unexplained control-file changes require at least "Needs attention first".',
)
AGENT_CONTROL_NEXT_ACTION = (
    "Re-run /shipshape-init to restore checks for agent and editor control files."
)
SCHEDULED_HEALTH_NEXT_ACTION = "Re-run /shipshape-init to restore the scheduled health check."
TIERED_REVIEW_NEXT_ACTION = "Turn off tiered review until every required check is enforced."
TIERED_REVIEW_UNVERIFIED = "could not verify that required checks guard auto-merge"
TIERED_REVIEW_REMOVE_ACTION = (
    "Remove .github/workflows/low-risk-automerge.yml before relying on tiered review being off."
)
GH_API_TIMEOUT_SECONDS = 10


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_state(repo: Path) -> dict:
    state_path = repo / ".sdlc" / "state.json"
    if state_path.is_file():
        return load_json(state_path)
    return {"kit_version": "", "files": {}}


def check(name: str, status: str, detail: str, next_action: str = "") -> dict:
    return {"name": name, "status": status, "detail": detail, "next_action": next_action}


def find_test_retry_markers(text: str, test_command: str) -> list[str]:
    lowered = text.casefold()
    markers = [action for action in RETRY_ACTIONS if action in lowered]
    if not test_command:
        return markers

    escaped_command = re.escape(test_command)
    for loop in ("until", "for"):
        if re.search(
            rf"\b{loop}\b[\s\S]{{0,{SHELL_LOOP_SCAN_LIMIT}}}?{escaped_command}"
            rf"[\s\S]{{0,{SHELL_LOOP_SCAN_LIMIT}}}?\bdone\b",
            text,
            flags=re.IGNORECASE,
        ):
            markers.append(f"{loop} loop around the configured test command")

    retry_flag = re.compile(r"--(?:retries|retry|reruns)\b", flags=re.IGNORECASE)
    for line in text.splitlines():
        if test_command.casefold() in line.casefold() and retry_flag.search(line):
            markers.append("retry flag on the configured test command")
            break
    return markers


def unused_settings_check(config: dict) -> dict:
    if "project_board" in config.get("features", {}):
        return check("unused settings", WARN, UNUSED_SETTING_MESSAGE, UNUSED_SETTING_MESSAGE)
    return check("unused settings", PASS, "no unused settings")


def test_retries_check(repo: Path, config: dict) -> dict:
    workflows_dir = repo / ".github" / "workflows"
    test_command = str(config.get("commands", {}).get("test", "")).strip()
    offenders = []
    if workflows_dir.is_dir():
        for workflow in sorted(workflows_dir.glob("*.yml")):
            text = workflow.read_text(encoding="utf-8", errors="ignore")
            if find_test_retry_markers(text, test_command):
                offenders.append(workflow.name)
    if offenders:
        return check(
            "test retries",
            WARN,
            f"possible test retry markers in: {', '.join(offenders)}",
            TEST_RETRY_NEXT_ACTION,
        )
    return check("test retries", PASS, "no test retries found")


def scheduled_health_check(repo: Path, features: dict) -> dict:
    if not features.get("scheduled_health", True):
        return check("scheduled health check", WARN, "scheduled health check is turned off")

    doctor = repo / ".sdlc" / "scripts" / "doctor.py"
    workflow = repo / ".github" / "workflows" / "shipshape-doctor.yml"
    workflow_text = (
        workflow.read_text(encoding="utf-8", errors="ignore") if workflow.is_file() else ""
    )
    if doctor.is_file() and re.search(r"(?m)^\s*schedule\s*:", workflow_text):
        return check(
            "scheduled health check",
            PASS,
            "doctor script and scheduled workflow present",
        )
    return check(
        "scheduled health check",
        FAIL,
        "doctor script or scheduled workflow is missing or incomplete",
        SCHEDULED_HEALTH_NEXT_ACTION,
    )


def run_gh_json(gh: str, repo: Path, args: list[str]) -> tuple[dict | list | None, str]:
    try:
        result = subprocess.run(
            [gh, *args],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=GH_API_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, "unavailable"
    if result.returncode != 0:
        status = "not_found" if re.search(r"\bHTTP\s+404\b", result.stderr) else "unavailable"
        return None, status
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, "unavailable"
    if not isinstance(payload, (dict, list)):
        return None, "unavailable"
    return payload, "ok"


def classic_status_contexts(payload: dict | list | None, status: str) -> set[str] | None:
    if status == "not_found":
        return set()
    if status != "ok" or not isinstance(payload, dict):
        return None
    contexts = payload.get("contexts", [])
    checks = payload.get("checks", [])
    if not isinstance(contexts, list) or not isinstance(checks, list):
        return None
    if not all(isinstance(context, str) for context in contexts):
        return None
    if not all(
        isinstance(status_check, dict) and isinstance(status_check.get("context"), str)
        for status_check in checks
    ):
        return None
    return set(contexts) | {status_check["context"] for status_check in checks}


def ruleset_status_contexts(payload: dict | list | None, status: str) -> set[str] | None:
    if status != "ok" or not isinstance(payload, list):
        return None
    contexts = set()
    for rule in payload:
        if not isinstance(rule, dict):
            return None
        if rule.get("type") != "required_status_checks":
            continue
        parameters = rule.get("parameters", {})
        if not isinstance(parameters, dict):
            return None
        checks = parameters.get("required_status_checks", [])
        if not isinstance(checks, list) or not all(
            isinstance(status_check, dict) and isinstance(status_check.get("context"), str)
            for status_check in checks
        ):
            return None
        contexts.update(status_check["context"] for status_check in checks)
    return contexts


def required_status_contexts(repo: Path, config: dict) -> set[str] | None:
    gh = shutil.which("gh")
    if not gh:
        return None

    owner_repo = str(config.get("repo", {}).get("owner_repo", "")).strip()
    if not owner_repo:
        repo_data, repo_status = run_gh_json(gh, repo, ["repo", "view", "--json", "nameWithOwner"])
        if repo_status == "ok" and isinstance(repo_data, dict):
            owner_repo = str(repo_data.get("nameWithOwner", "")).strip()
    if "/" not in owner_repo:
        return None

    branch = quote(str(config.get("default_branch", "main")), safe="")
    branch_data, branch_status = run_gh_json(
        gh, repo, ["api", f"repos/{owner_repo}/branches/{branch}"]
    )
    if branch_status != "ok" or not isinstance(branch_data, dict):
        return None
    if branch_data.get("protected") is False:
        return set()
    if branch_data.get("protected") is not True:
        return None

    protection, protection_status = run_gh_json(
        gh,
        repo,
        ["api", f"repos/{owner_repo}/branches/{branch}/protection/required_status_checks"],
    )
    rules, rules_status = run_gh_json(
        gh, repo, ["api", f"repos/{owner_repo}/rules/branches/{branch}"]
    )
    classic_contexts = classic_status_contexts(protection, protection_status)
    ruleset_contexts = ruleset_status_contexts(rules, rules_status)
    contexts = (classic_contexts or set()) | (ruleset_contexts or set())
    if "test" not in contexts and (classic_contexts is None or ruleset_contexts is None):
        return None
    return contexts


def tiered_review_gates_check(repo: Path, config: dict) -> dict:
    enabled = config.get("features", {}).get("tiered_review", False)
    workflow = repo / ".github" / "workflows" / "low-risk-automerge.yml"
    if not enabled and workflow.is_file():
        return check(
            "tiered review gates",
            FAIL,
            "tiered review is off but the auto-merge workflow is still present",
            TIERED_REVIEW_REMOVE_ACTION,
        )
    if not enabled:
        return check(
            "tiered review gates",
            PASS,
            "tiered review is off; every change needs a person",
        )

    if not workflow.is_file():
        return check(
            "tiered review gates",
            FAIL,
            "tiered review is on but the auto-merge workflow is missing",
            TIERED_REVIEW_NEXT_ACTION,
        )

    contexts = required_status_contexts(repo, config)
    if contexts is None:
        return check("tiered review gates", WARN, TIERED_REVIEW_UNVERIFIED)
    if "test" not in contexts:
        return check(
            "tiered review gates",
            FAIL,
            "the default branch does not require the `test` status check",
            TIERED_REVIEW_NEXT_ACTION,
        )
    return check(
        "tiered review gates",
        PASS,
        "`test` is required on the default branch and the auto-merge workflow is present",
    )


def agent_control_coverage_check(repo: Path, features: dict) -> dict:
    guard = repo / ".sdlc" / "hooks" / "secret-guard.sh"
    guard_text = guard.read_text(encoding="utf-8", errors="ignore") if guard.is_file() else ""
    has_guard_layer = AGENT_CONTROL_LAYER_MARKER in guard_text
    if features.get("secret_guard", True) and not has_guard_layer:
        return check(
            "agent control-file coverage",
            FAIL,
            "rendered secret guard lacks agent and editor control-file checks",
            AGENT_CONTROL_NEXT_ACTION,
        )
    if not has_guard_layer:
        return check(
            "agent control-file coverage",
            WARN,
            "secret guard is off; agent and editor control-file checks are inactive",
        )
    if not features.get("github_agents", False):
        return check(
            "agent control-file coverage",
            WARN,
            "deterministic guard layer is active; GitHub agent review is off",
        )

    reviewer = repo / ".github" / "agents" / "reviewer.md"
    reviewer_text = (
        reviewer.read_text(encoding="utf-8", errors="ignore") if reviewer.is_file() else ""
    )
    if not all(marker in reviewer_text for marker in AGENT_CONTROL_REVIEW_MARKERS):
        return check(
            "agent control-file coverage",
            FAIL,
            "GitHub reviewer lacks the agent control-file security rule",
            AGENT_CONTROL_NEXT_ACTION,
        )
    return check(
        "agent control-file coverage",
        PASS,
        "guard and GitHub reviewer cover agent and editor control files",
    )


def security_checks(repo: Path, config: dict) -> list[dict]:
    checks = []
    features = config.get("features", {})

    guard = repo / ".sdlc" / "hooks" / "secret-guard.sh"
    if not features.get("secret_guard", True):
        checks.append(check("secret guard", WARN, "turned off in .sdlc/config.json"))
    elif not guard.is_file():
        checks.append(
            check(
                "secret guard",
                FAIL,
                "the commit-time secret scanner is missing",
                "re-run /shipshape-init to restore it",
            )
        )
    else:
        checks.append(check("secret guard", PASS, "secret scanner present"))

    if guard.is_file() and os.environ.get("GITHUB_ACTIONS") == "true":
        secret_scan = repo / ".github" / "workflows" / "secret-scan.yml"
        if secret_scan.is_file():
            checks.append(
                check(
                    "secret guard installed",
                    PASS,
                    "per-clone hook not checkable in CI; pushes are covered by "
                    "the secret-scan workflow",
                )
            )
        else:
            checks.append(
                check(
                    "secret guard installed",
                    FAIL,
                    "the secret-scan workflow is missing in CI",
                    "Re-run /shipshape-init to restore the secret-scan workflow.",
                )
            )
    elif guard.is_file():
        hook = repo / ".git" / "hooks" / "pre-commit"
        if not hook.exists():
            checks.append(
                check(
                    "secret guard installed",
                    FAIL,
                    "the scanner exists but is not active for this clone",
                    "run: bash .sdlc/hooks/install.sh",
                )
            )
        else:
            checks.append(check("secret guard installed", PASS, "runs on every commit here"))

    checks.append(agent_control_coverage_check(repo, features))
    checks.append(tiered_review_gates_check(repo, config))

    codeql = repo / ".github" / "workflows" / "codeql.yml"
    if codeql.is_file():
        checks.append(check("code scanning (CodeQL)", PASS, "workflow present"))
    elif not features.get("codeql", True):
        checks.append(check("code scanning (CodeQL)", WARN, "turned off in .sdlc/config.json"))
    else:
        checks.append(
            check(
                "code scanning (CodeQL)",
                WARN,
                "no CodeQL workflow (unsupported language, or setup incomplete)",
            )
        )

    if (repo / ".github" / "dependabot.yml").is_file():
        checks.append(check("dependency watch (Dependabot)", PASS, "configured"))
    else:
        checks.append(
            check(
                "dependency watch (Dependabot)",
                WARN,
                "no dependabot.yml — vulnerable libraries won't be flagged",
            )
        )

    workflows_dir = repo / ".github" / "workflows"
    offenders = []
    if workflows_dir.is_dir():
        for workflow in sorted(workflows_dir.glob("*.yml")):
            if "permissions:" not in workflow.read_text(encoding="utf-8", errors="ignore"):
                offenders.append(workflow.name)
    if offenders:
        checks.append(
            check(
                "workflow permissions",
                WARN,
                f"workflows without an explicit permissions block: {', '.join(offenders)}",
                "add `permissions: contents: read` at the top of each",
            )
        )
    else:
        checks.append(check("workflow permissions", PASS, "all workflows declare permissions"))
    return checks


def setup_checks(repo: Path, config: dict, state: dict) -> list[dict]:
    checks = [unused_settings_check(config)]

    if (repo / ".github" / "workflows" / "ci.yml").is_file():
        checks.append(check("automated tests (CI)", PASS, "CI workflow present"))
    else:
        checks.append(check("automated tests (CI)", WARN, "no CI workflow found"))

    checks.append(test_retries_check(repo, config))
    checks.append(scheduled_health_check(repo, config.get("features", {})))

    drifted, missing = [], []
    for dest, record in state.get("files", {}).items():
        path = repo / dest
        if not path.is_file():
            missing.append(dest)
        elif sha256_text(path.read_text(encoding="utf-8")) != record["sha256"]:
            drifted.append(dest)
    if missing:
        checks.append(
            check(
                "managed files",
                WARN,
                f"shipshape-managed files were deleted: {', '.join(missing)}",
                "re-run /shipshape-init to restore them, or /shipshape-customize to drop them",
            )
        )
    elif drifted:
        checks.append(
            check(
                "managed files",
                PASS,
                f"present; edited by you (which is fine): {', '.join(drifted)}",
            )
        )
    else:
        checks.append(check("managed files", PASS, "all present and unmodified"))

    written_with = state.get("kit_version", "")
    if written_with and written_with != KIT_VERSION:
        checks.append(
            check(
                "kit version",
                WARN,
                f"set up with shipshape v{written_with}, rendered doctor is v{KIT_VERSION}",
                "re-run /shipshape-init to upgrade the managed files",
            )
        )
    else:
        checks.append(check("kit version", PASS, f"v{KIT_VERSION}"))
    return checks


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"ok": False, "error": "usage: doctor.py <repo-path>"}))
        return 2
    repo = Path(sys.argv[1]).resolve()
    config_path = repo / ".sdlc" / "config.json"
    if not config_path.is_file():
        print(
            json.dumps(
                {
                    "ok": False,
                    "set_up": False,
                    "error": "this repo has no shipshape setup yet",
                    "next_action": "run /shipshape-init",
                }
            )
        )
        return 1
    config = load_json(config_path)
    state = load_state(repo)

    sections = [
        {"name": "security", "checks": security_checks(repo, config)},
        {"name": "setup", "checks": setup_checks(repo, config, state)},
    ]
    all_checks = [item for section in sections for item in section["checks"]]
    counts = {
        status: sum(1 for item in all_checks if item["status"] == status)
        for status in (PASS, WARN, FAIL)
    }
    first_fail = next((item for item in all_checks if item["status"] == FAIL), None)
    first_warn = next((item for item in all_checks if item["status"] == WARN), None)
    if first_fail:
        next_action = first_fail["next_action"] or f"fix: {first_fail['name']}"
    elif first_warn:
        next_action = first_warn["next_action"] or f"consider: {first_warn['detail']}"
    else:
        next_action = "nothing — everything is shipshape"

    print(
        json.dumps(
            {
                "ok": counts[FAIL] == 0,
                "set_up": True,
                "counts": counts,
                "sections": sections,
                "next_action": next_action,
            },
            indent=2,
        )
    )
    return 0 if counts[FAIL] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
