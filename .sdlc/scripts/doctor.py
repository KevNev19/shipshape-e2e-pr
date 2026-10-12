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
check reports whether the secret-scan workflow is configured and leaves the
unavailable local-hook state as WARN. Local runs inspect Git's active hook path.

Usage:
    python3 doctor.py <repo-path>

The workflow-permissions and test-retry audits are deliberately naive text
checks. The pre-commit audit recognizes a conservative YAML subset and never
executes an installed hook. These checks report inspected wiring without
claiming that a workflow, scanner, or arbitrary dispatcher ran successfully.
"""

import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

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
AGENT_CONTROL_LAYER_MARKERS = (
    "# layer 3: agent control files",
    "# Layer 3: automation and policy control files.",
)
AGENT_CONTROL_REVIEW_MARKERS = (
    "are security findings: report purpose and consequence.",
    'Unexplained control-file changes require at least "Needs attention first".',
)
AGENT_CONTROL_NEXT_ACTION = (
    "Re-run /shipshape-init to restore checks for agent and editor control files."
)
SCHEDULED_HEALTH_NEXT_ACTION = "Re-run /shipshape-init to restore the scheduled health check."
TIERED_REVIEW_NEXT_ACTION = "Turn off tiered review until every required check is enforced."
PROTECTION_UNVERIFIED = "configured remote protection is unverified"
PROTECTION_NEXT_ACTION = (
    "Use /shipshape-access to verify or repair the requested remote branch protection."
)
TIERED_REVIEW_REMOVE_ACTION = (
    "Remove .github/workflows/low-risk-automerge.yml before relying on tiered review being off."
)
PROTECTION_WORKFLOW_PATHS = (
    ".github/workflows/ci.yml",
    ".github/workflows/secret-scan.yml",
    ".github/workflows/codeql.yml",
)
LOW_RISK_AUTOMERGE_PATH = ".github/workflows/low-risk-automerge.yml"
GH_API_TIMEOUT_SECONDS = 10
HOOK_INSTALL_ACTION = "run: bash .sdlc/hooks/install.sh"
CI_GUARD_DETAIL = (
    "secret-scan workflow is configured; local hook was not verified in GitHub Actions"
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_state(repo: Path) -> dict:
    state_path = repo / ".sdlc" / "state.json"
    if state_path.is_file():
        return load_json(state_path)
    return {"kit_version": "", "files": {}}


def check(name: str, status: str, detail: str, next_action: str = "") -> dict:
    return {"name": name, "status": status, "detail": detail, "next_action": next_action}


def managed_file_findings(repo: Path, destination: str, record: object) -> set[str]:
    """Inspect one managed path without following symlinks or decoding bytes."""
    relative = Path(destination)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in ("", ".", "..") for part in relative.parts)
    ):
        return {"unverified"}

    current = repo
    try:
        for index, part in enumerate(relative.parts):
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                return {"missing"}
            if stat.S_ISLNK(info.st_mode):
                return {"unverified"}
            if index < len(relative.parts) - 1 and not stat.S_ISDIR(info.st_mode):
                return {"unverified"}
        if not stat.S_ISREG(info.st_mode):
            return {"unverified"}
        content = current.read_bytes()
    except OSError:
        return {"unverified"}

    if not isinstance(record, dict) or not isinstance(record.get("sha256"), str):
        return {"unverified"}
    findings = set()
    if hashlib.sha256(content).hexdigest() != record["sha256"]:
        findings.add("bytes")
    recorded_mode = record.get("mode")
    if recorded_mode is None:
        findings.add("legacy-mode")
    elif not isinstance(recorded_mode, str) or re.fullmatch(r"0[0-7]{3}", recorded_mode) is None:
        findings.add("unverified")
    elif f"{stat.S_IMODE(info.st_mode):04o}" != recorded_mode:
        findings.add("mode")
    return findings


def kit_version_check(config: dict, state: dict, current: str, current_label: str) -> dict:
    config_version = config.get("kit_version", "")
    completed_version = state.get("completed_kit_version", state.get("kit_version", ""))
    if config_version == current and completed_version == current:
        return check("kit version", PASS, f"v{current}")

    details = []
    if config_version != current:
        details.append(
            f"configuration records v{config_version}"
            if isinstance(config_version, str) and re.fullmatch(r"[0-9A-Za-z._-]+", config_version)
            else "configuration version is missing or invalid"
        )
    if completed_version != current:
        details.append(
            f"completed state for the last complete setup records v{completed_version}"
            if isinstance(completed_version, str)
            and re.fullmatch(r"[0-9A-Za-z._-]+", completed_version)
            else "completed state has no valid version"
        )
    details.append(f"{current_label} is v{current}")
    last_run = state.get("last_run_kit_version", "")
    if (
        last_run
        and last_run != completed_version
        and isinstance(last_run, str)
        and re.fullmatch(r"[0-9A-Za-z._-]+", last_run)
    ):
        details.append(f"last setup attempt used v{last_run}")
    return check(
        "kit version",
        WARN,
        "; ".join(details),
        "re-run /shipshape-init to upgrade the managed files",
    )


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
            "doctor script and scheduled workflow present; setup inspection does not execute them",
        )
    return check(
        "scheduled health check",
        FAIL,
        "doctor script or scheduled workflow is missing or incomplete",
        SCHEDULED_HEALTH_NEXT_ACTION,
    )


def _yaml_value(line: str) -> str:
    value = line.split(":", 1)[1].strip()
    return re.sub(r"\s+#.*$", "", value).strip()


def _flow_stages(value: str) -> set[str] | None:
    if not value.startswith("[") or not value.endswith("]"):
        return None
    inner = value[1:-1].strip()
    if not inner:
        return set()
    stages = set()
    for item in inner.split(","):
        stage = item.strip()
        if not re.fullmatch(r"[a-z0-9-]+", stage):
            return None
        stages.add(stage)
    return stages


def pre_commit_config_wires_guard(text: str) -> tuple[bool, str]:
    """Recognize one conservative, effective local secret-guard configuration."""
    lines = text.splitlines()
    meaningful = [line for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if any("\t" in line[: len(line) - len(line.lstrip())] for line in meaningful):
        return False, "pre-commit configuration uses unsupported tab indentation"
    if any(re.search(r"(?:^|[\s:\[,])[&*][A-Za-z0-9_-]+", line) for line in meaningful):
        return False, "pre-commit configuration uses unsupported YAML aliases"
    yaml_content = [line.lstrip().removeprefix("- ").lstrip() for line in meaningful]
    if any(line.startswith(('"', "'", "{", "[", "<<:")) for line in yaml_content):
        return False, "pre-commit configuration uses unsupported YAML key syntax"

    top_level = [line for line in meaningful if len(line) == len(line.lstrip(" "))]
    repos_lines = [line for line in top_level if re.match(r"^repos\s*:", line)]
    default_lines = [line for line in top_level if re.match(r"^default_stages\s*:", line)]
    if len(repos_lines) != 1 or _yaml_value(repos_lines[0]):
        return False, "pre-commit configuration must contain one block-style repos list"
    if len(default_lines) > 1:
        return False, "pre-commit configuration repeats default_stages"
    default_stages = None
    if default_lines:
        default_stages = _flow_stages(_yaml_value(default_lines[0]))
        if default_stages is None:
            return False, "pre-commit default_stages uses an unsupported YAML form"

    repos_index = lines.index(repos_lines[0])
    repos_end = len(lines)
    for index in range(repos_index + 1, len(lines)):
        line = lines[index]
        if line.strip() and not line.lstrip().startswith("#") and not line.startswith(" "):
            repos_end = index
            break
    repo_lines = lines[repos_index + 1 : repos_end]
    repo_starts = [
        index for index, line in enumerate(repo_lines) if re.match(r"^  -\s+repo\s*:", line)
    ]
    if not repo_starts:
        return False, "pre-commit configuration has no supported repository blocks"

    secret_hooks = []
    for position, start in enumerate(repo_starts):
        end = repo_starts[position + 1] if position + 1 < len(repo_starts) else len(repo_lines)
        repo_block = repo_lines[start:end]
        repo_keys = [
            line
            for line in repo_block
            if re.match(r"^    repo\s*:", line) or re.match(r"^  -\s+repo\s*:", line)
        ]
        repo_value = _yaml_value(repo_block[0])
        hooks_lines = [line for line in repo_block if re.match(r"^    hooks\s*:", line)]
        if repo_value != "local" or len(repo_keys) != 1 or len(hooks_lines) != 1:
            continue
        hooks_index = repo_block.index(hooks_lines[0])
        if _yaml_value(hooks_lines[0]):
            continue
        hooks_block = repo_block[hooks_index + 1 :]
        hook_starts = [
            index for index, line in enumerate(hooks_block) if re.match(r"^      -\s+id\s*:", line)
        ]
        for hook_position, hook_start in enumerate(hook_starts):
            hook_end = (
                hook_starts[hook_position + 1]
                if hook_position + 1 < len(hook_starts)
                else len(hooks_block)
            )
            hook_block = hooks_block[hook_start:hook_end]
            if _yaml_value(hook_block[0]) != "secret-guard":
                continue
            values: dict[str, list[str]] = {}
            supported = True
            for field_index, line in enumerate(hook_block):
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                field_line = line[8:] if field_index else line[8:].lstrip("- ")
                match = re.fullmatch(r"([a-z_]+)\s*:\s*(.*)", field_line)
                if match is None:
                    supported = False
                    break
                key = match.group(1)
                if key not in {
                    "id",
                    "name",
                    "entry",
                    "language",
                    "pass_filenames",
                    "always_run",
                    "stages",
                }:
                    supported = False
                    break
                values.setdefault(key, []).append(re.sub(r"\s+#.*$", "", match.group(2)).strip())
            is_first = position == 0 and hook_position == 0
            secret_hooks.append((supported and is_first, values, default_stages))

    if len(secret_hooks) != 1:
        return False, "pre-commit configuration must contain one local secret-guard hook"
    supported, values, global_stages = secret_hooks[0]
    if not supported or any(len(items) != 1 for items in values.values()):
        return False, "secret-guard hook uses unsupported or duplicate keys"
    expected = {
        "id": "secret-guard",
        "entry": ".sdlc/hooks/secret-guard.sh",
        "language": "script",
        "pass_filenames": "false",
        "always_run": "true",
    }
    actual = {key: items[0] for key, items in values.items()}
    if actual.get("entry", "").startswith("./"):
        actual["entry"] = actual["entry"][2:]
    if any(actual.get(key) != value for key, value in expected.items()):
        return False, "local secret-guard hook does not match the supported wiring"
    if "stages" in actual:
        effective_stages = _flow_stages(actual["stages"])
        if effective_stages is None:
            return False, "secret-guard stages uses an unsupported YAML form"
    else:
        effective_stages = global_stages
    if effective_stages is not None and "pre-commit" not in effective_stages:
        return False, "secret-guard is not enabled for the pre-commit stage"
    return True, "supported local secret-guard wiring is scheduled for pre-commit"


def is_pre_commit_dispatcher(text: str) -> bool:
    has_header = re.search(r"(?m)^# File generated by pre-commit(?::|$)", text)
    has_args = re.search(
        r"(?m)^[ \t]*ARGS=\(hook-impl[ \t]+"
        r"--config=\.?/?\.pre-commit-config\.yaml[ \t]+"
        r"--hook-type=pre-commit\)[ \t]*$",
        text,
    )
    has_dispatch = re.search(
        r'(?m)^[ \t]*exec[ \t]+(?:pre-commit|"\$INSTALL_PYTHON"[ \t]+-mpre_commit)'
        r'[ \t]+"\$\{ARGS\[@\]\}"[ \t]*$',
        text,
    )
    return bool(has_header and has_args and has_dispatch)


def active_pre_commit_hook(repo: Path) -> tuple[Path | None, str]:
    """Resolve the hook Git actually uses, including core.hooksPath."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--git-path", "hooks"],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=GH_API_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, "unavailable"
    hooks_value = result.stdout.removesuffix("\n")
    if result.returncode != 0 or not hooks_value:
        return None, "unavailable"
    hooks_path = Path(hooks_value)
    if not hooks_path.is_absolute():
        hooks_path = repo / hooks_path
    return hooks_path / "pre-commit", "ok"


def hook_matches_guard(hook: Path, guard: Path) -> bool:
    try:
        if hook.samefile(guard):
            return True
    except OSError:
        pass
    try:
        return hook.is_file() and hook.read_bytes() == guard.read_bytes()
    except OSError:
        return False


def secret_guard_is_skipped() -> bool:
    return "secret-guard" in {
        item.strip() for item in os.environ.get("SKIP", "").split(",") if item.strip()
    }


def guard_installation_check(repo: Path, features: dict, guard: Path) -> dict:
    if not features.get("secret_guard", True):
        return check(
            "secret guard installed",
            WARN,
            "secret guard is disabled in .sdlc/config.json; hook activity is not claimed",
        )

    if os.environ.get("GITHUB_ACTIONS") == "true":
        secret_scan = repo / ".github" / "workflows" / "secret-scan.yml"
        if secret_scan.is_file():
            return check("secret guard installed", WARN, CI_GUARD_DETAIL)
        return check(
            "secret guard installed",
            FAIL,
            "the secret-scan workflow is missing in GitHub Actions",
            "Re-run /shipshape-init to restore the secret-scan workflow.",
        )

    hook, hook_status = active_pre_commit_hook(repo)
    if hook_status != "ok" or hook is None:
        return check(
            "secret guard installed",
            WARN,
            "could not determine the active Git hook path; guard activity is unknown",
            HOOK_INSTALL_ACTION,
        )
    if not hook.exists():
        return check(
            "secret guard installed",
            FAIL,
            "the scanner exists but no pre-commit hook is present in the active Git hook path",
            HOOK_INSTALL_ACTION,
        )
    if not os.access(hook, os.X_OK):
        return check(
            "secret guard installed",
            FAIL,
            "the active pre-commit hook or its secret guard target is not executable",
            HOOK_INSTALL_ACTION,
        )
    if hook_matches_guard(hook, guard):
        return check(
            "secret guard installed",
            PASS,
            "active hook path contains the expected guard; scanner execution was not observed",
        )

    try:
        hook_text = hook.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return check(
            "secret guard installed",
            WARN,
            "the active pre-commit hook could not be inspected; guard activity is unknown",
            HOOK_INSTALL_ACTION,
        )
    if not is_pre_commit_dispatcher(hook_text):
        return check(
            "secret guard installed",
            FAIL,
            "the active pre-commit hook does not invoke the expected secret guard",
            HOOK_INSTALL_ACTION,
        )

    config_path = repo / ".pre-commit-config.yaml"
    if not config_path.is_file():
        return check(
            "secret guard installed",
            FAIL,
            "the active pre-commit dispatcher has no configuration wiring the secret guard",
            HOOK_INSTALL_ACTION,
        )
    try:
        config_text = config_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return check(
            "secret guard installed",
            WARN,
            "pre-commit configuration could not be inspected; guard activity is unknown",
            HOOK_INSTALL_ACTION,
        )
    wired, wiring_detail = pre_commit_config_wires_guard(config_text)
    if not wired:
        return check(
            "secret guard installed",
            FAIL,
            wiring_detail,
            HOOK_INSTALL_ACTION,
        )
    if secret_guard_is_skipped():
        return check(
            "secret guard installed",
            FAIL,
            "current SKIP environment disables the secret-guard pre-commit hook",
            "remove secret-guard from SKIP before committing",
        )
    return check(
        "secret guard installed",
        PASS,
        "static inspection found a pre-commit-shaped dispatcher and supported local "
        "configuration scheduled for commits; dispatcher execution was not observed, "
        "and scanner execution was not observed",
    )


def available_protection_workflows(repo: Path) -> set[str]:
    """Return only fixed workflow paths that are regular files, without following links."""
    available = set()
    for relative in PROTECTION_WORKFLOW_PATHS:
        try:
            mode = (repo / relative).lstat().st_mode
        except OSError:
            continue
        if stat.S_ISREG(mode):
            available.add(relative)
    return available


def path_presence(path: Path) -> bool | None:
    """Return exact directory-entry presence without following a link."""
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return None
    return True


def inspect_rendered_protection(repo: Path, config: dict) -> dict:
    helper = repo / ".sdlc" / "scripts" / "review-gates.py"
    try:
        helper_mode = helper.lstat().st_mode
    except FileNotFoundError:
        return {
            "ok": False,
            "requested": None,
            "request": None,
            "reason": "the rendered review-gates helper is missing",
        }
    except OSError:
        return {
            "ok": False,
            "requested": None,
            "request": None,
            "reason": "the rendered review-gates helper could not be inspected",
        }
    if not stat.S_ISREG(helper_mode):
        return {
            "ok": False,
            "requested": None,
            "request": None,
            "reason": "the rendered review-gates helper is not a regular file",
        }
    module_name = "_shipshape_rendered_review_gates"
    try:
        spec = importlib.util.spec_from_file_location(module_name, helper)
        if spec is None or spec.loader is None:
            raise ImportError("the rendered review-gates helper could not be loaded")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            sys.modules.pop(module_name, None)
        result = module.inspect_configured_protection(
            module.GitHubClient(), config, available_protection_workflows(repo)
        )
    except (AttributeError, ImportError, OSError, RuntimeError, SyntaxError, TypeError) as error:
        return {"ok": False, "reason": f"review-gates inspection unavailable: {error}"}
    if not isinstance(result, dict):
        return {"ok": False, "reason": "review-gates inspection returned malformed data"}
    return result


def remote_protection_check(repo: Path, config: dict) -> dict:
    protection = inspect_rendered_protection(repo, config)
    request = protection.get("request")
    workflow = repo / LOW_RISK_AUTOMERGE_PATH
    workflow_present = path_presence(workflow)
    if workflow_present is None:
        return check(
            "remote protection",
            FAIL,
            f"{PROTECTION_UNVERIFIED}: the auto-merge workflow could not be inspected",
            PROTECTION_NEXT_ACTION,
        )
    workflow_is_regular = False
    if workflow_present:
        try:
            workflow_is_regular = stat.S_ISREG(workflow.lstat().st_mode)
        except OSError:
            return check(
                "remote protection",
                FAIL,
                f"{PROTECTION_UNVERIFIED}: the auto-merge workflow could not be inspected",
                PROTECTION_NEXT_ACTION,
            )
    if (
        isinstance(request, dict)
        and request.get("tiered_review") is True
        and not workflow_is_regular
    ):
        return check(
            "remote protection",
            FAIL,
            "tiered review is on but the auto-merge workflow is missing or not a regular file",
            TIERED_REVIEW_NEXT_ACTION,
        )
    if isinstance(request, dict) and request.get("tiered_review") is False and workflow_present:
        return check(
            "remote protection",
            FAIL,
            "tiered review is off but the auto-merge workflow is still present",
            TIERED_REVIEW_REMOVE_ACTION,
        )
    if protection.get("ok") is not True:
        reason = str(protection.get("reason") or "protection inspection did not complete")
        return check(
            "remote protection",
            FAIL,
            f"{PROTECTION_UNVERIFIED}: {reason}",
            PROTECTION_NEXT_ACTION,
        )
    if not isinstance(request, dict) or type(protection.get("requested")) is not bool:
        return check(
            "remote protection",
            FAIL,
            f"{PROTECTION_UNVERIFIED}: the shared inspection result was incomplete",
            PROTECTION_NEXT_ACTION,
        )
    if protection["requested"] is False:
        return check("remote protection", PASS, str(protection["reason"]))

    mode = "trunk" if request.get("workflow_style") == "trunk" else "PR"
    return check(
        "remote protection",
        PASS,
        f"configured {mode} protection verified: {protection['reason']}",
    )


def agent_control_coverage_check(repo: Path, features: dict) -> dict:
    guard = repo / ".sdlc" / "hooks" / "secret-guard.sh"
    guard_text = guard.read_text(encoding="utf-8", errors="ignore") if guard.is_file() else ""
    has_guard_layer = any(marker in guard_text for marker in AGENT_CONTROL_LAYER_MARKERS)
    if features.get("secret_guard", True) and not has_guard_layer:
        return check(
            "agent control-file coverage",
            FAIL,
            "rendered secret guard lacks agent and editor control-file checks",
            AGENT_CONTROL_NEXT_ACTION,
        )
    if not features.get("secret_guard", True):
        return check(
            "agent control-file coverage",
            WARN,
            "secret guard is off; agent and editor control-file checks are inactive",
        )
    if not features.get("github_agents", False):
        return check(
            "agent control-file coverage",
            WARN,
            "deterministic guard rules are configured; GitHub agent review is off",
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
        "guard and reviewer rules are present; setup inspection does not execute them "
        "or prove behavioural security",
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
        checks.append(
            check(
                "secret guard",
                PASS,
                "secret scanner file present; setup inspection does not execute it or prove "
                "behavioural security",
            )
        )

    if guard.is_file():
        checks.append(guard_installation_check(repo, features, guard))

    checks.append(agent_control_coverage_check(repo, features))
    checks.append(remote_protection_check(repo, config))

    codeql = repo / ".github" / "workflows" / "codeql.yml"
    if codeql.is_file():
        checks.append(
            check(
                "code scanning (CodeQL)",
                PASS,
                "workflow present; setup inspection does not run CodeQL or query alerts",
            )
        )
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
        checks.append(
            check(
                "dependency watch (Dependabot)",
                PASS,
                "configuration present; setup inspection does not query vulnerability alerts",
            )
        )
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
        checks.append(
            check(
                "workflow permissions",
                PASS,
                "all workflows declare permissions; setup inspection does not parse their "
                "behaviour or prove least privilege",
            )
        )
    return checks


def setup_checks(repo: Path, config: dict, state: dict) -> list[dict]:
    checks = [unused_settings_check(config)]

    if (repo / ".github" / "workflows" / "ci.yml").is_file():
        if config.get("workflow_style", "trunk") == "trunk":
            detail = (
                "CI workflow is configured for pushes; no run was observed and no "
                "pre-landing enforcement is proved"
            )
        else:
            detail = "CI workflow is configured; setup inspection did not observe a run"
        checks.append(
            check(
                "automated tests (CI)",
                PASS,
                detail,
            )
        )
    else:
        checks.append(check("automated tests (CI)", WARN, "no CI workflow found"))

    checks.append(test_retries_check(repo, config))
    checks.append(scheduled_health_check(repo, config.get("features", {})))

    byte_drifted, mode_drifted, legacy_modes, missing, unverified = [], [], [], [], []
    for dest, record in state.get("files", {}).items():
        findings = managed_file_findings(repo, dest, record)
        if "missing" in findings:
            missing.append(dest)
        if "unverified" in findings:
            unverified.append(dest)
        if "bytes" in findings:
            byte_drifted.append(dest)
        if "mode" in findings:
            mode_drifted.append(dest)
        if "legacy-mode" in findings:
            legacy_modes.append(dest)
    pending_conflicts = [
        item for item in state.get("pending_conflicts", []) if isinstance(item, str)
    ]
    error_paths = [
        str(item.get("path"))
        for item in state.get("last_run_errors", [])
        if isinstance(item, dict) and item.get("path")
    ]
    if state.get("status") == "partial" or pending_conflicts or error_paths:
        details = []
        if pending_conflicts:
            details.append(f"untouched conflicts: {', '.join(pending_conflicts)}")
        if error_paths:
            details.append(f"operation errors: {', '.join(error_paths)}")
        if missing:
            details.append(f"missing files: {', '.join(missing)}")
        if unverified:
            details.append(f"could not safely inspect: {', '.join(unverified)}")
        if legacy_modes:
            details.append(f"legacy state has no recorded mode: {', '.join(legacy_modes)}")
        if byte_drifted:
            details.append(f"edited bytes: {', '.join(byte_drifted)}")
        if mode_drifted:
            details.append(f"edited modes: {', '.join(mode_drifted)}")
        detail = "; ".join(details) or "completion was not recorded"
        checks.append(
            check(
                "managed files",
                WARN,
                f"last setup apply was partial; {detail}",
                "review the pending paths, then re-run /shipshape-init with explicit "
                "per-file approval where intended",
            )
        )
    elif missing or unverified or legacy_modes:
        details = []
        if missing:
            details.append(f"shipshape-managed files were deleted: {', '.join(missing)}")
        if unverified:
            details.append(f"could not safely inspect: {', '.join(unverified)}")
        if legacy_modes:
            details.append(f"legacy state has no recorded mode: {', '.join(legacy_modes)}")
        if byte_drifted:
            details.append(f"edited bytes: {', '.join(byte_drifted)}")
        if mode_drifted:
            details.append(f"edited modes: {', '.join(mode_drifted)}")
        checks.append(
            check(
                "managed files",
                WARN,
                "; ".join(details),
                "re-run /shipshape-init to restore them, or /shipshape-customize to drop them",
            )
        )
    elif byte_drifted or mode_drifted:
        details = []
        if byte_drifted:
            details.append(f"edited bytes: {', '.join(byte_drifted)}")
        if mode_drifted:
            details.append(f"edited modes: {', '.join(mode_drifted)}")
        checks.append(
            check(
                "managed files",
                PASS,
                f"present; edited by you (which is fine); {'; '.join(details)}",
            )
        )
    else:
        checks.append(check("managed files", PASS, "all present and unmodified"))

    checks.append(kit_version_check(config, state, KIT_VERSION, "rendered doctor"))
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
