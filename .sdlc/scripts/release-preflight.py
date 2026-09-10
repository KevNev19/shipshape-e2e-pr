#!/usr/bin/env python3
# What this is: proves that one exact commit has the GitHub evidence required
# before a tag is pushed or a GitHub release is created.
# Safe to edit: yes — shipshape will ask before overwriting your edits.
# managed-by: shipshape v0.2.1

import argparse
import base64
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

SHA_RE = re.compile(r"[0-9a-f]{40}")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
WORKFLOW_PATHS = {
    "ci": ".github/workflows/ci.yml",
    "secret_scan": ".github/workflows/secret-scan.yml",
    "codeql": ".github/workflows/codeql.yml",
    "release": ".github/workflows/release.yml",
}
API_VERSION = "2022-11-28"
CODEQL_PRIMARY_LANGUAGES = {"python", "node", "go", "java", "ruby", "csharp"}
PUBLICATION_HELPER_PATH = ".sdlc/scripts/release-preflight.py"


class PreflightFailure(Exception):
    def __init__(self, code: str, message: str, next_action: str, **details: object):
        super().__init__(message)
        self.code = code
        self.message = message
        self.next_action = next_action
        self.details = details


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise PreflightFailure(
            "invalid_arguments",
            message,
            "Run the helper with local <repository> or publish --repo OWNER/REPO --tag TAG.",
        )


def fail(code: str, message: str, next_action: str, **details: object) -> None:
    raise PreflightFailure(code, message, next_action, **details)


def run_command(command: list[str], *, cwd: Path | None = None) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail(
            "command_unavailable",
            f"Could not run {command[0]}.",
            f"Install {command[0]} and retry the release preflight.",
        )
    if result.returncode != 0:
        fail(
            "command_failed",
            f"{command[0]} could not supply required release evidence.",
            f"Resolve the {command[0]} error and rerun the release preflight.",
        )
    return result.stdout.strip()


class GitHubApi:
    def request(
        self,
        endpoint: str,
        *,
        fields: dict[str, str] | None = None,
        paginate: bool = False,
    ) -> object:
        command = [
            "gh",
            "api",
            "--method",
            "GET",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            f"X-GitHub-Api-Version: {API_VERSION}",
        ]
        if paginate:
            command.extend(["--paginate", "--slurp"])
        command.append(endpoint)
        for name, value in (fields or {}).items():
            command.extend(["-f", f"{name}={value}"])
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            fail(
                "github_api_error",
                f"GitHub API evidence was unavailable for {endpoint}.",
                "Authenticate GitHub CLI with read access, check connectivity, "
                "and rerun preflight.",
                endpoint=endpoint,
            )
        if result.returncode != 0:
            fail(
                "github_api_error",
                f"GitHub API evidence was unavailable for {endpoint}.",
                "Authenticate GitHub CLI with read access, check connectivity, "
                "and rerun preflight.",
                endpoint=endpoint,
            )
        try:
            return json.loads(result.stdout)
        except (json.JSONDecodeError, TypeError):
            fail(
                "github_api_malformed",
                f"GitHub returned malformed evidence for {endpoint}.",
                "Retry the preflight; if it repeats, inspect the GitHub API response.",
                endpoint=endpoint,
            )

    def object_pages(
        self, endpoint: str, item_key: str, *, fields: dict[str, str] | None = None
    ) -> list[dict]:
        payload = self.request(endpoint, fields=fields, paginate=True)
        if not isinstance(payload, list) or not payload:
            incomplete(endpoint, "paginated response is not a non-empty page list")
        items: list[dict] = []
        total_count: int | None = None
        for page in payload:
            if not isinstance(page, dict):
                incomplete(endpoint, "a page is not an object")
            page_items = page.get(item_key)
            page_total = page.get("total_count")
            if not isinstance(page_items, list) or not isinstance(page_total, int):
                incomplete(endpoint, f"a page lacks {item_key} or total_count")
            if total_count is None:
                total_count = page_total
            elif total_count != page_total:
                incomplete(endpoint, "total_count changed between pages")
            if not all(isinstance(item, dict) for item in page_items):
                incomplete(endpoint, f"{item_key} contains a non-object")
            items.extend(page_items)
        if total_count != len(items):
            incomplete(endpoint, "pagination did not return every advertised item")
        return items

    def list_pages(self, endpoint: str) -> list[dict]:
        payload = self.request(endpoint, fields={"per_page": "100"}, paginate=True)
        if not isinstance(payload, list) or not payload:
            incomplete(endpoint, "paginated response is not a non-empty page list")
        items: list[dict] = []
        for page in payload:
            if not isinstance(page, list) or not all(isinstance(item, dict) for item in page):
                incomplete(endpoint, "a page is not a list of objects")
            items.extend(page)
        return items


def incomplete(endpoint: str, detail: str) -> None:
    fail(
        "incomplete_response",
        f"GitHub evidence for {endpoint} is incomplete: {detail}.",
        "Retry preflight; inspect the named API endpoint if the response remains incomplete.",
        endpoint=endpoint,
    )


def require_dict(payload: object, endpoint: str) -> dict:
    if not isinstance(payload, dict):
        incomplete(endpoint, "response is not an object")
    return payload


def require_sha(value: object, endpoint: str, field: str = "sha") -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        incomplete(endpoint, f"{field} is not a full commit SHA")
    return value


def require_utc_timestamp(value: object, endpoint: str, field: str) -> datetime:
    if not isinstance(value, str):
        incomplete(endpoint, f"a workflow run lacks valid {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        incomplete(endpoint, f"a workflow run has malformed {field}")
    if parsed.utcoffset() != timezone.utc.utcoffset(None):
        incomplete(endpoint, f"a workflow run has non-UTC {field}")
    return parsed


def validate_repository(value: str) -> str:
    value = value.removesuffix(".git")
    if REPOSITORY_RE.fullmatch(value) is None:
        fail(
            "repository_invalid",
            "The GitHub repository must be written as OWNER/REPO.",
            "Pass --repo OWNER/REPO and rerun preflight.",
        )
    return value


def repository_from_remote(remote_url: str) -> str | None:
    if remote_url.startswith("git@github.com:"):
        return remote_url.split(":", 1)[1].removesuffix(".git")
    parsed = urlparse(remote_url)
    if parsed.hostname != "github.com":
        return None
    path = parsed.path.strip("/").removesuffix(".git")
    return path if REPOSITORY_RE.fullmatch(path) else None


def validate_tag(tag: str) -> str:
    forbidden = ("..", "@{", "//", "\\")
    if (
        not tag
        or len(tag) > 255
        or tag.startswith(("/", "."))
        or tag.endswith(("/", "."))
        or any(part.startswith(".") or part.endswith(".lock") for part in tag.split("/"))
        or any(item in tag for item in forbidden)
        or any(character.isspace() or ord(character) < 32 for character in tag)
        or any(character in tag for character in "~^:?*[")
    ):
        fail(
            "tag_invalid",
            "The tag is not a safe Git reference name.",
            "Choose a version tag such as v1.2.3 and rerun preflight.",
        )
    return tag


def remote_metadata(api: GitHubApi, requested_repository: str) -> tuple[str, str, str]:
    repository = validate_repository(requested_repository)
    endpoint = f"repos/{repository}"
    metadata = require_dict(api.request(endpoint), endpoint)
    full_name = metadata.get("full_name")
    default_branch = metadata.get("default_branch")
    if (
        not isinstance(full_name, str)
        or full_name.casefold() != repository.casefold()
        or not isinstance(default_branch, str)
        or not default_branch
    ):
        incomplete(endpoint, "full_name or default_branch is missing")
    repository = validate_repository(full_name)
    commit_endpoint = f"repos/{repository}/commits/{quote(default_branch, safe='')}"
    commit = require_dict(api.request(commit_endpoint), commit_endpoint)
    default_sha = require_sha(commit.get("sha"), commit_endpoint)
    return repository, default_branch, default_sha


def candidate_config(api: GitHubApi, repository: str, candidate: str) -> dict:
    endpoint = f"repos/{repository}/contents/.sdlc/config.json"
    payload = require_dict(api.request(endpoint, fields={"ref": candidate}), endpoint)
    if payload.get("type") != "file" or payload.get("encoding") != "base64":
        incomplete(endpoint, "the candidate config is not a base64 file")
    content = payload.get("content")
    if not isinstance(content, str):
        incomplete(endpoint, "content is missing")
    try:
        decoded = base64.b64decode("".join(content.split()), validate=True).decode("utf-8")
        config = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        incomplete(endpoint, "content is not valid base64 JSON")
    if (
        not isinstance(config, dict)
        or not isinstance(config.get("features"), dict)
        or not isinstance(config.get("languages"), list)
        or not all(isinstance(language, str) for language in config["languages"])
    ):
        incomplete(endpoint, "features or languages are missing from the candidate config")
    features = config["features"]
    for name in ("release_automation", "secret_guard", "codeql"):
        if not isinstance(features.get(name), bool):
            incomplete(endpoint, f"features.{name} is missing or is not boolean")
    if not features["release_automation"]:
        fail(
            "release_automation_disabled",
            "Release automation is disabled in the candidate configuration.",
            "Enable release automation through shipshape customization before cutting a release.",
        )
    return config


def required_workflows(config: dict) -> list[tuple[str, str]]:
    features = config["features"]
    languages = config["languages"]
    required = [("ci", WORKFLOW_PATHS["ci"])]
    if features["secret_guard"]:
        required.append(("secret_scan", WORKFLOW_PATHS["secret_scan"]))
    if features["codeql"] and languages and languages[0] in CODEQL_PRIMARY_LANGUAGES:
        required.append(("codeql", WORKFLOW_PATHS["codeql"]))
    return required


def workflow_catalog(api: GitHubApi, repository: str) -> dict[str, dict]:
    endpoint = f"repos/{repository}/actions/workflows"
    workflows = api.object_pages(endpoint, "workflows", fields={"per_page": "100"})
    by_path: dict[str, dict] = {}
    for workflow in workflows:
        path = workflow.get("path")
        workflow_id = workflow.get("id")
        state = workflow.get("state")
        if (
            not isinstance(path, str)
            or not isinstance(workflow_id, int)
            or not isinstance(state, str)
        ):
            incomplete(endpoint, "a workflow lacks path, id, or state")
        if path in by_path:
            incomplete(endpoint, f"duplicate workflow path {path}")
        by_path[path] = workflow
    return by_path


def verify_publication_readiness(
    api: GitHubApi, repository: str, candidate: str, catalog: dict[str, dict]
) -> dict[str, object]:
    workflow_path = WORKFLOW_PATHS["release"]
    workflow = catalog.get(workflow_path)
    if workflow is None:
        fail(
            "publication_workflow_missing",
            f"Publication workflow {workflow_path} is not registered on GitHub.",
            f"Render and push {workflow_path} on the default branch, wait for GitHub "
            "to register it, then rerun preflight.",
            path=workflow_path,
        )
    if workflow.get("state") != "active":
        fail(
            "publication_workflow_disabled",
            f"Publication workflow {workflow_path} is not active.",
            f"Enable {workflow_path} from the default branch in GitHub Actions, then "
            "rerun preflight; no prior release run is required.",
            path=workflow_path,
            state=workflow.get("state"),
        )

    helper_path = PUBLICATION_HELPER_PATH
    endpoint = f"repos/{repository}/contents/{helper_path}"
    try:
        helper = api.request(endpoint, fields={"ref": candidate})
    except PreflightFailure as error:
        if error.code not in {"github_api_error", "github_api_malformed"}:
            raise
        fail(
            "publication_helper_unavailable",
            f"Publication helper {helper_path} could not be verified at {candidate}.",
            f"Render and push {helper_path} on the default branch, confirm GitHub "
            "Actions read access, then rerun preflight.",
            path=helper_path,
            head_sha=candidate,
        )
    valid_helper = (
        isinstance(helper, dict)
        and helper.get("type") == "file"
        and helper.get("path") == helper_path
        and isinstance(helper.get("sha"), str)
        and SHA_RE.fullmatch(helper["sha"]) is not None
    )
    if not valid_helper:
        fail(
            "publication_helper_invalid",
            f"Publication helper {helper_path} has missing or mismatched identity.",
            f"Render and push the exact {helper_path} file on the default branch, then "
            "rerun preflight.",
            path=helper_path,
            head_sha=candidate,
        )
    return {
        "workflow": {
            "path": workflow_path,
            "workflow_id": workflow["id"],
            "state": workflow["state"],
        },
        "helper": {
            "path": helper_path,
            "blob_sha": helper["sha"],
            "head_sha": candidate,
        },
    }


def validate_run_shape(run: dict, endpoint: str) -> None:
    required_types = {
        "id": int,
        "workflow_id": int,
        "run_number": int,
        "run_attempt": int,
        "check_suite_id": int,
        "status": str,
        "head_sha": str,
        "head_branch": str,
        "event": str,
        "path": str,
        "html_url": str,
    }
    for field, expected_type in required_types.items():
        if not isinstance(run.get(field), expected_type):
            incomplete(endpoint, f"a workflow run lacks valid {field}")
    require_sha(run["head_sha"], endpoint, "head_sha")
    if run["run_attempt"] < 1 or run["run_number"] < 1:
        incomplete(endpoint, "run_number or run_attempt is not positive")
    if run.get("conclusion") is not None and not isinstance(run.get("conclusion"), str):
        incomplete(endpoint, "a workflow run has an invalid conclusion")
    require_utc_timestamp(run.get("run_started_at"), endpoint, "run_started_at")


def normalized_run_path(path: str) -> str:
    return path.split("@", 1)[0]


def select_latest_current_attempt(
    runs: list[dict], endpoint: str, key: str, expected_path: str
) -> dict:
    chronology = [
        (require_utc_timestamp(run["run_started_at"], endpoint, "run_started_at"), run)
        for run in runs
    ]
    latest_started_at = max(started_at for started_at, _ in chronology)
    latest = [run for started_at, run in chronology if started_at == latest_started_at]
    if len(latest) != 1:
        fail(
            "workflow_run_chronology_ambiguous",
            f"Latest current attempts for {expected_path} share the same run_started_at.",
            "Rerun the intended final workflow run so one current attempt has an "
            "unambiguously later start, then rerun preflight.",
            workflow=key,
            path=expected_path,
            run_started_at=latest[0]["run_started_at"],
            runs=[
                {
                    "run_id": run["id"],
                    "run_number": run["run_number"],
                    "run_attempt": run["run_attempt"],
                    "url": run["html_url"],
                }
                for run in latest
            ],
        )
    return latest[0]


def verify_jobs(
    api: GitHubApi, repository: str, run: dict, candidate: str
) -> list[dict[str, object]]:
    endpoint = f"repos/{repository}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs"
    jobs = api.object_pages(endpoint, "jobs", fields={"per_page": "100"})
    if not jobs:
        fail(
            "workflow_jobs_absent",
            f"Workflow run {run['id']} has no jobs for attempt {run['run_attempt']}.",
            "Inspect the exact run and rerun preflight after every required job completes.",
            run_id=run["id"],
            run_attempt=run["run_attempt"],
            url=run["html_url"],
        )
    evidence = []
    unsuccessful = []
    for job in jobs:
        required_types = {
            "id": int,
            "run_id": int,
            "head_sha": str,
            "name": str,
            "status": str,
            "html_url": str,
        }
        for field, expected_type in required_types.items():
            if not isinstance(job.get(field), expected_type):
                incomplete(endpoint, f"a job lacks valid {field}")
        require_sha(job["head_sha"], endpoint, "head_sha")
        if job["run_id"] != run["id"] or job["head_sha"] != candidate:
            incomplete(endpoint, "a job does not belong to the exact run and commit")
        conclusion = job.get("conclusion")
        if conclusion is not None and not isinstance(conclusion, str):
            incomplete(endpoint, "a job has an invalid conclusion")
        item = {
            "name": job["name"],
            "status": job["status"],
            "conclusion": conclusion,
            "url": job["html_url"],
        }
        evidence.append(item)
        if job["status"] != "completed" or conclusion != "success":
            unsuccessful.append(item)
    if unsuccessful:
        fail(
            "workflow_jobs_unsuccessful",
            f"Workflow run {run['id']} has jobs without successful completion.",
            "Open the exact run, make every required job succeed, then rerun preflight.",
            run_id=run["id"],
            run_attempt=run["run_attempt"],
            url=run["html_url"],
            jobs=unsuccessful,
        )
    return evidence


def verify_workflow(
    api: GitHubApi,
    repository: str,
    head_branch: str,
    candidate: str,
    key: str,
    expected_path: str,
    workflow: dict,
    *,
    filter_branch: bool = True,
) -> dict[str, object]:
    workflow_id = workflow["id"]
    if workflow.get("state") != "active":
        fail(
            "workflow_disabled",
            f"Required workflow {expected_path} is not active.",
            "Enable the exact workflow and obtain a successful push run for the candidate commit.",
            workflow=key,
            path=expected_path,
        )
    endpoint = f"repos/{repository}/actions/workflows/{workflow_id}/runs"
    fields = {"event": "push", "head_sha": candidate, "per_page": "100"}
    if filter_branch:
        fields["branch"] = head_branch
    runs = api.object_pages(endpoint, "workflow_runs", fields=fields)
    applicable = []
    candidate_identity_mismatch = False
    for run in runs:
        validate_run_shape(run, endpoint)
        exact_identity = (
            run["workflow_id"] == workflow_id
            and normalized_run_path(run["path"]) == expected_path
            and run["event"] == "push"
            and run["head_branch"] == head_branch
        )
        if run["head_sha"] == candidate and not exact_identity:
            candidate_identity_mismatch = True
        if run["head_sha"] == candidate and exact_identity:
            applicable.append(run)
    if not applicable:
        code = (
            "workflow_run_identity_mismatch"
            if candidate_identity_mismatch
            else "workflow_run_absent"
        )
        fail(
            code,
            f"No applicable {expected_path} push run exists for commit {candidate}.",
            "Inspect why the exact push run is absent. If GITHUB_TOKEN suppressed "
            "a bot-merge push, make a separately approved release/version commit "
            "and push that new candidate with normal human or appropriately "
            "authorized app credentials, then restart preflight for its new SHA; "
            "the old SHA, an unchanged-ref push, and workflow_dispatch do not qualify.",
            workflow=key,
            path=expected_path,
            head_sha=candidate,
        )
    latest = select_latest_current_attempt(applicable, endpoint, key, expected_path)
    if latest["status"] != "completed":
        fail(
            "workflow_run_pending",
            f"The latest applicable {expected_path} attempt is {latest['status']}.",
            "Wait for the exact run to complete successfully, then rerun preflight.",
            workflow=key,
            path=expected_path,
            run_id=latest["id"],
            run_attempt=latest["run_attempt"],
            status=latest["status"],
            url=latest["html_url"],
        )
    if latest.get("conclusion") != "success":
        fail(
            "workflow_run_unsuccessful",
            f"The latest applicable {expected_path} attempt concluded {latest.get('conclusion')}.",
            "Fix or rerun the exact failed workflow attempt, then rerun preflight.",
            workflow=key,
            path=expected_path,
            run_id=latest["id"],
            run_attempt=latest["run_attempt"],
            conclusion=latest.get("conclusion"),
            url=latest["html_url"],
        )
    jobs = verify_jobs(api, repository, latest, candidate)
    return {
        "workflow": key,
        "path": expected_path,
        "workflow_id": workflow_id,
        "run_id": latest["id"],
        "run_number": latest["run_number"],
        "run_attempt": latest["run_attempt"],
        "run_started_at": latest["run_started_at"],
        "check_suite_id": latest["check_suite_id"],
        "head_sha": candidate,
        "head_branch": head_branch,
        "event": "push",
        "status": latest["status"],
        "conclusion": latest["conclusion"],
        "url": latest["html_url"],
        "jobs": jobs,
    }


def verify_workflows(
    api: GitHubApi,
    repository: str,
    default_branch: str,
    candidate: str,
    *,
    config: dict | None = None,
    catalog: dict[str, dict] | None = None,
) -> list[dict[str, object]]:
    if config is None:
        config = candidate_config(api, repository, candidate)
    if catalog is None:
        catalog = workflow_catalog(api, repository)
    evidence = []
    for key, path in required_workflows(config):
        workflow = catalog.get(path)
        if workflow is None:
            fail(
                "workflow_missing",
                f"Required workflow {path} is not registered on GitHub.",
                "Restore and enable the exact workflow, run it on the candidate, then retry.",
                workflow=key,
                path=path,
            )
        evidence.append(
            verify_workflow(api, repository, default_branch, candidate, key, path, workflow)
        )
    return evidence


def matching_remote_tag(api: GitHubApi, repository: str, tag: str) -> dict | None:
    endpoint = f"repos/{repository}/git/matching-refs/tags/{quote(tag, safe='')}"
    matches = api.list_pages(endpoint)
    exact_ref = f"refs/tags/{tag}"
    exact = [match for match in matches if match.get("ref") == exact_ref]
    if len(exact) > 1:
        incomplete(endpoint, "the exact tag appears more than once")
    return exact[0] if exact else None


def peel_remote_tag(api: GitHubApi, repository: str, tag_ref: dict) -> str:
    current = tag_ref.get("object")
    seen: set[str] = set()
    for _ in range(10):
        if not isinstance(current, dict):
            incomplete("git tag reference", "object is missing")
        object_type = current.get("type")
        sha = require_sha(current.get("sha"), "git tag reference")
        if object_type == "commit":
            return sha
        if object_type != "tag" or sha in seen:
            incomplete("git tag reference", "tag object cannot be resolved to a commit")
        seen.add(sha)
        endpoint = f"repos/{repository}/git/tags/{sha}"
        tag_object = require_dict(api.request(endpoint), endpoint)
        current = tag_object.get("object")
    incomplete("git tag reference", "tag nesting exceeds the safe resolution limit")


def verify_ancestry(api: GitHubApi, repository: str, candidate: str, default_sha: str) -> None:
    if candidate == default_sha:
        return
    endpoint = f"repos/{repository}/compare/{candidate}...{default_sha}"
    comparison = require_dict(api.request(endpoint), endpoint)
    base_commit = comparison.get("base_commit")
    merge_base = comparison.get("merge_base_commit")
    if not isinstance(base_commit, dict) or not isinstance(merge_base, dict):
        incomplete(endpoint, "base_commit or merge_base_commit is missing")
    base_sha = require_sha(base_commit.get("sha"), endpoint, "base_commit.sha")
    merge_base_sha = require_sha(merge_base.get("sha"), endpoint, "merge_base_commit.sha")
    if (
        base_sha != candidate
        or merge_base_sha != candidate
        or comparison.get("status") not in {"ahead", "identical"}
    ):
        fail(
            "candidate_not_default_ancestor",
            f"Commit {candidate} is not on the trusted default-branch ancestry.",
            "Create a new tag from a verified default-branch commit; never move this tag.",
            head_sha=candidate,
            default_sha=default_sha,
        )


def local_preflight(args: argparse.Namespace, result: dict) -> None:
    repo = Path(args.repository).resolve()
    root = Path(run_command(["git", "-C", str(repo), "rev-parse", "--show-toplevel"]))
    result["local_root"] = str(root)
    candidate = require_sha(
        run_command(["git", "-C", str(root), "rev-parse", "HEAD"]), "local git", "HEAD"
    )
    result["candidate_sha"] = candidate
    if args.candidate is not None and args.candidate != candidate:
        fail(
            "candidate_changed",
            "The checked-out commit changed after release review.",
            "Review the new exact commit and restart release preflight.",
            expected_sha=args.candidate,
            actual_sha=candidate,
        )
    status = run_command(["git", "-C", str(root), "status", "--porcelain=v1"])
    if status:
        fail(
            "working_tree_dirty",
            "The working tree has uncommitted changes.",
            "Commit or safely set aside every change, then rerun preflight.",
        )
    try:
        origin = run_command(["git", "-C", str(root), "remote", "get-url", "origin"])
    except PreflightFailure:
        fail(
            "github_remote_missing",
            "This local repository has no origin, so GitHub release evidence cannot be verified.",
            "Add the intended GitHub origin, push the default branch, then rerun preflight.",
        )
    if not origin:
        fail(
            "github_remote_missing",
            "This local repository has no origin, so GitHub release evidence cannot be verified.",
            "Add the intended GitHub origin, push the default branch, then rerun preflight.",
        )
    inferred_repository = repository_from_remote(origin)
    if args.repo is None and inferred_repository is None:
        fail(
            "github_remote_missing",
            "The origin is not an identifiable GitHub repository.",
            "Set origin to the intended GitHub repository, then rerun preflight.",
        )
    requested_repository = args.repo or inferred_repository
    if inferred_repository is not None and args.repo is not None:
        if inferred_repository.casefold() != args.repo.casefold():
            fail(
                "repository_mismatch",
                "--repo does not match the GitHub origin.",
                "Use the repository named by origin and rerun preflight.",
            )
    api = GitHubApi()
    repository, default_branch, default_sha = remote_metadata(api, requested_repository)
    result["repository"] = repository
    result["default_branch"] = default_branch
    result["default_branch_sha"] = default_sha
    branch = run_command(["git", "-C", str(root), "symbolic-ref", "--short", "HEAD"])
    if branch != default_branch:
        fail(
            "not_default_branch",
            f"The checked-out branch is {branch}, not GitHub's default branch {default_branch}.",
            f"Switch to {default_branch}, update it, and rerun preflight.",
            actual_branch=branch,
            expected_branch=default_branch,
        )
    remote_ref = f"refs/heads/{default_branch}"
    remote_line = run_command(
        ["git", "-C", str(root), "ls-remote", "--exit-code", "origin", remote_ref]
    )
    remote_parts = remote_line.split()
    if len(remote_parts) != 2 or remote_parts[1] != remote_ref:
        fail(
            "remote_default_incomplete",
            "Origin did not return one exact default-branch reference.",
            "Check origin and GitHub's default branch, then rerun preflight.",
        )
    origin_default_sha = require_sha(remote_parts[0], "origin default branch")
    if origin_default_sha != default_sha:
        fail(
            "remote_default_mismatch",
            "Origin and the GitHub API disagree about the default-branch commit.",
            "Retry after the remote settles; investigate origin if the mismatch persists.",
            git_sha=origin_default_sha,
            github_sha=default_sha,
        )
    if candidate != default_sha:
        fail(
            "candidate_not_remote_head",
            "The local candidate is not the exact remote default-branch head.",
            f"Update and push {default_branch}, then rerun preflight on the exact remote head.",
            head_sha=candidate,
            default_sha=default_sha,
        )
    if args.tag is not None:
        tag = validate_tag(args.tag)
        result["tag"] = tag
        local_tag_sha = require_sha(
            run_command(
                ["git", "-C", str(root), "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"]
            ),
            "local tag",
        )
        if local_tag_sha != candidate:
            fail(
                "local_tag_mismatch",
                f"Local tag {tag} does not point to the release candidate.",
                "Choose a new version tag on the exact candidate; never move an existing tag.",
                tag_sha=local_tag_sha,
                head_sha=candidate,
            )
        remote_tag = matching_remote_tag(api, repository, tag)
        if remote_tag is not None:
            remote_tag_sha = peel_remote_tag(api, repository, remote_tag)
            code = "remote_tag_mismatch" if remote_tag_sha != candidate else "remote_tag_exists"
            fail(
                code,
                f"Remote tag {tag} already exists at {remote_tag_sha}.",
                "Choose a new patch version; never move or replace a published tag.",
                tag_sha=remote_tag_sha,
                head_sha=candidate,
            )
    config = candidate_config(api, repository, candidate)
    catalog = workflow_catalog(api, repository)
    result["publication_artifacts"] = verify_publication_readiness(
        api, repository, candidate, catalog
    )
    result["workflow_runs"] = verify_workflows(
        api,
        repository,
        default_branch,
        candidate,
        config=config,
        catalog=catalog,
    )
    result["checks"] = [
        "working_tree_clean",
        "actual_default_branch",
        "exact_remote_head",
        "default_branch_ancestry",
        "release_workflow_active",
        "publication_helper_present",
        "exact_workflow_runs",
        "successful_jobs",
    ]
    if args.tag is not None:
        result["checks"].extend(["local_tag_matches_candidate", "remote_tag_absent"])
    result["next_action"] = (
        f"Push tag {args.tag} without moving it."
        if args.tag is not None
        else "Review the release contents and version before requesting publication approval."
    )


def publish_preflight(args: argparse.Namespace, result: dict) -> None:
    repository = validate_repository(args.repo)
    tag = validate_tag(args.tag)
    if args.candidate is not None:
        require_sha(args.candidate, "command arguments", "candidate")
    api = GitHubApi()
    repository, default_branch, default_sha = remote_metadata(api, repository)
    result["repository"] = repository
    result["default_branch"] = default_branch
    result["default_branch_sha"] = default_sha
    result["tag"] = tag
    tag_ref = matching_remote_tag(api, repository, tag)
    if tag_ref is None:
        fail(
            "remote_tag_missing",
            f"Remote tag {tag} does not exist.",
            "Push the verified immutable tag before publishing a GitHub release.",
        )
    candidate = peel_remote_tag(api, repository, tag_ref)
    result["candidate_sha"] = candidate
    if args.candidate is not None and args.candidate != candidate:
        fail(
            "tag_candidate_changed",
            f"Remote tag {tag} no longer resolves to the expected candidate.",
            "Stop publication and inspect the tag; create a new patch tag instead of moving it.",
            expected_sha=args.candidate,
            actual_sha=candidate,
        )
    verify_ancestry(api, repository, candidate, default_sha)
    result["workflow_runs"] = verify_workflows(api, repository, default_branch, candidate)
    result["checks"] = [
        "remote_tag_matches_candidate",
        "default_branch_ancestry",
        "exact_workflow_runs",
        "successful_jobs",
    ]
    result["next_action"] = f"Publish GitHub release {tag} for exact commit {candidate}."


def verify_release(args: argparse.Namespace, result: dict) -> None:
    repository = validate_repository(args.repo)
    tag = validate_tag(args.tag)
    if args.candidate is not None:
        require_sha(args.candidate, "command arguments", "candidate")
    api = GitHubApi()
    repository, default_branch, default_sha = remote_metadata(api, repository)
    result["repository"] = repository
    result["default_branch"] = default_branch
    result["default_branch_sha"] = default_sha
    result["tag"] = tag
    tag_ref = matching_remote_tag(api, repository, tag)
    if tag_ref is None:
        fail(
            "remote_tag_missing",
            f"Remote tag {tag} does not exist.",
            "Inspect the tag push and rerun exact release verification.",
        )
    candidate = peel_remote_tag(api, repository, tag_ref)
    result["candidate_sha"] = candidate
    if args.candidate is not None and args.candidate != candidate:
        fail(
            "tag_candidate_changed",
            f"Remote tag {tag} no longer resolves to the expected candidate.",
            "Stop and inspect the tag; create a new patch tag instead of moving it.",
            expected_sha=args.candidate,
            actual_sha=candidate,
        )
    verify_ancestry(api, repository, candidate, default_sha)
    workflow_evidence = verify_workflows(api, repository, default_branch, candidate)
    catalog = workflow_catalog(api, repository)
    release_path = WORKFLOW_PATHS["release"]
    release_workflow = catalog.get(release_path)
    if release_workflow is None:
        fail(
            "workflow_missing",
            f"Required workflow {release_path} is not registered on GitHub.",
            "Restore the exact release workflow and rerun verification.",
            workflow="release",
            path=release_path,
        )
    workflow_evidence.append(
        verify_workflow(
            api,
            repository,
            tag,
            candidate,
            "release",
            release_path,
            release_workflow,
            filter_branch=False,
        )
    )
    endpoint = f"repos/{repository}/releases/tags/{quote(tag, safe='')}"
    release = require_dict(api.request(endpoint), endpoint)
    if (
        release.get("tag_name") != tag
        or release.get("draft") is not False
        or not isinstance(release.get("html_url"), str)
    ):
        incomplete(endpoint, "tag_name, draft state, or html_url is invalid")
    result["workflow_runs"] = workflow_evidence
    result["release"] = {
        "tag": tag,
        "head_sha": candidate,
        "url": release["html_url"],
    }
    result["checks"] = [
        "remote_tag_matches_candidate",
        "default_branch_ancestry",
        "exact_workflow_runs",
        "successful_jobs",
        "exact_release_run",
        "published_release",
    ]
    result["next_action"] = f"Release {tag} is verified at {release['html_url']}."


def build_parser() -> JsonArgumentParser:
    parser = JsonArgumentParser(add_help=False)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    local = subparsers.add_parser("local", add_help=False)
    local.add_argument("repository", nargs="?", default=".")
    local.add_argument("--repo")
    local.add_argument("--tag")
    local.add_argument("--candidate")
    publish = subparsers.add_parser("publish", add_help=False)
    publish.add_argument("--repo", required=True)
    publish.add_argument("--tag", required=True)
    publish.add_argument("--candidate")
    verify = subparsers.add_parser("verify-release", add_help=False)
    verify.add_argument("--repo", required=True)
    verify.add_argument("--tag", required=True)
    verify.add_argument("--candidate")
    return parser


def main(argv: list[str] | None = None) -> int:
    result = {
        "ok": False,
        "mode": None,
        "repository": None,
        "default_branch": None,
        "default_branch_sha": None,
        "candidate_sha": None,
        "tag": None,
        "checks": [],
        "workflow_runs": [],
        "publication_artifacts": {},
        "errors": [],
        "next_action": "Rerun release preflight after resolving the reported blocker.",
    }
    try:
        args = build_parser().parse_args(argv)
        result["mode"] = args.mode
        if args.mode == "local":
            local_preflight(args, result)
        elif args.mode == "publish":
            publish_preflight(args, result)
        else:
            verify_release(args, result)
        result["ok"] = True
    except PreflightFailure as error:
        result["errors"].append({"code": error.code, "message": error.message, **error.details})
        result["next_action"] = error.next_action
    except Exception:
        result["errors"].append(
            {
                "code": "internal_error",
                "message": "Release evidence could not be verified because the helper failed.",
            }
        )
        result["next_action"] = "Inspect the helper failure and rerun; do not publish meanwhile."
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
