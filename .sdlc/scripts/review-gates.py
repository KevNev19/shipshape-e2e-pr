#!/usr/bin/env python3
"""Fail-closed GitHub review gates for Shipshape-managed automation.

The module reads pull-request state only through GitHub APIs. It never checks
out, imports, installs, or executes candidate content. Automatic merging is an
immediate REST request bound to the verified head SHA; no authorization is
stored for a later head. Stdout is one JSON object so workflows and doctor can
consume the same decision surface.
"""

# managed-by: shipshape v0.2.1

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass
from datetime import datetime

API_PAGE_SIZE = 100
MAX_ITEMS = 3000
GITHUB_ACTIONS_APP_ID = 15368
CODEQL_APP_ID = 57789
RULESET_NAME = "Shipshape automatic merge safety"
BASELINE_RULESET_NAME = "Shipshape branch protection"
TRUNK_RULE_TYPES = ("deletion", "non_fast_forward")
CONFIG_PATH = ".sdlc/config.json"
SHA_RE = re.compile(r"[0-9a-f]{40}")
REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
CODEQL_LANGUAGES = {"python", "node", "go", "java", "ruby", "csharp"}
MAX_TRUSTED_BLOB_SIZE = 1_000_000

ROOT_DOCUMENTS = {
    "CHANGELOG.md",
    "README.md",
}
# Fixed support boundary: root README/changelog files and prose below
# docs/guides/. Paths only bound automatic authority; they do not prove content
# semantics. Every other documentation location requires human review.
ORDINARY_DOCUMENT_PREFIXES = ("docs/guides/",)
DOCUMENT_SUFFIXES = {".adoc", ".asciidoc", ".markdown", ".md", ".rst", ".txt"}
SENSITIVE_WORDS = {
    "adr",
    "adrs",
    "agent",
    "agents",
    "architecture",
    "architectures",
    "compliance",
    "conduct",
    "contributing",
    "control",
    "controls",
    "copyright",
    "decision",
    "decisions",
    "governance",
    "guideline",
    "guidelines",
    "harness",
    "legal",
    "licence",
    "license",
    "licensing",
    "notice",
    "policy",
    "policies",
    "privacy",
    "procedure",
    "procedures",
    "process",
    "runbook",
    "runbooks",
    "review",
    "reviews",
    "rfc",
    "rfcs",
    "sdlc",
    "security",
    "skill",
    "skills",
    "support",
    "terms",
}


class GateError(RuntimeError):
    """The API evidence cannot prove that an immediate merge is safe."""


@dataclass(frozen=True)
class GateSpec:
    context: str
    app_id: int
    workflow_path: str
    workflow_name: str
    event: str
    job_name: str


BASE_GATES = (
    GateSpec(
        "test",
        GITHUB_ACTIONS_APP_ID,
        ".github/workflows/ci.yml",
        "CI",
        "pull_request",
        "test",
    ),
    GateSpec(
        "secret-scan",
        GITHUB_ACTIONS_APP_ID,
        ".github/workflows/secret-scan.yml",
        "Secret scan",
        "pull_request_target",
        "secret-scan",
    ),
)
CODEQL_GATE = GateSpec(
    "CodeQL",
    CODEQL_APP_ID,
    ".github/workflows/codeql.yml",
    "CodeQL",
    "pull_request",
    "analyze",
)

AUTO_MERGE_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      id
      autoMergeRequest { enabledBy { login } }
    }
  }
}
"""


class GitHubClient:
    """Small JSON-only adapter over ``gh api``."""

    def _call(self, arguments: list[str], payload: dict | None = None):
        try:
            process = subprocess.run(
                [
                    "gh",
                    "api",
                    "-H",
                    "Accept: application/vnd.github+json",
                    "-H",
                    "X-GitHub-Api-Version: 2022-11-28",
                    *arguments,
                ],
                input=json.dumps(payload) if payload is not None else None,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise GateError("GitHub API command was unavailable or timed out") from error
        if process.returncode != 0:
            detail = process.stderr.strip() or "GitHub API request failed"
            raise GateError(detail)
        try:
            return json.loads(process.stdout)
        except json.JSONDecodeError as error:
            raise GateError("GitHub API returned malformed JSON") from error

    def get(self, path: str):
        return self._call([path])

    def graphql(self, query: str, variables: dict):
        return self._call(["graphql", "--input", "-"], {"query": query, "variables": variables})

    def put(self, path: str, payload: dict):
        return self._call(["--method", "PUT", path, "--input", "-"], payload)


def _require_dict(value, label: str) -> dict:
    if not isinstance(value, dict):
        raise GateError(f"{label} was malformed")
    return value


def _require_sha(value, label: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise GateError(f"{label} was not an exact commit SHA")
    return value


def _require_repo(repo: str) -> tuple[str, str]:
    if not isinstance(repo, str) or REPO_RE.fullmatch(repo) is None:
        raise GateError("repository must be an exact owner/name slug")
    owner, name = repo.split("/", 1)
    return owner, name


def required_gates(codeql_enabled: bool) -> tuple[GateSpec, ...]:
    """Return the exact source-bound checks in the Shipshape ruleset contract."""
    return BASE_GATES + ((CODEQL_GATE,) if codeql_enabled else ())


def derive_protection_request(config: dict, workflow_paths: set[str]) -> dict:
    """Derive one exact, JSON-safe remote inspection request from local state."""
    if not isinstance(config, dict):
        raise GateError("protection configuration was not a JSON object")
    features = config.get("features")
    if not isinstance(features, dict) or any(
        not isinstance(key, str) or type(value) is not bool for key, value in features.items()
    ):
        raise GateError("protection configuration feature flags were malformed")
    required_features = ("branch_protection", "tiered_review", "codeql", "secret_guard")
    if any(feature not in features for feature in required_features):
        raise GateError("protection configuration feature flags were incomplete")

    workflow_style = config.get("workflow_style")
    if workflow_style not in {"trunk", "pr"} or not isinstance(workflow_style, str):
        raise GateError("protection workflow style must be exactly 'trunk' or 'pr'")
    branch = config.get("default_branch")
    if (
        not isinstance(branch, str)
        or not branch
        or branch.startswith("refs/")
        or any(character in branch for character in "\x00\r\n")
    ):
        raise GateError("protection default branch was malformed")
    languages = config.get("languages")
    if (
        not isinstance(languages, list)
        or not all(
            isinstance(language, str)
            and language
            and language == language.strip()
            and language == language.lower()
            for language in languages
        )
        or len(languages) != len(set(languages))
    ):
        raise GateError("protection languages were malformed")
    if type(workflow_paths) is not set or not all(
        isinstance(path, str) and path for path in workflow_paths
    ):
        raise GateError("available workflow paths were malformed")

    requested = features["branch_protection"]
    tiered_review = features["tiered_review"]
    if tiered_review and (
        not requested or workflow_style != "pr" or features["secret_guard"] is not True
    ):
        raise GateError("tiered review requires PR-style branch protection and the secret guard")
    repository = config.get("repo")
    if not isinstance(repository, dict):
        raise GateError("protection repository metadata was malformed")
    owner_repo = repository.get("owner_repo")
    if requested:
        _require_repo(owner_repo)
    elif not isinstance(owner_repo, str):
        raise GateError("protection repository metadata was malformed")

    primary_language = languages[0] if languages else "none"
    codeql_enabled = features["codeql"] and primary_language in CODEQL_LANGUAGES
    if codeql_enabled and CODEQL_GATE.workflow_path not in workflow_paths:
        raise GateError("configured applicable CodeQL workflow was missing")

    gates = ()
    required_rule_types = []
    ruleset_name = None
    if requested and workflow_style == "trunk":
        required_rule_types = list(TRUNK_RULE_TYPES)
        ruleset_name = BASELINE_RULESET_NAME
    elif requested:
        gates = required_gates(codeql_enabled) if tiered_review else (BASE_GATES[0],)
        if codeql_enabled and not tiered_review:
            gates += (CODEQL_GATE,)
        missing = [gate.workflow_path for gate in gates if gate.workflow_path not in workflow_paths]
        if missing:
            raise GateError(f"required protection workflow was missing: {missing[0]}")
        required_rule_types = ["required_status_checks"]
        ruleset_name = RULESET_NAME if tiered_review else BASELINE_RULESET_NAME

    return {
        "requested": requested,
        "repo": owner_repo,
        "branch": branch,
        "workflow_style": workflow_style,
        "tiered_review": tiered_review,
        "codeql_enabled": codeql_enabled,
        "ruleset_name": ruleset_name,
        "required_checks": [
            {"context": gate.context, "integration_id": gate.app_id} for gate in gates
        ],
        "required_rule_types": required_rule_types,
    }


def _path_with_page(path: str, page: int) -> str:
    separator = "&" if "?" in path else "?"
    return f"{path}{separator}per_page={API_PAGE_SIZE}&page={page}"


def _list_pages(api, path: str, label: str, *, allow_empty: bool = False) -> list:
    items = []
    for page in range(1, MAX_ITEMS // API_PAGE_SIZE + 2):
        payload = api.get(_path_with_page(path, page))
        if not isinstance(payload, list) or len(payload) > API_PAGE_SIZE:
            raise GateError(f"{label} pagination was malformed")
        if not payload:
            break
        items.extend(payload)
        if len(items) > MAX_ITEMS:
            raise GateError(f"{label} exceeded the inspection limit")
        if len(payload) < API_PAGE_SIZE:
            break
    else:
        raise GateError(f"{label} pagination did not terminate")
    if not items and not allow_empty:
        raise GateError(f"{label} was empty")
    return items


def _object_pages(api, path: str, key: str, label: str) -> list[dict]:
    items = []
    expected_total = None
    for page in range(1, MAX_ITEMS // API_PAGE_SIZE + 2):
        payload = _require_dict(api.get(_path_with_page(path, page)), label)
        batch = payload.get(key)
        total = payload.get("total_count")
        if (
            not isinstance(batch, list)
            or len(batch) > API_PAGE_SIZE
            or type(total) is not int
            or total < 0
        ):
            raise GateError(f"{label} pagination was malformed")
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise GateError(f"{label} total changed during pagination")
        items.extend(batch)
        if len(items) > MAX_ITEMS or len(items) > total:
            raise GateError(f"{label} pagination was inconsistent")
        if not batch or len(batch) < API_PAGE_SIZE:
            break
    else:
        raise GateError(f"{label} pagination did not terminate")
    if not items or len(items) != expected_total:
        raise GateError(f"{label} was empty or truncated")
    if not all(isinstance(item, dict) for item in items):
        raise GateError(f"{label} contained malformed records")
    return items


def _repository_snapshot(api, repo: str) -> dict:
    repository = _require_dict(api.get(f"repos/{repo}"), "repository")
    if (
        repository.get("full_name") != repo
        or type(repository.get("id")) is not int
        or repository["id"] <= 0
        or not isinstance(repository.get("name"), str)
        or not repository["name"]
        or not isinstance(repository.get("url"), str)
        or not repository["url"]
        or not isinstance(repository.get("default_branch"), str)
        or not repository["default_branch"]
    ):
        raise GateError("repository identity or default branch was malformed")
    return {
        "id": repository["id"],
        "name": repository["name"],
        "url": repository["url"],
        "default_branch": repository["default_branch"],
    }


def _pull_snapshot(api, repo: str, number: int) -> dict:
    pull = _require_dict(api.get(f"repos/{repo}/pulls/{number}"), "pull request")
    head = _require_dict(pull.get("head"), "pull request head")
    base = _require_dict(pull.get("base"), "pull request base")
    head_repo = _require_dict(head.get("repo"), "head repository")
    base_repo = _require_dict(base.get("repo"), "base repository")
    pull_id = pull.get("id")
    pull_url = pull.get("url")
    if (
        pull.get("number") != number
        or type(pull_id) is not int
        or pull_id <= 0
        or not isinstance(pull_url, str)
        or not pull_url
        or not isinstance(pull.get("state"), str)
    ):
        raise GateError("pull request identity or state was malformed")
    if not isinstance(pull.get("draft"), bool):
        raise GateError("pull request draft state was malformed")
    if base_repo.get("full_name") != repo:
        raise GateError("pull request targets a different repository")
    if not isinstance(head_repo.get("full_name"), str) or not head_repo["full_name"]:
        raise GateError("head repository identity was unavailable")
    for label, repository in (("head", head_repo), ("base", base_repo)):
        if (
            type(repository.get("id")) is not int
            or repository["id"] <= 0
            or not isinstance(repository.get("name"), str)
            or not repository["name"]
            or not isinstance(repository.get("url"), str)
            or not repository["url"]
        ):
            raise GateError(f"{label} repository identity was unavailable")
    if not isinstance(head.get("ref"), str) or not head["ref"]:
        raise GateError("head branch was unavailable")
    if not isinstance(base.get("ref"), str) or not base["ref"]:
        raise GateError("base branch was unavailable")
    if type(pull.get("changed_files")) is not int or not 0 < pull["changed_files"] <= MAX_ITEMS:
        raise GateError("changed-file count was empty or outside the inspection limit")
    return {
        "pull_id": pull_id,
        "pull_url": pull_url,
        "head_sha": _require_sha(head.get("sha"), "pull request head"),
        "head_ref": head["ref"],
        "head_repo": head_repo["full_name"],
        "head_repo_id": head_repo["id"],
        "head_repo_name": head_repo["name"],
        "head_repo_url": head_repo["url"],
        "base_sha": _require_sha(base.get("sha"), "pull request base"),
        "base_ref": base["ref"],
        "base_repo_id": base_repo["id"],
        "base_repo_name": base_repo["name"],
        "base_repo_url": base_repo["url"],
        "changed_files": pull["changed_files"],
        "merge_commit_sha": _require_sha(
            pull.get("merge_commit_sha"), "pull request merge candidate"
        ),
        "mergeable": pull.get("mergeable"),
        "mergeable_state": pull.get("mergeable_state"),
        "state": pull["state"],
        "draft": pull["draft"],
    }


def _same_candidate(first: dict, second: dict) -> bool:
    keys = (
        "pull_id",
        "pull_url",
        "head_sha",
        "head_ref",
        "head_repo",
        "head_repo_id",
        "head_repo_url",
        "base_sha",
        "base_ref",
        "base_repo_id",
        "base_repo_url",
        "merge_commit_sha",
    )
    return all(first[key] == second[key] for key in keys)


def _persistent_auto_merge_actor(api, repo: str, number: int) -> str | None:
    owner, name = _require_repo(repo)
    payload = _require_dict(
        api.graphql(AUTO_MERGE_QUERY, {"owner": owner, "name": name, "number": number}),
        "auto-merge state",
    )
    errors = payload.get("errors", [])
    if not isinstance(errors, list):
        raise GateError("auto-merge GraphQL errors were malformed")
    if errors:
        raise GateError("auto-merge GraphQL errors made persistent state unknown")
    data = _require_dict(payload.get("data"), "auto-merge data")
    repository = _require_dict(data.get("repository"), "auto-merge repository")
    pull = _require_dict(repository.get("pullRequest"), "auto-merge pull request")
    pull_id = pull.get("id")
    request = pull.get("autoMergeRequest")
    if not isinstance(pull_id, str) or not pull_id:
        raise GateError("pull request node identity was unavailable")
    if request is None:
        return None
    request = _require_dict(request, "auto-merge request")
    enabled_by = _require_dict(request.get("enabledBy"), "auto-merge actor")
    login = enabled_by.get("login")
    if not isinstance(login, str) or not login:
        raise GateError("auto-merge actor identity was unavailable")
    return login


def _tree(api, repo: str, commit_sha: str) -> dict[str, dict]:
    commit = _require_dict(api.get(f"repos/{repo}/git/commits/{commit_sha}"), "git commit")
    if _require_sha(commit.get("sha"), "git commit") != commit_sha:
        raise GateError("git commit response did not match the requested SHA")
    tree_ref = _require_dict(commit.get("tree"), "git commit tree")
    tree_sha = _require_sha(tree_ref.get("sha"), "git tree")
    payload = _require_dict(
        api.get(f"repos/{repo}/git/trees/{tree_sha}?recursive=1"), "recursive git tree"
    )
    if payload.get("truncated") is not False or not isinstance(payload.get("tree"), list):
        raise GateError("recursive git tree was malformed or truncated")
    entries = {}
    for item in payload["tree"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise GateError("recursive git tree contained a malformed entry")
        path = item["path"]
        if not path or path in entries:
            raise GateError("recursive git tree contained an empty or duplicate path")
        entries[path] = item
    if not entries:
        raise GateError("recursive git tree was empty")
    return entries


def _path_words(path: str) -> set[str]:
    words = set()
    for component in path.split("/"):
        words.update(word for word in re.split(r"[^a-z0-9]+", component.lower()) if word)
    return words


def is_ordinary_document(path: str) -> bool:
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        return False
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    if any(part.startswith(".") for part in parts):
        return False
    if _path_words(path) & SENSITIVE_WORDS:
        return False
    if len(parts) == 1:
        return path in ROOT_DOCUMENTS
    if not any(path.startswith(prefix) for prefix in ORDINARY_DOCUMENT_PREFIXES):
        return False
    suffix = "." + parts[-1].rsplit(".", 1)[-1].lower() if "." in parts[-1] else ""
    return suffix in DOCUMENT_SUFFIXES


def _regular_blob(tree: dict[str, dict], path: str) -> bool:
    item = tree.get(path)
    return (
        isinstance(item, dict)
        and item.get("type") == "blob"
        and item.get("mode") == "100644"
        and isinstance(item.get("sha"), str)
        and SHA_RE.fullmatch(item["sha"]) is not None
    )


def _decode_trusted_blob(api, repo: str, tree: dict[str, dict], path: str, label: str) -> bytes:
    if not _regular_blob(tree, path):
        raise GateError(f"trusted {label} was missing or not a regular non-executable blob")
    blob_sha = tree[path]["sha"]
    payload = _require_dict(api.get(f"repos/{repo}/git/blobs/{blob_sha}"), label)
    encoded = payload.get("content")
    if not isinstance(encoded, str):
        raise GateError(f"trusted {label} response was malformed")
    normalized = encoded.replace("\r", "").replace("\n", "")
    try:
        content = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as error:
        raise GateError(f"trusted {label} response was malformed") from error
    identity = hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()
    if (
        payload.get("encoding") != "base64"
        or payload.get("sha") != blob_sha
        or payload.get("size") != len(content)
        or identity != blob_sha
        or len(content) > MAX_TRUSTED_BLOB_SIZE
    ):
        raise GateError(f"trusted {label} identity was malformed")
    return content


def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _trusted_automation_config(api, repo: str, base_tree: dict[str, dict]) -> dict:
    content = _decode_trusted_blob(api, repo, base_tree, CONFIG_PATH, "configuration")
    try:
        config = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise GateError("trusted configuration was not valid UTF-8 JSON") from error
    if not isinstance(config, dict):
        raise GateError("trusted configuration was not a JSON object")
    features = config.get("features")
    languages = config.get("languages")
    if not isinstance(features, dict):
        raise GateError("trusted configuration features were malformed")
    if config.get("workflow_style") != "pr" or features.get("tiered_review") is not True:
        raise GateError("trusted configuration does not opt in to PR-style tiered review")
    if features.get("secret_guard") is not True:
        raise GateError("trusted configuration does not enable the secret guard")
    if not isinstance(features.get("codeql"), bool):
        raise GateError("trusted configuration CodeQL setting was malformed")
    if (
        not isinstance(languages, list)
        or not all(isinstance(language, str) and language for language in languages)
        or len(languages) != len(set(languages))
    ):
        raise GateError("trusted configuration languages were malformed")
    primary_language = languages[0] if languages else "none"
    return {
        "codeql_applicable": (features["codeql"] is True and primary_language in CODEQL_LANGUAGES),
        "primary_language": primary_language,
    }


def classify_documentation(files: list, base_tree: dict, head_tree: dict) -> tuple[str, str]:
    if not files or not all(isinstance(item, dict) for item in files):
        return "none", "changed-file metadata was empty or malformed"
    seen = set()
    for item in files:
        path = item.get("filename")
        status = item.get("status")
        previous = item.get("previous_filename")
        if not isinstance(path, str) or path in seen:
            return "none", "changed-file metadata had an empty or duplicate path"
        seen.add(path)
        if status not in {"added", "modified", "removed", "renamed"}:
            return "none", "a file had an unsupported change status"
        if status == "renamed":
            if not isinstance(previous, str) or previous in seen:
                return "none", "a rename lacked a distinct previous filename"
            seen.add(previous)
        elif previous is not None:
            return "none", "a non-rename unexpectedly had a previous filename"
        paths = [path] + ([previous] if status == "renamed" else [])
        if not all(is_ordinary_document(candidate) for candidate in paths):
            return (
                "none",
                "a changed or previous path was outside the fixed ordinary-document "
                "allowlist or used a reserved policy/control name; request human review",
            )
        if status in {"modified", "removed"} and not _regular_blob(base_tree, path):
            return "none", "a base path was missing or not a regular non-executable blob"
        if status in {"added", "modified", "renamed"} and not _regular_blob(head_tree, path):
            return "none", "a head path was missing or not a regular non-executable blob"
        if status == "renamed" and not _regular_blob(base_tree, previous):
            return "none", "a previous path was missing or not a regular non-executable blob"
    return (
        "docs-only",
        "paths and modes match the supported documentation allowlist; "
        "content semantics were not assessed",
    )


def _ruleset_contract(
    api,
    repo: str,
    branch: str,
    gates: tuple[GateSpec, ...],
    *,
    ruleset_name: str = RULESET_NAME,
) -> int:
    encoded_branch = urllib.parse.quote(branch, safe="")
    active = _list_pages(
        api,
        f"repos/{repo}/rules/branches/{encoded_branch}",
        "active branch rules",
    )
    ruleset_ids = set()
    for rule in active:
        if not isinstance(rule, dict):
            raise GateError("active branch rules contained malformed records")
        if rule.get("type") != "required_status_checks":
            continue
        ruleset_id = rule.get("ruleset_id")
        if type(ruleset_id) is not int or ruleset_id <= 0:
            raise GateError("an active required-check rule lacked a ruleset identity")
        ruleset_ids.add(ruleset_id)
    if not ruleset_ids:
        raise GateError("no active source-bound required-check ruleset was found")

    matches = []
    for ruleset_id in sorted(ruleset_ids):
        ruleset = _require_dict(
            api.get(f"repos/{repo}/rulesets/{ruleset_id}"), "repository ruleset"
        )
        if ruleset.get("name") != ruleset_name:
            continue
        matches.append((ruleset_id, ruleset))
    if len(matches) != 1:
        raise GateError("the active Shipshape ruleset was missing or ambiguous")
    ruleset_id, ruleset = matches[0]
    if (
        ruleset.get("id") != ruleset_id
        or ruleset.get("target") != "branch"
        or ruleset.get("source_type") != "Repository"
        or ruleset.get("source") != repo
        or ruleset.get("enforcement") != "active"
        or ruleset.get("current_user_can_bypass") != "never"
        or not isinstance(ruleset.get("rules"), list)
    ):
        raise GateError("the Shipshape ruleset was disabled, bypassable, or malformed")
    if not all(isinstance(rule, dict) for rule in ruleset["rules"]):
        raise GateError("the Shipshape ruleset contained a malformed rule")
    required_rules = [
        rule for rule in ruleset["rules"] if rule.get("type") == "required_status_checks"
    ]
    if len(required_rules) != 1:
        raise GateError("the Shipshape ruleset required-check rule was missing or ambiguous")
    parameters = _require_dict(required_rules[0].get("parameters"), "required-check parameters")
    checks = parameters.get("required_status_checks")
    if (
        parameters.get("strict_required_status_checks_policy") is not True
        or parameters.get("do_not_enforce_on_create") is not False
        or not isinstance(checks, list)
        or not checks
    ):
        raise GateError("the Shipshape ruleset was not strict or was malformed")
    actual = []
    for check in checks:
        if not isinstance(check, dict):
            raise GateError("a required check was malformed")
        context = check.get("context")
        integration_id = check.get("integration_id")
        if (
            not isinstance(context, str)
            or not context
            or any(character in context for character in "*?[")
            or type(integration_id) is not int
            or integration_id <= 0
        ):
            raise GateError("a required check was wildcarded or not source-bound")
        actual.append((context, integration_id))
    expected = [(gate.context, gate.app_id) for gate in gates]
    if len(set(actual)) != len(actual) or not set(expected).issubset(set(actual)):
        raise GateError("the Shipshape ruleset did not require every expected source")
    return ruleset_id


def _ruleset_rule_types_contract(
    api, repo: str, branch: str, ruleset_name: str, required_types: tuple[str, ...]
) -> int:
    encoded_branch = urllib.parse.quote(branch, safe="")
    active = _list_pages(
        api,
        f"repos/{repo}/rules/branches/{encoded_branch}",
        "active branch rules",
    )
    active_types_by_ruleset = {}
    for rule in active:
        if not isinstance(rule, dict):
            raise GateError("active branch rules contained malformed records")
        if rule.get("type") not in required_types:
            continue
        ruleset_id = rule.get("ruleset_id")
        if type(ruleset_id) is not int or ruleset_id <= 0:
            raise GateError("an active safeguard rule lacked a ruleset identity")
        active_types_by_ruleset.setdefault(ruleset_id, set()).add(rule["type"])
    candidate_ids = [
        ruleset_id
        for ruleset_id, active_types in active_types_by_ruleset.items()
        if set(required_types).issubset(active_types)
    ]
    matches = []
    for ruleset_id in sorted(candidate_ids):
        ruleset = _require_dict(
            api.get(f"repos/{repo}/rulesets/{ruleset_id}"), "repository ruleset"
        )
        if ruleset.get("name") == ruleset_name:
            matches.append((ruleset_id, ruleset))
    if len(matches) != 1:
        raise GateError("the active Shipshape safeguard ruleset was missing or ambiguous")
    ruleset_id, ruleset = matches[0]
    if (
        ruleset.get("id") != ruleset_id
        or ruleset.get("target") != "branch"
        or ruleset.get("source_type") != "Repository"
        or ruleset.get("source") != repo
        or ruleset.get("enforcement") != "active"
        or ruleset.get("current_user_can_bypass") != "never"
        or not isinstance(ruleset.get("rules"), list)
        or not all(isinstance(rule, dict) for rule in ruleset["rules"])
    ):
        raise GateError("the Shipshape safeguard ruleset was disabled, bypassable, or malformed")
    actual_types = {rule.get("type") for rule in ruleset["rules"]}
    if not set(required_types).issubset(actual_types):
        raise GateError("the Shipshape safeguard ruleset omitted a required rule")
    return ruleset_id


def inspect_protection(api, repo: str, branch: str, codeql_enabled: bool) -> dict:
    """Return JSON-safe proof for doctor without changing repository protection."""
    gates = required_gates(codeql_enabled)
    result = {
        "ok": False,
        "ruleset_name": RULESET_NAME,
        "ruleset_id": None,
        "required_checks": [
            {"context": gate.context, "integration_id": gate.app_id} for gate in gates
        ],
        "reason": "protection inspection did not complete",
    }
    try:
        _require_repo(repo)
        if not isinstance(branch, str) or not branch:
            raise GateError("target branch was unavailable")
        result["ruleset_id"] = _ruleset_contract(api, repo, branch, gates)
        result["ok"] = True
        result["reason"] = "strict source-bound required checks are active"
    except GateError as error:
        result["reason"] = str(error)
    return result


def inspect_configured_protection(api, config: dict, workflow_paths: set[str]) -> dict:
    """Derive and inspect every configured protection mode without mutation."""
    result = {
        "ok": False,
        "requested": None,
        "request": None,
        "ruleset_id": None,
        "reason": "configured protection inspection did not complete",
    }
    try:
        request = derive_protection_request(config, workflow_paths)
        result["requested"] = request["requested"]
        result["request"] = request
        if not request["requested"]:
            result["ok"] = True
            result["reason"] = "remote branch protection is not requested by configuration"
            return result
        if request["workflow_style"] == "trunk":
            result["ruleset_id"] = _ruleset_rule_types_contract(
                api,
                request["repo"],
                request["branch"],
                request["ruleset_name"],
                tuple(request["required_rule_types"]),
            )
            result["reason"] = "deletion and non-fast-forward safeguards are active"
        else:
            gates = required_gates(request["codeql_enabled"])
            if not request["tiered_review"]:
                gates = (BASE_GATES[0],) + ((CODEQL_GATE,) if request["codeql_enabled"] else ())
            result["ruleset_id"] = _ruleset_contract(
                api,
                request["repo"],
                request["branch"],
                gates,
                ruleset_name=request["ruleset_name"],
            )
            result["reason"] = "strict source-bound required checks are active"
        result["ok"] = True
    except GateError as error:
        result["reason"] = str(error)
    return result


def _pull_link_matches(run: dict, snapshot: dict, number: int) -> bool:
    pulls = run.get("pull_requests")
    if not isinstance(pulls, list) or len(pulls) != 1:
        return False
    pull = pulls[0]
    if (
        not isinstance(pull, dict)
        or pull.get("id") != snapshot["pull_id"]
        or pull.get("number") != number
        or pull.get("url") != snapshot["pull_url"]
    ):
        return False
    head = pull.get("head")
    base = pull.get("base")
    head_repo = head.get("repo") if isinstance(head, dict) else None
    base_repo = base.get("repo") if isinstance(base, dict) else None
    return (
        isinstance(head, dict)
        and isinstance(base, dict)
        and isinstance(head_repo, dict)
        and isinstance(base_repo, dict)
        and head.get("sha") == snapshot["head_sha"]
        and head.get("ref") == snapshot["head_ref"]
        and head_repo.get("id") == snapshot["head_repo_id"]
        and head_repo.get("name") == snapshot["head_repo_name"]
        and head_repo.get("url") == snapshot["head_repo_url"]
        and base.get("sha") == snapshot["base_sha"]
        and base.get("ref") == snapshot["base_ref"]
        and base_repo.get("id") == snapshot["base_repo_id"]
        and base_repo.get("name") == snapshot["base_repo_name"]
        and base_repo.get("url") == snapshot["base_repo_url"]
    )


def _validate_run_identity(
    api, run: dict, repo: str, number: int, snapshot: dict, spec: GateSpec
) -> None:
    repository = run.get("repository")
    if (
        type(run.get("id")) is not int
        or run["id"] <= 0
        or type(run.get("workflow_id")) is not int
        or run["workflow_id"] <= 0
        or run.get("head_sha") != snapshot["head_sha"]
        or run.get("event") != spec.event
        # Captured REST runs use bare workflow paths. Ref-suffixed or other
        # variants remain unsupported because their binding is unproven.
        or run.get("path") != spec.workflow_path
        or not isinstance(repository, dict)
        or repository.get("full_name") != repo
        or repository.get("id") != snapshot["base_repo_id"]
        or repository.get("name") != snapshot["base_repo_name"]
        or repository.get("url") != snapshot["base_repo_url"]
        or not _pull_link_matches(run, snapshot, number)
    ):
        raise GateError(f"{spec.context} workflow run was not bound to this pull request")
    workflow = _require_dict(
        api.get(f"repos/{repo}/actions/workflows/{run['workflow_id']}"),
        f"{spec.context} workflow",
    )
    if (
        workflow.get("id") != run["workflow_id"]
        or workflow.get("name") != spec.workflow_name
        or workflow.get("path") != spec.workflow_path
        or workflow.get("state") != "active"
    ):
        raise GateError(f"{spec.context} workflow identity was not trusted")


def _run_started_at(run: dict, spec: GateSpec) -> datetime:
    value = run.get("run_started_at")
    if not isinstance(value, str):
        raise GateError(f"{spec.context} workflow run chronology was malformed")
    try:
        started_at = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise GateError(f"{spec.context} workflow run chronology was malformed") from error
    if (
        started_at.strftime("%Y-%m-%dT%H:%M:%SZ") != value
        or type(run.get("run_attempt")) is not int
        or run["run_attempt"] < 1
        or type(run.get("check_suite_id")) is not int
        or run["check_suite_id"] <= 0
        or not isinstance(run.get("status"), str)
        or not run["status"]
        or (
            run.get("conclusion") is not None
            and (not isinstance(run["conclusion"], str) or not run["conclusion"])
        )
    ):
        raise GateError(f"{spec.context} workflow run chronology was malformed")
    return started_at


def _latest_workflow_run(api, repo: str, number: int, snapshot: dict, spec: GateSpec) -> dict:
    workflow_file = urllib.parse.quote(spec.workflow_path.rsplit("/", 1)[-1], safe="")
    query = urllib.parse.urlencode({"event": spec.event, "head_sha": snapshot["head_sha"]})
    runs = _object_pages(
        api,
        f"repos/{repo}/actions/workflows/{workflow_file}/runs?{query}",
        "workflow_runs",
        f"{spec.context} workflow runs",
    )
    chronologies = {}
    seen_run_ids = set()
    for run in runs:
        _validate_run_identity(api, run, repo, number, snapshot, spec)
        if run["id"] in seen_run_ids:
            raise GateError(f"{spec.context} workflow run chronology was ambiguous")
        seen_run_ids.add(run["id"])
        started_at = _run_started_at(run, spec)
        if started_at in chronologies:
            raise GateError(f"{spec.context} workflow run chronology was ambiguous")
        chronologies[started_at] = run
    latest = chronologies[max(chronologies)]
    if latest.get("status") != "completed" or latest.get("conclusion") != "success":
        raise GateError(f"latest {spec.context} workflow run was not successful")
    return latest


def _verify_actions_job(api, repo: str, snapshot: dict, spec: GateSpec, run: dict) -> None:
    jobs = _object_pages(
        api,
        f"repos/{repo}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?filter=latest",
        "jobs",
        f"{spec.context} workflow jobs",
    )
    matches = [job for job in jobs if job.get("name") == spec.job_name]
    if len(matches) != 1:
        raise GateError(f"{spec.context} workflow job was missing or ambiguous")
    job = matches[0]
    check_url = job.get("check_run_url")
    check_id_match = (
        re.search(r"/check-runs/([0-9]+)$", check_url) if isinstance(check_url, str) else None
    )
    if (
        job.get("run_id") != run["id"]
        or job.get("head_sha") != snapshot["head_sha"]
        or job.get("status") != "completed"
        or job.get("conclusion") != "success"
        or check_id_match is None
    ):
        raise GateError(f"{spec.context} workflow job was not successful on the exact head")
    check_id = int(check_id_match.group(1))
    check = _require_dict(
        api.get(f"repos/{repo}/check-runs/{check_id}"), f"{spec.context} check run"
    )
    app = check.get("app")
    suite = check.get("check_suite")
    if (
        check.get("id") != check_id
        or check.get("name") != spec.job_name
        or check.get("head_sha") != snapshot["head_sha"]
        or check.get("status") != "completed"
        or check.get("conclusion") != "success"
        or not isinstance(app, dict)
        or app.get("id") != GITHUB_ACTIONS_APP_ID
        or not isinstance(suite, dict)
        or suite.get("id") != run["check_suite_id"]
    ):
        raise GateError(f"{spec.context} check run source or suite did not match")


def _verify_codeql_check(api, repo: str, snapshot: dict, spec: GateSpec) -> None:
    query = urllib.parse.urlencode({"check_name": spec.context, "filter": "latest"})
    checks = _object_pages(
        api,
        f"repos/{repo}/commits/{snapshot['head_sha']}/check-runs?{query}",
        "check_runs",
        "CodeQL check runs",
    )
    matches = [check for check in checks if check.get("name") == spec.context]
    if not matches:
        raise GateError("CodeQL check run was missing")
    if not all(type(check.get("id")) is int for check in matches):
        raise GateError("CodeQL check run identity was malformed")
    latest = max(matches, key=lambda check: check["id"])
    app = latest.get("app")
    suite = latest.get("check_suite")
    if (
        not isinstance(latest.get("id"), int)
        or latest.get("head_sha") != snapshot["head_sha"]
        or latest.get("status") != "completed"
        or latest.get("conclusion") != "success"
        or not isinstance(app, dict)
        or app.get("id") != CODEQL_APP_ID
        or not isinstance(suite, dict)
        or type(suite.get("id")) is not int
    ):
        raise GateError("latest CodeQL check was not successful from the expected app")
    suite_payload = _require_dict(
        api.get(f"repos/{repo}/check-suites/{suite['id']}"), "CodeQL check suite"
    )
    suite_app = suite_payload.get("app")
    if (
        suite_payload.get("id") != suite["id"]
        or suite_payload.get("head_sha") != snapshot["head_sha"]
        or not isinstance(suite_app, dict)
        or suite_app.get("id") != CODEQL_APP_ID
    ):
        raise GateError("CodeQL check suite was not bound to the exact head and app")


def _verify_checks(api, repo: str, number: int, snapshot: dict, gates: tuple[GateSpec, ...]):
    for spec in gates:
        run = _latest_workflow_run(api, repo, number, snapshot, spec)
        _verify_actions_job(api, repo, snapshot, spec, run)
        if spec is CODEQL_GATE:
            _verify_codeql_check(api, repo, snapshot, spec)


def _validate_wakeup(api, repo: str, number: int, snapshot: dict, run_id: int | None) -> bool:
    if run_id is None:
        return True
    run = _require_dict(api.get(f"repos/{repo}/actions/runs/{run_id}"), "wakeup workflow run")
    specs = [spec for spec in (*BASE_GATES, CODEQL_GATE) if run.get("path") == spec.workflow_path]
    if len(specs) != 1 or run.get("id") != run_id:
        raise GateError("workflow_run wakeup did not identify one trusted workflow")
    spec = specs[0]
    _validate_run_identity(api, run, repo, number, snapshot, spec)
    return run.get("status") == "completed" and run.get("conclusion") == "success"


def evaluate(
    api,
    repo: str,
    number: int,
    workflow_run_id: int | None = None,
    trusted_base_sha: str | None = None,
) -> dict:
    """Evaluate one PR and attempt one immediate, exact-head merge when proven safe."""
    result = {
        "ok": True,
        "eligible": False,
        "merged": False,
        "classification": "none",
        "head_sha": "",
        "base_sha": "",
        "ruleset_id": None,
        "persistent_auto_merge_present": False,
        "migration_action": None,
        "reason": "evaluation did not complete",
        "assurance": (
            "The REST merge is head-bound but not transactionally bound to the observed base. "
            "Strict source-bound rules are rechecked and GitHub enforces them at merge time."
        ),
    }
    try:
        _require_repo(repo)
        if type(number) is not int or number <= 0:
            raise GateError("pull request number must be positive")
        repository = _repository_snapshot(api, repo)
        snapshot = _pull_snapshot(api, repo, number)
        if (
            snapshot["base_ref"] != repository["default_branch"]
            or snapshot["base_repo_id"] != repository["id"]
            or snapshot["base_repo_name"] != repository["name"]
            or snapshot["base_repo_url"] != repository["url"]
        ):
            raise GateError("trusted policy base was not the repository default branch")
        result["head_sha"] = snapshot["head_sha"]
        result["base_sha"] = snapshot["base_sha"]
        wakeup_succeeded = _validate_wakeup(api, repo, number, snapshot, workflow_run_id)
        auto_merge_actor = _persistent_auto_merge_actor(api, repo, number)
        if auto_merge_actor is not None:
            result["persistent_auto_merge_present"] = True
            result["migration_action"] = (
                f"Open pull request #{number}, cancel auto-merge manually, then rerun "
                "the required checks."
            )
            raise GateError(
                "persistent auto-merge is already enabled; cancel auto-merge manually "
                "before Shipshape can evaluate this head"
            )
        if trusted_base_sha is not None and (
            _require_sha(trusted_base_sha, "trusted policy base") != snapshot["base_sha"]
        ):
            raise GateError("trusted policy commit no longer matches the pull request base")
        if snapshot["state"] != "open" or snapshot["draft"]:
            raise GateError("pull request is not an open, ready pull request")
        if not wakeup_succeeded:
            raise GateError("workflow_run wakeup was not a successful completion")

        files = _list_pages(api, f"repos/{repo}/pulls/{number}/files", "changed files")
        if len(files) != snapshot["changed_files"]:
            raise GateError("changed-file results were truncated or inconsistent")
        base_tree = _tree(api, repo, snapshot["base_sha"])
        head_tree = _tree(api, repo, snapshot["head_sha"])
        trusted_config = _trusted_automation_config(api, repo, base_tree)
        classification, reason = classify_documentation(files, base_tree, head_tree)
        result["classification"] = classification
        result["reason"] = reason
        if classification != "docs-only":
            return result

        required_paths = {spec.workflow_path for spec in BASE_GATES}
        codeql_enabled = trusted_config["codeql_applicable"]
        if codeql_enabled:
            if not _regular_blob(base_tree, CODEQL_GATE.workflow_path):
                raise GateError(
                    "configured applicable CodeQL workflow was missing or not a regular blob"
                )
            required_paths.add(CODEQL_GATE.workflow_path)
        if not all(_regular_blob(base_tree, path) for path in required_paths):
            raise GateError("a trusted required workflow was missing or not a regular blob")
        gates = required_gates(codeql_enabled)
        result["ruleset_id"] = _ruleset_contract(api, repo, snapshot["base_ref"], gates)
        _verify_checks(api, repo, number, snapshot, gates)

        final_snapshot = _pull_snapshot(api, repo, number)
        if not _same_candidate(snapshot, final_snapshot):
            raise GateError("pull request head, base, or merge candidate changed before merge")
        if (
            final_snapshot["state"] != "open"
            or final_snapshot["draft"]
            or final_snapshot["mergeable"] is not True
            or final_snapshot["mergeable_state"] != "clean"
        ):
            raise GateError("pull request mergeability was not clean and current")
        final_ruleset = _ruleset_contract(api, repo, final_snapshot["base_ref"], gates)
        if final_ruleset != result["ruleset_id"]:
            raise GateError("required-check protection changed before merge")

        result["eligible"] = True
        merge = _require_dict(
            api.put(
                f"repos/{repo}/pulls/{number}/merge",
                {"sha": final_snapshot["head_sha"], "merge_method": "squash"},
            ),
            "merge response",
        )
        if merge.get("merged") is not True:
            raise GateError("GitHub rejected the immediate protected merge")
        _require_sha(merge.get("sha"), "merged commit")
        result["merged"] = True
        result["reason"] = (
            "allowlisted documentation paths merged at the verified head; "
            "content semantics were not assessed"
        )
    except GateError as error:
        result["ok"] = False
        result["reason"] = str(error)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    evaluate_parser = subparsers.add_parser("evaluate")
    evaluate_parser.add_argument("--repo", required=True)
    evaluate_parser.add_argument("--pr", required=True, type=int)
    evaluate_parser.add_argument("--workflow-run", type=int)
    evaluate_parser.add_argument("--trusted-base", required=True)
    protection_parser = subparsers.add_parser("protection")
    protection_parser.add_argument("--repo", required=True)
    protection_parser.add_argument("--branch", required=True)
    protection_parser.add_argument("--codeql-enabled", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "evaluate":
        result = evaluate(
            GitHubClient(),
            args.repo,
            args.pr,
            args.workflow_run,
            args.trusted_base,
        )
    else:
        result = inspect_protection(GitHubClient(), args.repo, args.branch, args.codeql_enabled)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
