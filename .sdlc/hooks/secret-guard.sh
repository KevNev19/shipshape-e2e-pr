#!/usr/bin/env bash
# What this is: a safety net that checks changes for secrets (passwords,
# API keys, credential files) and risky agent/editor controls before they
# can enter history. As a pre-commit hook it scans the staged index. With
# --range A..B it scans each commit introduced between A and B, so a secret
# added and removed in separate commits is still found. If it blocks a local
# commit, fix the finding or use git commit --no-verify for a reviewed false
# alarm.
# Safe to edit: yes, but keep all three layers — file, content, and control paths.
# managed-by: shipshape v0.2.1
set -u

inspection_error() {
  echo "ERROR: secret guard could not inspect the requested Git changes." >&2
  echo "  Check the revisions and repository state, then run the scan again." >&2
  exit 2
}

usage_error() {
  echo "usage: secret-guard.sh [--range A..B]" >&2
  exit 2
}

if ! root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  inspection_error
fi
if ! cd "$root"; then
  inspection_error
fi

mode="staged"
range=""
if [ "$#" -eq 2 ] && [ "$1" = "--range" ]; then
  mode="range"
  range="$2"
elif [ "$#" -ne 0 ]; then
  usage_error
fi

task_tmp="$(mktemp -d "${TMPDIR:-/tmp}/shipshape-secret-guard.XXXXXX")" || inspection_error
trap 'rm -rf "$task_tmp"' EXIT HUP INT TERM

blocked=0
secret_blocked=0
control_blocked=0
scan_number=0
patterns='AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY-----'

extract_added_lines() {
  local normalized_file="$2.normalized"

  LC_ALL=C tr '\000' ' ' <"$1" >"$normalized_file" || return 1
  LC_ALL=C awk '
    /^diff --git / { in_hunk = 0; next }
    /^@@ / { in_hunk = 1; next }
    in_hunk && substr($0, 1, 1) == "+" { print }
  ' "$normalized_file" >"$2"
}

count_ere_matches() {
  local pattern="$1"
  local input="$2"
  local count status

  count="$(LC_ALL=C grep -a -cE "$pattern" "$input")"
  status=$?
  case "$status" in
    0|1) printf '%s\n' "${count:-0}" ;;
    *) return "$status" ;;
  esac
}

count_fixed_file_matches() {
  local pattern_file="$1"
  local input="$2"
  local count status

  count="$(LC_ALL=C grep -a -cFf "$pattern_file" "$input")"
  status=$?
  case "$status" in
    0|1) printf '%s\n' "${count:-0}" ;;
    *) return "$status" ;;
  esac
}

write_scan_files() {
  local diff_file="$1"
  local changed_file="$2"
  local control_file="$3"
  local from_revision="${4:-}"
  local to_revision="${5:-}"

  if [ "$mode" = "staged" ]; then
    git diff --cached --text --no-ext-diff --no-textconv --no-renames -U0 -- >"$diff_file" || return 1
    git diff --cached --name-only -z --no-ext-diff --no-textconv --no-renames --diff-filter=ACM -- >"$changed_file" || return 1
    git diff --cached --name-only -z --no-ext-diff --no-textconv --no-renames --diff-filter=ACMTD -- >"$control_file" || return 1
  else
    git diff --text --no-ext-diff --no-textconv --no-renames -U0 \
      "$from_revision" "$to_revision" -- >"$diff_file" || return 1
    git diff --name-only -z --no-ext-diff --no-textconv --no-renames --diff-filter=ACM \
      "$from_revision" "$to_revision" -- >"$changed_file" || return 1
    git diff --name-only -z --no-ext-diff --no-textconv --no-renames --diff-filter=ACMTD \
      "$from_revision" "$to_revision" -- >"$control_file" || return 1
  fi
}

write_file_diff() {
  local output="$1"
  local path="$2"
  local from_revision="${3:-}"
  local to_revision="${4:-}"

  if [ "$mode" = "staged" ]; then
    git diff --cached --text --no-ext-diff --no-textconv --no-renames -U0 -- "$path" >"$output"
  else
    git diff --text --no-ext-diff --no-textconv --no-renames -U0 \
      "$from_revision" "$to_revision" -- "$path" >"$output"
  fi
}

is_control_file() {
  case "$1" in
    AGENTS.md|*/AGENTS.md|CLAUDE.md|*/CLAUDE.md|SKILL.md|*/SKILL.md|\
    .claude/*|*/.claude/*|.agents/*|*/.agents/*|.codex/*|*/.codex/*|\
    .claude-plugin/*|*/.claude-plugin/*|.codex-plugin/*|*/.codex-plugin/*|\
    .github/agents/*|*/.github/agents/*|.github/copilot-instructions.md|*/.github/copilot-instructions.md|\
    .github/workflows/*|*/.github/workflows/*|.sdlc/*|*/.sdlc/*|\
    docs/agents/*|*/docs/agents/*|docs/sdlc/*|*/docs/sdlc/*|docs/harness.md|*/docs/harness.md|\
    .vscode/*|*/.vscode/*|.idea/runConfigurations/*|*/.idea/runConfigurations/*|\
    .zed/tasks.json|*/.zed/tasks.json|.zed/settings.json|*/.zed/settings.json|\
    .fleet/run.json|*/.fleet/run.json|.devcontainer/*|*/.devcontainer/*)
      return 0
      ;;
    *) return 1 ;;
  esac
}

is_executable_json_settings_file() {
  case "$1" in
    .claude/*.json|*/.claude/*.json|.claude/*.jsonc|*/.claude/*.jsonc|\
    .agents/*.json|*/.agents/*.json|.agents/*.jsonc|*/.agents/*.jsonc|\
    .codex/*.json|*/.codex/*.json|.codex/*.jsonc|*/.codex/*.jsonc|\
    .vscode/*.json|*/.vscode/*.json|.vscode/*.jsonc|*/.vscode/*.jsonc|\
    .zed/tasks.json|*/.zed/tasks.json|.zed/settings.json|*/.zed/settings.json|\
    .fleet/run.json|*/.fleet/run.json|\
    .devcontainer/*.json|*/.devcontainer/*.json|.devcontainer/*.jsonc|*/.devcontainer/*.jsonc)
      return 0
      ;;
    *) return 1 ;;
  esac
}

scan_control_file() {
  local path="$1"
  local from_revision="${2:-}"
  local to_revision="${3:-}"
  local raw_file="$task_tmp/control-$scan_number.diff"
  local added_file="$task_tmp/control-$scan_number.added"
  local execution_settings execution_hits profile_keys profile_values profile_hits
  local task_hits encoded_hits
  scan_number=$((scan_number + 1))

  write_file_diff "$raw_file" "$path" "$from_revision" "$to_revision" || return 1
  extract_added_lines "$raw_file" "$added_file" || return 1
  [ ! -s "$added_file" ] && return 0

  if is_executable_json_settings_file "$path"; then
    execution_settings='"(command|hooks?)"[[:space:]]*:|"terminal\.integrated\.(shell|shellArgs|automationProfile)\.(linux|osx|windows)"[[:space:]]*:|"type"[[:space:]]*:[[:space:]]*"(command|process|shell)"'
    execution_hits="$(count_ere_matches "$execution_settings" "$added_file")" || return 1

    profile_keys="$(count_ere_matches '"terminal\.integrated\.profiles\.(linux|osx|windows)"[[:space:]]*:' "$added_file")" || return 1
    profile_values="$(count_ere_matches '"(path|args)"[[:space:]]*:' "$added_file")" || return 1
    if [ "${profile_keys:-0}" -gt 0 ] && [ "${profile_values:-0}" -gt 0 ]; then
      profile_hits=1
    else
      profile_hits=0
    fi

    case "$path" in
      .vscode/tasks.json|*/.vscode/tasks.json|.vscode/tasks.jsonc|*/.vscode/tasks.jsonc)
        task_hits="$(count_ere_matches '"args"[[:space:]]*:' "$added_file")" || return 1
        ;;
      *) task_hits=0 ;;
    esac

    if [ "${execution_hits:-0}" -gt 0 ] || [ "$profile_hits" -gt 0 ] || [ "${task_hits:-0}" -gt 0 ]; then
      printf "BLOCKED: executable agent or editor settings were added to '%s'.\n" "$path" >&2
      echo "  Command, hook, task, and terminal settings can run code on your machine." >&2
      blocked=1
      control_blocked=1
    fi

    encoded_hits="$(count_ere_matches '[A-Za-z0-9+/=]{40,}' "$added_file")" || return 1
    if [ "${encoded_hits:-0}" -gt 0 ]; then
      printf "BLOCKED: a long base64-looking value was added to '%s'.\n" "$path" >&2
      echo "  Decode and review it before allowing automated tools to read it." >&2
      blocked=1
      control_blocked=1
    fi
  fi
}

scan_unit() {
  local unit="$1"
  local from_revision="${2:-}"
  local to_revision="${3:-}"
  local diff_file="$task_tmp/$unit.diff"
  local added_file="$task_tmp/$unit.added"
  local changed_file="$task_tmp/$unit.changed"
  local control_file="$task_tmp/$unit.control"
  local path matches warned denylist denylist_hits

  write_scan_files \
    "$diff_file" "$changed_file" "$control_file" "$from_revision" "$to_revision" || return 1
  extract_added_lines "$diff_file" "$added_file" || return 1

  # Layer 1: whole files that should never enter history. NUL delimiters keep
  # spaces, tabs, newlines, and leading dashes inside the filename.
  while IFS= read -r -d '' path; do
    case "$path" in
      *.pem|*.key|*id_rsa*|*id_ed25519*|*.p12|*.pfx|.env|*/.env|.env.*|*/.env.*|*credentials.json|*serviceaccount*.json)
        printf "BLOCKED: '%s' looks like a credential or key file. Files like this\n" "$path" >&2
        echo "  should stay out of git entirely (add it to .gitignore instead)." >&2
        blocked=1
        secret_blocked=1
        ;;
    esac
  done <"$changed_file"

  # Layer 2: newly added lines that match high-confidence secret patterns.
  matches="$(count_ere_matches "$patterns" "$added_file")" || return 1
  if [ "${matches:-0}" -gt 0 ]; then
    echo "BLOCKED: $matches added line(s) look like an API key, token, or private key." >&2
    echo "  If this got committed, anyone with repo access could use it." >&2
    echo "  Remove the secret and store it outside git (an ignored .env file)." >&2
    blocked=1
    secret_blocked=1
  fi

  # Layer 3: automation and policy control files. Each file is diffed independently
  # so executable JSON settings are attributed without exposing their content.
  warned=0
  while IFS= read -r -d '' path; do
    if is_control_file "$path"; then
      if [ "$warned" -eq 0 ]; then
        echo "WARN: automation or policy control files changed:" >&2
        warned=1
      fi
      printf '  - %s\n' "$path" >&2
      scan_control_file "$path" "$from_revision" "$to_revision" || return 1
    fi
  done <"$control_file"
  if [ "$warned" -eq 1 ]; then
    echo "  These files change how automated tools behave or define project policy." >&2
    echo "  Review them as carefully as code." >&2
  fi

  denylist="$root/.sdlc/hooks/denylist.txt"
  if [ -f "$denylist" ]; then
    denylist_hits="$(count_fixed_file_matches "$denylist" "$added_file")" || return 1
    if [ "${denylist_hits:-0}" -gt 0 ]; then
      echo "BLOCKED: $denylist_hits added line(s) match your private denylist." >&2
      blocked=1
      secret_blocked=1
    fi
  fi
}

if [ "$mode" = "staged" ]; then
  scan_unit staged || inspection_error
else
  case "$range" in
    *...*|-*|*..*..*|..*|*..)
      inspection_error
      ;;
    *..*) ;;
    *) usage_error ;;
  esac
  base_revision="${range%%..*}"
  tip_revision="${range#*..}"
  case "$base_revision" in ""|-*) inspection_error ;; esac
  case "$tip_revision" in ""|-*) inspection_error ;; esac

  base_commit="$(git rev-parse --verify "$base_revision^{commit}" 2>/dev/null)" || inspection_error
  tip_commit="$(git rev-parse --verify "$tip_revision^{commit}" 2>/dev/null)" || inspection_error
  commits_file="$task_tmp/commits"
  git rev-list --reverse "$base_commit..$tip_commit" -- >"$commits_file" 2>/dev/null || inspection_error
  empty_tree="$(git hash-object -t tree /dev/null 2>/dev/null)" || inspection_error

  commit_number=0
  while IFS= read -r commit; do
    [ -z "$commit" ] && continue
    commit_line="$(git rev-list --parents -n 1 "$commit" -- 2>/dev/null)" || inspection_error
    set -- $commit_line
    commit_hash="$1"
    shift
    parent_commit="${1:-$empty_tree}"
    scan_unit "commit-$commit_number" "$parent_commit" "$commit_hash" || inspection_error
    commit_number=$((commit_number + 1))
  done <"$commits_file"
fi

if [ "$blocked" -eq 1 ]; then
  echo "" >&2
  if [ "$mode" = "range" ]; then
    if [ "$control_blocked" -eq 1 ]; then
      echo "This change adds executable agent or editor settings. Review and" >&2
      echo "remove them before merging unless they are clearly intended." >&2
    fi
    if [ "$secret_blocked" -eq 1 ]; then
      echo "This change contains something that looks like a secret. Remove it" >&2
      echo "before merging — and if it was real, rotate it (change the key or" >&2
      echo "password) first: deleting the line does not un-leak it." >&2
    fi
  else
    echo "Nothing was committed. Fix the lines above and try again," >&2
    echo "or use 'git commit --no-verify' if you are sure this is a false alarm." >&2
  fi
  exit 1
fi
exit 0
