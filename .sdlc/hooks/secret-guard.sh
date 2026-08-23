#!/usr/bin/env bash
# What this is: a safety net that checks changes for secrets (passwords,
# API keys, credential files) and risky agent/editor controls before they
# can enter history. It runs two
# ways: as a pre-commit hook on your computer (checks what you're about to
# commit), and with --range A..B in CI (checks a pushed or proposed change,
# including ones written by AI agents). If it blocks a commit, it tells you
# why. To bypass in a genuine false alarm:
#   git commit --no-verify
# Safe to edit: yes, but keep all three layers — file, content, and control paths.
# managed-by: shipshape v0.2.1
set -u

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

# Mode: staged index (default, pre-commit) or a commit range (CI).
range=""
if [ "${1:-}" = "--range" ]; then
  range="${2:?usage: secret-guard.sh [--range A..B]}"
fi
if [ -n "$range" ]; then
  changed="$(git diff --name-only --diff-filter=ACM "$range")"
  control_changed="$(git diff --name-only --no-renames --diff-filter=ACMTD "$range")"
  diff_text() { git diff -U0 "$range"; }
  added_lines() { git diff --no-renames -U0 "$range" -- "$1" | grep -E '^\+' | grep -vE '^\+\+\+' || true; }
else
  changed="$(git diff --cached --name-only --diff-filter=ACM)"
  control_changed="$(git diff --cached --name-only --no-renames --diff-filter=ACMTD)"
  diff_text() { git diff --cached -U0; }
  added_lines() { git diff --cached --no-renames -U0 -- "$1" | grep -E '^\+' | grep -vE '^\+\+\+' || true; }
fi
[ -z "$changed" ] && [ -z "$control_changed" ] && exit 0
blocked=0
secret_blocked=0
control_blocked=0

# Layer 1: whole files that should never enter history.
while IFS= read -r f; do
  case "$f" in
    *.pem|*.key|*id_rsa*|*id_ed25519*|*.p12|*.pfx|.env|*/.env|.env.*|*credentials.json|*serviceaccount*.json)
      echo "BLOCKED: '$f' looks like a credential or key file. Files like this" >&2
      echo "  should stay out of git entirely (add it to .gitignore instead)." >&2
      blocked=1
      secret_blocked=1
      ;;
  esac
done <<EOF
$changed
EOF

# Layer 2: newly added lines that match well-known secret patterns.
patterns='AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY-----'
matches="$(diff_text | grep -E '^\+' | grep -vE '^\+\+\+' | grep -cE "$patterns" || true)"
if [ "${matches:-0}" -gt 0 ]; then
  echo "BLOCKED: $matches added line(s) look like an API key, token, or private key." >&2
  echo "  If this got committed, anyone with repo access could use it." >&2
  echo "  Remove the secret and store it outside git (an ignored .env file)." >&2
  blocked=1
  secret_blocked=1
fi

# layer 3: agent control files
control_files="$(printf '%s\n' "$control_changed" | grep -E '^(\.claude/|\.vscode/|\.github/agents/|\.github/copilot-instructions\.md$|AGENTS\.md$|CLAUDE\.md$|\.sdlc/hooks/)' || true)"
if [ -n "$control_files" ]; then
  echo "WARN: agent or editor control files changed:" >&2
  while IFS= read -r f; do
    printf '  - %s\n' "$f" >&2
  done <<EOF
$control_files
EOF
  echo "  These files change how automated tools behave in this repository." >&2
  echo "  Review them as carefully as code." >&2
fi

while IFS= read -r f; do
  case "$f" in
    *.json|*.jsonc)
      added="$(added_lines "$f")"
      [ -z "$added" ] && continue

      # Explicit command, hook, shell, or executable type settings.
      execution_settings='"(command|hooks?)"[[:space:]]*:|"terminal\.integrated\.(shell|shellArgs|automationProfile)\.(linux|osx|windows)"[[:space:]]*:|"type"[[:space:]]*:[[:space:]]*"(command|process|shell)"'
      execution_hits="$(printf '%s\n' "$added" | grep -cE "$execution_settings" || true)"

      # A modern VS Code terminal profile executes its added path and arguments.
      profile_keys="$(printf '%s\n' "$added" | grep -cE '"terminal\.integrated\.profiles\.(linux|osx|windows)"[[:space:]]*:' || true)"
      profile_values="$(printf '%s\n' "$added" | grep -cE '"(path|args)"[[:space:]]*:' || true)"
      if [ "${profile_keys:-0}" -gt 0 ] && [ "${profile_values:-0}" -gt 0 ]; then
        profile_hits=1
      else
        profile_hits=0
      fi

      # Arguments in VS Code task files extend a command invocation.
      case "$f" in
        .vscode/tasks.json|.vscode/tasks.jsonc)
          task_hits="$(printf '%s\n' "$added" | grep -cE '"args"[[:space:]]*:' || true)"
          ;;
        *) task_hits=0 ;;
      esac

      if [ "${execution_hits:-0}" -gt 0 ] || [ "${profile_hits:-0}" -gt 0 ] || [ "${task_hits:-0}" -gt 0 ]; then
        echo "BLOCKED: executable agent or editor settings were added to '$f'." >&2
        echo "  Command, hook, task, and terminal settings can run code on your machine." >&2
        blocked=1
        control_blocked=1
      fi

      # Long base64-looking strings can conceal encoded commands or payloads.
      encoded_hits="$(printf '%s\n' "$added" | grep -cE '[A-Za-z0-9+/=]{40,}' || true)"
      if [ "${encoded_hits:-0}" -gt 0 ]; then
        echo "BLOCKED: a long base64-looking value was added to '$f'." >&2
        echo "  Decode and review it before allowing automated tools to read it." >&2
        blocked=1
        control_blocked=1
      fi
      ;;
  esac
done <<EOF
$control_files
EOF

# Optional extra denylist: one string per line in .sdlc/hooks/denylist.txt
# (keep that file out of git — it may itself contain sensitive words).
denylist="$root/.sdlc/hooks/denylist.txt"
if [ -f "$denylist" ]; then
  hits="$(diff_text | grep -E '^\+' | grep -vE '^\+\+\+' | grep -cFf "$denylist" || true)"
  if [ "${hits:-0}" -gt 0 ]; then
    echo "BLOCKED: $hits added line(s) match your private denylist." >&2
    blocked=1
    secret_blocked=1
  fi
fi

if [ "$blocked" -eq 1 ]; then
  echo "" >&2
  if [ -n "$range" ]; then
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
