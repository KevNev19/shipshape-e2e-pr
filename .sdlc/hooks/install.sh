#!/usr/bin/env bash
# What this is: one-time installer for the commit-time secret guard. Run it
# once per clone of this repository: bash .sdlc/hooks/install.sh
# It follows Git's active hook directory, verifies pre-commit wiring before
# using the framework, and leaves any unrelated existing hook byte-for-byte
# unchanged.
# Safe to edit: yes.
# managed-by: shipshape v0.2.1
set -euo pipefail

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

config_wires_guard() {
  awk '
    function indentation(line, copy) {
      copy = line
      sub(/[^[:space:]].*$/, "", copy)
      return length(copy)
    }
    function trim(value) {
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)
      return value
    }
    function value_after_colon(line, value) {
      value = line
      sub(/^[^:]*:/, "", value)
      sub(/[[:space:]]+#.*$/, "", value)
      return trim(value)
    }
    function stages_include_pre_commit(value, inner, count, items, item, position, found) {
      value = trim(value)
      if (substr(value, 1, 1) != "[" || substr(value, length(value), 1) != "]") {
        return -1
      }
      inner = substr(value, 2, length(value) - 2)
      if (inner ~ /\[/ || inner ~ /\]/) {
        return -1
      }
      if (trim(inner) == "") {
        return 0
      }
      count = split(inner, items, ",")
      found = 0
      for (position = 1; position <= count; position++) {
        item = trim(items[position])
        if (item !~ /^[a-z0-9-]+$/) {
          return -1
        }
        if (item == "pre-commit") {
          found = 1
        }
      }
      return found
    }
    function finish_hook(candidate, entry) {
      if (!in_hook) {
        return
      }
      if (hook_secret_seen) {
        secret_hooks++
        entry = hook_entry
        sub(/^\.\//, "", entry)
        candidate_valid[secret_hooks] = repo_local
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && repo_keys == 1
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && hooks_keys == 1
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && !hook_invalid
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && hook_id_count == 1
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && hook_id == "secret-guard"
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && entry_count == 1
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && entry == ".sdlc/hooks/secret-guard.sh"
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && language_count == 1
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && hook_language == "script"
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && pass_count == 1
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && hook_pass == "false"
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && always_count == 1
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && hook_always == "true"
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && stages_count <= 1
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && name_count <= 1
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && repo_order == 1
        candidate_valid[secret_hooks] = candidate_valid[secret_hooks] && hook_order == 1
        candidate_has_stages[secret_hooks] = stages_count == 1
        candidate_stages[secret_hooks] = hook_stages
      }
      in_hook = hook_secret_seen = hook_invalid = 0
    }
    function finish_repo() {
      finish_hook()
      in_repo = in_hooks = 0
    }
    {
      raw = $0
      if (raw ~ /^[[:space:]]*(#|$)/) {
        next
      }
      indent = indentation(raw)
      if (substr(raw, 1, indent) ~ /\t/) {
        invalid_config = 1
      }
      content = substr(raw, indent + 1)
      key_content = content
      sub(/^-[[:space:]]+/, "", key_content)
      key_first = substr(key_content, 1, 1)
      unsupported_key = key_first == "\"" || key_first == sprintf("%c", 39)
      unsupported_key = unsupported_key || key_first == "{" || key_first == "["
      unsupported_alias = key_content ~ /^<<:/ || key_content ~ /&[A-Za-z0-9_-]+/
      unsupported_alias = unsupported_alias || key_content ~ /\*[A-Za-z0-9_-]+/
      if (unsupported_key || unsupported_alias) {
        invalid_config = 1
      }
      if (indent == 0) {
        finish_repo()
        in_repos = 0
        if (content ~ /^repos[[:space:]]*:/) {
          top_repos++
          if (value_after_colon(content) != "") {
            invalid_config = 1
          }
          in_repos = 1
        } else if (content ~ /^default_stages[[:space:]]*:/) {
          default_count++
          default_stages = value_after_colon(content)
        }
        next
      }
      if (!in_repos) {
        next
      }
      if (indent == 2 && content ~ /^-[[:space:]]+repo[[:space:]]*:/) {
        finish_repo()
        in_repos = 1
        in_repo = 1
        repo_order++
        repo_keys = 1
        repo_local = value_after_colon(content) == "local"
        hooks_keys = 0
        next
      }
      if (!in_repo) {
        next
      }
      if (indent == 4 && content ~ /^repo[[:space:]]*:/) {
        repo_keys++
        if (value_after_colon(content) == "local") {
          repo_local = 1
        }
        next
      }
      if (indent == 4 && content ~ /^hooks[[:space:]]*:/) {
        finish_hook()
        hooks_keys++
        in_hooks = value_after_colon(content) == ""
        next
      }
      if (in_hooks && indent == 6 && content ~ /^-[[:space:]]+id[[:space:]]*:/) {
        finish_hook()
        in_hook = 1
        hook_order++
        hook_id = value_after_colon(content)
        hook_id_count = 1
        hook_secret_seen = hook_id == "secret-guard"
        hook_invalid = 0
        entry_count = language_count = pass_count = always_count = 0
        stages_count = name_count = 0
        hook_entry = hook_language = hook_pass = hook_always = hook_stages = ""
        next
      }
      if (!in_hook) {
        next
      }
      if (indent != 8 || content !~ /^[a-z_]+[[:space:]]*:/) {
        if (hook_secret_seen) {
          hook_invalid = 1
        }
        next
      }
      key = content
      sub(/[[:space:]]*:.*$/, "", key)
      value = value_after_colon(content)
      if (key == "id") {
        hook_id_count++
        hook_id = value
        if (value == "secret-guard") {
          hook_secret_seen = 1
        }
      } else if (key == "name") {
        name_count++
      } else if (key == "entry") {
        entry_count++
        hook_entry = value
      } else if (key == "language") {
        language_count++
        hook_language = value
      } else if (key == "pass_filenames") {
        pass_count++
        hook_pass = value
      } else if (key == "always_run") {
        always_count++
        hook_always = value
      } else if (key == "stages") {
        stages_count++
        hook_stages = value
      } else if (hook_secret_seen) {
        hook_invalid = 1
      }
    }
    END {
      finish_repo()
      valid = !invalid_config && top_repos == 1 && default_count <= 1 && secret_hooks == 1
      if (valid) {
        if (candidate_has_stages[1]) {
          stage_result = stages_include_pre_commit(candidate_stages[1])
        } else if (default_count) {
          stage_result = stages_include_pre_commit(default_stages)
        } else {
          stage_result = 1
        }
        valid = candidate_valid[1] && stage_result == 1
      }
      exit(valid ? 0 : 1)
    }
  ' "$config"
}

guard_is_skipped() {
  case ",${SKIP:-}," in
    *,secret-guard,*) return 0 ;;
    *) return 1 ;;
  esac
}

hook_is_direct_guard() {
  [ -e "$hook" ] && { [ "$hook" -ef "$guard" ] || cmp -s "$hook" "$guard"; }
}

hook_is_pre_commit_dispatcher() {
  [ -f "$hook" ] &&
    grep -Eq '^# File generated by pre-commit(:|$)' "$hook" &&
    grep -Eq '^[[:space:]]*ARGS=\(hook-impl[[:space:]]+--config=\.?/?\.pre-commit-config\.yaml[[:space:]]+--hook-type=pre-commit\)[[:space:]]*$' "$hook" &&
    { grep -Eq '^[[:space:]]*exec[[:space:]]+pre-commit[[:space:]]+"\$\{ARGS\[@\]\}"[[:space:]]*$' "$hook" ||
      grep -Eq '^[[:space:]]*exec[[:space:]]+"\$INSTALL_PYTHON"[[:space:]]+-mpre_commit[[:space:]]+"\$\{ARGS\[@\]\}"[[:space:]]*$' "$hook"; }
}

root="$(git rev-parse --show-toplevel 2>/dev/null)" || fail "run this installer inside a Git repository."
cd "$root"
guard="$root/.sdlc/hooks/secret-guard.sh"
config="$root/.pre-commit-config.yaml"
[ -x "$guard" ] || fail "the expected executable guard is missing at .sdlc/hooks/secret-guard.sh; re-run /shipshape-init."

hooks_path="$(git rev-parse --git-path hooks 2>/dev/null)" || fail "could not determine Git's active hook path."
configured_hooks_path=""
if configured_hooks_path="$(git config --get core.hooksPath 2>/dev/null)"; then
  :
else
  config_status=$?
  [ "$config_status" -eq 1 ] || fail "could not inspect Git's configured hook path."
fi
case "$hooks_path" in
  /*) hooks_dir="$hooks_path" ;;
  *) hooks_dir="$root/$hooks_path" ;;
esac
hook="$hooks_dir/pre-commit"
mkdir -p "$hooks_dir"

hook_kind="none"
if [ -e "$hook" ] || [ -L "$hook" ]; then
  if hook_is_direct_guard; then
    hook_kind="direct"
  elif hook_is_pre_commit_dispatcher; then
    hook_kind="pre-commit"
  else
    fail "an unrelated existing pre-commit hook is active at '$hook'; it was not changed. Integrate .sdlc/hooks/secret-guard.sh manually, then re-run this installer."
  fi
fi

if [ "$hook_kind" = "pre-commit" ]; then
  if [ ! -x "$hook" ] || [ ! -f "$config" ] || ! config_wires_guard || guard_is_skipped; then
    fail "the active pre-commit dispatcher does not verifiably wire the executable secret guard; it was not changed."
  fi
  echo "Existing wiring was checked statically; the supported pre-commit configuration schedules the secret guard."
  exit 0
fi

# pre-commit refuses installation when core.hooksPath is configured. In that
# case the direct path below is the only installation that honors Git's setup.
if [ -z "$configured_hooks_path" ] && command -v pre-commit >/dev/null 2>&1 && [ -f "$config" ]; then
  if ! config_wires_guard || guard_is_skipped; then
    fail ".pre-commit-config.yaml does not wire the secret-guard hook; it was not changed and no hook was installed. Add the shipshape local hook entry or restore the managed configuration."
  fi
  if [ "$hook_kind" = "direct" ]; then
    (cd "$root" && pre-commit install --overwrite)
  else
    (cd "$root" && pre-commit install)
  fi
  if [ ! -x "$hook" ] || ! hook_is_pre_commit_dispatcher || ! config_wires_guard; then
    fail "pre-commit returned without installing a verifiable executable secret-guard dispatcher at '$hook'."
  fi
  echo "Installed hooks via the pre-commit framework."
  exit 0
fi

if [ "$hook_kind" = "none" ]; then
  ln -s "$guard" "$hook"
fi
if [ ! -x "$hook" ] || ! hook_is_direct_guard; then
  fail "the direct secret guard could not be verified at '$hook'."
fi

echo "Installed the secret guard as this clone's pre-commit hook."
echo "Optional upgrade: install the pre-commit framework (pip install pre-commit)"
echo "and re-run this script to get the full hook set."
