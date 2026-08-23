#!/usr/bin/env bash
# What this is: one-time installer for the commit-time secret guard. Run it
# once per clone of this repository: bash .sdlc/hooks/install.sh
# It prefers the pre-commit framework when available, and otherwise links the
# guard directly so a fresh clone is never left unprotected.
# Safe to edit: yes.
# managed-by: shipshape v0.2.1
set -euo pipefail

root="$(git rev-parse --show-toplevel)"

if command -v pre-commit >/dev/null 2>&1 && [ -f "$root/.pre-commit-config.yaml" ]; then
  (cd "$root" && pre-commit install)
  echo "Installed hooks via the pre-commit framework."
else
  ln -sf ../../.sdlc/hooks/secret-guard.sh "$root/.git/hooks/pre-commit"
  echo "Installed the secret guard as this clone's pre-commit hook."
  echo "Optional upgrade: install the pre-commit framework (pip install pre-commit)"
  echo "and re-run this script to get the full hook set."
fi
