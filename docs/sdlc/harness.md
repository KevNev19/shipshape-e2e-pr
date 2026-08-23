<!--
  What this is: the working agreement for shipshape-e2e-pr — how changes get
  built, checked, and released. Humans and AI assistants both follow it.
  Safe to edit: yes, this is your document. Shipshape will ask before
  overwriting any edits you make.
  managed-by: shipshape v0.2.1
-->

# How We Work on shipshape-e2e-pr

This is the single source of truth for this project's process. Tool-specific
files (like `CLAUDE.md`) may add wiring, but they must point here for policy —
mirrored only by reference, not rewritten differently.

## The basics

- The main branch is `main`. Working style: **pr**
  ("trunk" means small changes go straight to the main branch; "pr" means
  changes go through a pull request — a proposed change someone reviews first).
- Every change, however small, should leave the project working: tests pass,
  nothing half-finished on the main branch.

## Checking your work

- Run the tests with: `pytest`
- The same checks run automatically on GitHub every time code is pushed
  (see `.github/workflows/ci.yml`). A green check means the change is safe;
  a red X means something broke — open the failed step to see what.

## Security

Security guardrails are not optional in this project. The full picture —
what protects you, from what — lives in `docs/sdlc/security.md` once security
setup has run. Never commit passwords, API keys, or personal data.

## Reviews

Before accepting a change, understand what it does and what could break.
If an AI assistant made the change, it must explain the change in plain
language and say honestly whether tests passed.

## Releases

A release is a named, tagged version of the project that others can rely on.
Releases are cut deliberately (not on every change), come with human-readable
notes on what changed, and only from a green main branch.

## For AI assistants

- Read `docs/sdlc/design.md` first to understand what this project is.
- Before finishing any piece of work: run the tests, report results honestly
  (including failures), and list every file you changed.
- Never commit or push without being asked. Never delete files you did not
  create in the current session without asking.
