<!--
  What this is: the entry point ANY coding agent reads when it works on this
  project — GitHub Copilot coding agent, Codex, Claude, and others all pick
  this file up. It deliberately stays small — real policy lives in
  docs/sdlc/harness.md.
  Safe to edit: yes, but keep policy in the harness doc, not here.
  managed-by: shipshape v0.2.1
-->

# shipshape-e2e-pr — Instructions for AI Agents

This project's process is defined in `docs/sdlc/harness.md`. Read it before
making changes; it is the source of truth for how work is built, checked,
and released here. Keep agent-specific setup in this file small — substantive
policy belongs in the harness doc and must be mirrored only by reference,
not rewritten differently.

Quick facts:

- Main branch: `main` (working style: pr)
- Run tests: `pytest`
- Project overview: `docs/sdlc/design.md`
- SDLC configuration: `.sdlc/config.json` (do not edit by hand)

Rules that apply to every agent working here:

- Run the tests and report results honestly, including failures, before
  calling any work done.
- Open changes as pull requests when working from GitHub; never bypass the
  checks. A red CI is a stop sign, not an inconvenience.
- Never commit secrets, and never weaken the security workflows or the
  secret guard to make something pass.
