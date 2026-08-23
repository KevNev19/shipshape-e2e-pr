<!--
  What this is: the entry point Claude Code reads when it opens this project.
  It deliberately stays small — real policy lives in docs/sdlc/harness.md.
  Safe to edit: yes, but keep policy in the harness doc, not here.
  managed-by: shipshape v0.2.1
-->

# shipshape-e2e-pr — Instructions for AI Agents

This project's process is defined in `docs/sdlc/harness.md`. Read it before
making changes; it is the source of truth for how work is built, checked,
and released here. Keep tool-specific setup in this file small — substantive
policy belongs in the harness doc and must be mirrored only by reference,
not rewritten differently.

Quick facts:

- Main branch: `main` (working style: pr)
- Run tests: `pytest`
- Project overview: `docs/sdlc/design.md`
- SDLC configuration: `.sdlc/config.json` (change it with `/shipshape-customize`,
  not by hand)
