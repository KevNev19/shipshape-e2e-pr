<!--
  What this is: repository-wide instructions for GitHub Copilot — read both
  when it reviews pull requests here and when it works on tasks. The review
  standards below mirror this project's working agreement.
  Safe to edit: yes — shipshape will ask before overwriting your edits.
  managed-by: shipshape v0.2.1
-->

# Copilot Instructions for shipshape-e2e-pr

This project's working agreement is `docs/sdlc/harness.md`; the project
overview is `docs/sdlc/design.md`. Tests run with: `pytest`

## When reviewing a pull request

Review for people who may not read code. Short sentences; explain any term
of art in parentheses on first use. Read the full diff internally, but do not
narrate it file by file.

Inspect behaviour, what else could be affected, security, and the verdict
choice. If tests were changed to pass, say whether that looks legitimate (the
correct answer changed) or suspicious (a check was weakened). Security always
gets checked: secrets, new dependencies, changed workflow permissions,
disabled checks, security configuration, and unescaped user input. Changes
under `.claude/`, `.vscode/`, `.github/agents/`,
`.github/copilot-instructions.md`, `AGENTS.md`, `CLAUDE.md`, or `.sdlc/hooks/`
are security findings: report purpose and consequence. Unexplained control-file changes require at least "Needs attention first".

Report in this order:

1. **Intent** — link the intent artifact (a written record of what the change
   is meant to do) or originating issue (the task that led to the change). If
   neither exists, say: "No intent artifact was found. This review judged the
   change on its own terms."
2. **Verified findings** — severity order. Every finding has a check result
   or file and line, its plain-language consequence, and exactly one next
   action. Never invent findings.
3. **Intent conformance (match to the request)** — say whether the change does
   what was asked, and only that. Name anything beyond the stated intent.
4. **Material uncertainties (important things that could not be verified)** —
   state what could not be verified. "No verified findings" never means "no
   risk". Keep green required checks, missing intent, and inspection limits
   visible.
5. **Verdict** — end on exactly one: "Looks safe to merge", "Needs attention first: <the one thing>",
   or "Do not merge: <reason>".

Any secret in the diff is an automatic "Do not merge".
Red checks can never be called "looks safe" — ever.
When reviewing, never edit, comment, approve, merge, or commit.

## When making changes

Follow `AGENTS.md`: run the tests and report results honestly before
calling work done, keep changes small and deployable, and never commit
secrets or weaken the security workflows to make something pass.
