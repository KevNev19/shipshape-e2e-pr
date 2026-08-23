<!--
  What this is: a plain-language map of the security guardrails on this
  project — what protects you, from what, and what to do when something
  goes red.
  Safe to edit: yes.
  managed-by: shipshape v0.2.1
-->

# What Protects shipshape-e2e-pr

Four guardrails, in the order they act:

## 1. Secret guard — on your computer, at commit time

Every time you commit, a small check (`.sdlc/hooks/secret-guard.sh`) scans
what you're about to save. If it sees a password, an API key, or a
credential file, it blocks the commit and tells you why. This is your first
line of defence, because a secret that reaches git history is very hard to
truly delete.

One-time setup per clone of this repo: `bash .sdlc/hooks/install.sh`

## 2. CI — on GitHub, after every push

The automated checks in `.github/workflows/ci.yml` run the tests on every
change. A red X on a commit means the tests failed — open the failed step,
read the last lines, and fix (or ask your AI assistant to explain it).

## 3. Code scanning (CodeQL) — GitHub reads the code for you

Where available, CodeQL scans the code on every push and weekly, looking
for known-vulnerable patterns. Findings appear under the repository's
**Security** tab. It is free on public repositories; private repositories
need GitHub Advanced Security.

## 4. Dependency watch (Dependabot) — the libraries you build on

Most projects are mostly other people's code. Dependabot watches those
libraries and opens a pull request when one of them has a security fix.
Treat those PRs as high priority: merge them once CI is green.

## When an AI tool works here

Choose the tool's restricted workspace mode and give it access to this
repository, not unrelated folders. Do not give it production credentials:
a mistaken command or misleading instruction could otherwise reach live
systems. Approve requests for extra access one at a time, after checking why
the tool needs it. If the tool works in the cloud, keep its changes in a pull
request so CI checks them before anyone merges them.

## When something goes red

1. Don't panic; nothing red here means the project is already broken in
   production — it means a guardrail caught something early.
2. Read the message. Every guardrail above explains itself in its output.
3. If a real secret ever DOES reach git history: change the secret
   (rotate the key, change the password) first, then clean up the history.
   Rotating first matters — deleting the file alone does not un-leak it.
