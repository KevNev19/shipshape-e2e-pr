<!--
  What this is: plain-English definitions of the terms this project's
  tooling uses. Skills and docs link here instead of re-explaining.
  Safe to edit: yes.
  managed-by: shipshape v0.2.1
-->

# Glossary

- **Repository (repo)** — the project folder plus its entire change history.
- **Commit** — one saved change with a message saying what and why. The
  history is made of commits.
- **Branch** — a parallel line of work. The main branch is the real project;
  other branches are drafts.
- **Push** — send your commits to GitHub so others (and the automation) see
  them.
- **Pull request (PR)** — a proposed change someone can review before it
  joins the main branch.
- **CI (continuous integration)** — the automated checks that run on GitHub
  after every push. Green check: tests passed. Red X: something broke.
- **Workflow** — one automation recipe in `.github/workflows/` (the CI is
  one, the release process is another).
- **Secret** — anything that grants access: passwords, API keys, tokens.
  Secrets must never be committed; the secret guard checks every commit.
- **Branch protection** — a GitHub rule that stops changes landing on the
  main branch unless conditions are met (like CI passing).
- **Dependabot** — GitHub's watcher that proposes updates when a library you
  use gets a fix.
- **CodeQL** — GitHub's code scanner that looks for security mistakes.
- **Release** — a named, tagged version of the project (like v1.2.0) with
  notes on what changed.
- **Semver (semantic versioning)** — version numbers as MAJOR.MINOR.PATCH:
  bump PATCH for fixes, MINOR for new features, MAJOR for breaking changes.
- **Tag** — a permanent label on one commit, usually marking a release.
