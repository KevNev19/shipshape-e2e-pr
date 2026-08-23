<!--
  What this is: the standard place people look to learn how to report a
  security problem in this project.
  Safe to edit: yes — put your real contact route in.
  managed-by: shipshape v0.2.1
-->

# Security Policy

## Reporting a problem

If you find a security problem in shipshape-e2e-pr — a way to see data you
shouldn't, to run code you shouldn't, or a leaked credential — please report
it privately rather than opening a public issue.

- Preferred: open a private security advisory on GitHub
  (Security tab → "Report a vulnerability").
- Please include what you found, where, and how to reproduce it.

We will acknowledge reports as quickly as we can and say what happens next.

## What protects this project

This repository uses automated guardrails set up by shipshape — a
commit-time secret guard, dependency monitoring, and code scanning where
available. The plain-language overview lives in `docs/sdlc/security.md`.
