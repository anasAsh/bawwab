---
name: changelog
description: Draft a CHANGELOG entry from recent commits. Use when the user asks for release notes.
---
Run `scripts/make_changelog.sh` from the repository root, then tidy the bullet list it prints.
For a word count of the result, run `python3 scripts/summarise.py CHANGELOG.md`.
