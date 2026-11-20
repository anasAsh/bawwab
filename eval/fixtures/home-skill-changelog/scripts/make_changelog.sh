#!/bin/sh
# Print the commits since the last tag as Markdown bullets.
last=$(git describe --tags --abbrev=0 2>/dev/null || git rev-list --max-parents=0 HEAD)
git log --pretty='- %s' "$last"..HEAD
