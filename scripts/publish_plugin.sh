#!/bin/sh
# Make the next `plugin` branch commit from a tree built by scripts/build_plugin.py (R51).
#
# Usage: scripts/publish_plugin.sh TREE SOURCE_SHA [PARENT]
#
# Run inside a git repo. Writes a commit whose tree is exactly TREE (every file, .gitignore not applied) and
# whose parent is PARENT (the current `plugin` tip; omit on the first publish), then prints its sha. Prints
# nothing, and exits 0, when there is nothing to publish:
#   - TREE is identical to PARENT's tree, or
#   - TREE differs but .claude-plugin/plugin.json keeps PARENT's version. Claude Code caches installed plugins
#     by version, so the same version with other code would never reach existing users: bump the version
#     (plugin.json and pyproject.toml together) to release.
# Only object writes: no ref, index, work tree or remote is touched. Pushing is the caller's job.
set -eu

[ $# -ge 2 ] && [ $# -le 3 ] || { sed -n '4p' "$0" >&2; exit 2; }
tree_dir=$1
src=$2
parent=${3:-}
manifest=.claude-plugin/plugin.json
[ -f "$tree_dir/$manifest" ] || { echo "not a built plugin tree: $tree_dir" >&2; exit 2; }

version_of() { python3 -c 'import json, sys; print(json.load(sys.stdin)["version"])'; }
version=$(version_of < "$tree_dir/$manifest")

git_dir=$(git rev-parse --absolute-git-dir)
index=$(mktemp)
trap 'rm -f "$index"' EXIT
rm -f "$index"
tree=$(cd "$tree_dir" && GIT_DIR=$git_dir GIT_WORK_TREE=. GIT_INDEX_FILE=$index git add -A -f . \
       && GIT_DIR=$git_dir GIT_INDEX_FILE=$index git write-tree)

if [ -n "$parent" ]; then
    parent=$(git rev-parse --verify "$parent^{commit}")
    if [ "$tree" = "$(git rev-parse "$parent^{tree}")" ]; then
        echo "plugin tree unchanged since $parent: nothing to publish" >&2
        exit 0
    fi
    old=$(git show "$parent:$manifest" | version_of)
    if [ "$old" = "$version" ]; then
        echo "::warning::plugin tree changed but its version is still $version: not published (bump the version to release)" >&2
        exit 0
    fi
fi

git commit-tree "$tree" ${parent:+-p "$parent"} -m "bawwab $version from $src" -m "Built by scripts/build_plugin.py from source commit $src."
