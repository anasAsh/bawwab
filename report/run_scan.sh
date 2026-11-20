#!/usr/bin/env bash
# Run report/scan.py in a throwaway environment: no real HOME, ~/.claude, ~/.bawwab, XDG or Claude
# session variables are visible to the scanner. Downloads land under $REPORT_WORK (default
# /var/tmp/bawwab-report-work). Arguments are passed through to scan.py.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
W="${REPORT_WORK:-/var/tmp/bawwab-report-work}"
PY="${REPORT_PYTHON:-$ROOT/.venv/bin/python}"
mkdir -p "$W"/{home,bawwab,tmp,work,xdg/config,xdg/state,xdg/cache,xdg/data,tslp}
# Bawwab parses code with tree-sitter; give it a private copy of the grammar cache.
if [ ! -d "$W/tslp/tree-sitter-language-pack" ] && [ -d "$HOME/.cache/tree-sitter-language-pack" ]; then
  cp -r "$HOME/.cache/tree-sitter-language-pack" "$W/tslp/"
fi
echo '{"trusted": []}' > "$W/bawwab/config.json"
exec env -u CLAUDE_PLUGIN_DATA -u CLAUDE_PROJECT_DIR -u XDG_STATE_HOME -u CLAUDE_PLUGIN_ROOT -u BAWWAB_SESSION_ID \
  HOME="$W/home" BAWWAB_HOME="$W/bawwab" TMPDIR="$W/tmp" \
  XDG_CONFIG_HOME="$W/xdg/config" XDG_STATE_HOME="$W/xdg/state" XDG_CACHE_HOME="$W/xdg/cache" XDG_DATA_HOME="$W/xdg/data" \
  TREE_SITTER_LANGUAGE_PACK_CACHE_DIR="$W/tslp" \
  "$PY" -I "$ROOT/report/scan.py" --work "$W/work" "$@"
