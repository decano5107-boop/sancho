#!/bin/bash
# Install (or reinstall) Sancho as a launchd agent: it starts with the Mac and
# restarts itself if it exits. Without this it is a loose process that dies on
# every reboot, and you find out the day you message it and nobody answers.
#
#   deploy/install.sh            install and start
#   deploy/install.sh --remove   uninstall and leave the Mac as it was
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$(pwd)"
LABEL="${SANCHO_LABEL:-com.sancho.listener}"
DEST="$HOME/Library/LaunchAgents/$LABEL.plist"
# Inside the state directory, which the gate protects like the rest of Sancho's own files.
STATE="${SANCHO_LOG_DIR:-$HOME/.sancho/state/logs}"

remove() {
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    rm -f "$DEST"
    echo "removed; Sancho no longer starts on its own"
}
if [ "${1:-}" = "--remove" ]; then remove; exit 0; fi

PYTHON="$(command -v python3 || true)"
[ -n "$PYTHON" ] || { echo "ERROR: python3 not found on PATH" >&2; exit 1; }
"$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 11))' || {
    echo "ERROR: $PYTHON is older than 3.11; put a newer python3 first on PATH" >&2; exit 1; }
command -v claude >/dev/null || { echo "ERROR: the claude CLI is not on PATH" >&2; exit 1; }
[ -f "$REPO/.env" ] || { echo "ERROR: create $REPO/.env from .env.example first" >&2; exit 1; }
# An empty token makes the listener exit at once, and launchd would restart it forever.
for key in TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID CLAUDE_CODE_OAUTH_TOKEN; do
    grep -Eq "^${key}=.+" "$REPO/.env" || { echo "ERROR: $key is empty in .env" >&2; exit 1; }
done

mkdir -p "$HOME/Library/LaunchAgents" "$STATE"

# launchd starts with a minimal PATH; claude, ffmpeg and python3 usually live
# outside it, so the PATH of the shell running this installer is recorded.
# Filled in by Python rather than sed: the values are XML-escaped, and a "#" or "&"
# in a path cannot corrupt the file.
LABEL="$LABEL" PY="$PYTHON" REPO="$REPO" LOGS="$STATE" "$PYTHON" - deploy/sancho.plist.template "$DEST" <<'PY'
import os, sys
from xml.sax.saxutils import escape
text = open(sys.argv[1], encoding="utf-8").read()
for key, env in (("__LABEL__", "LABEL"), ("__PYTHON__", "PY"), ("__REPO__", "REPO"),
                 ("__LOGS__", "LOGS"), ("__PATH__", "PATH")):
    text = text.replace(key, escape(os.environ[env]))
open(sys.argv[2], "w", encoding="utf-8").write(text)
PY

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$DEST"
launchctl enable "gui/$(id -u)/$LABEL" 2>/dev/null || true

echo "installed as $LABEL; logs in $STATE"
echo "to remove:  deploy/install.sh --remove"
