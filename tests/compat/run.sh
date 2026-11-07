#!/bin/sh
# Compatibility check against the real old server: it stores secrets on disk
# the way share.js did, then the new server opens them from the same storage.
# This also covers links that must survive the switch to the new server.
# Usage: tests/compat/run.sh   (OLD_REF selects the old commit, c209340 by default)
set -e

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OLD_REF=${OLD_REF:-c209340}
WORK=$(mktemp -d)
OLD_PID=
NEW_PID=
cleanup() {
  [ -n "$OLD_PID" ] && kill "$OLD_PID" 2>/dev/null || true
  if [ -n "$NEW_PID" ]; then kill "$NEW_PID" 2>/dev/null; wait "$NEW_PID" 2>/dev/null; fi
  git -C "$ROOT" worktree remove --force "$WORK/old" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

wait_for() {
  for i in $(seq 1 50); do
    curl -s -o /dev/null "$1" && return 0
    sleep 0.2
  done
  echo "server at $1 did not start" >&2
  exit 1
}

echo "Building the old server ($OLD_REF)"
git -C "$ROOT" worktree add -q --detach "$WORK/old" "$OLD_REF"
(cd "$WORK/old" && go run github.com/benbjohnson/ego/cmd/ego@v0.4.3 templates templates/partitial && go build -o "$WORK/old-server" .)
# The old server hashes these bower files on start; content does not matter here.
mkdir -p "$WORK/old/public/bower_components/crypto-js" "$WORK/old/public/bower_components/jquery/dist"
cp "$ROOT/public/assets/vendor/crypto-js.js" "$WORK/old/public/bower_components/crypto-js/crypto-js.js"
: > "$WORK/old/public/bower_components/jquery/dist/jquery.js"

mkdir -p "$WORK/store"
(cd "$WORK/old" && STORAGE_TYPE=disk DISK_STORAGE_PATHS="$WORK/store" LISTEN=127.0.0.1:8751 exec "$WORK/old-server") >/dev/null 2>&1 &
OLD_PID=$!
wait_for http://127.0.0.1:8751/
node "$ROOT/tests/compat/check.js" store http://127.0.0.1:8751 > "$WORK/links.json"
kill "$OLD_PID"; wait "$OLD_PID" 2>/dev/null || true; OLD_PID=

echo "Opening the old secrets with the new server"
(cd "$ROOT" && go build -o "$WORK/new-server" .)
(cd "$ROOT" && STORAGE_TYPE=disk DISK_STORAGE_PATHS="$WORK/store" LISTEN=127.0.0.1:8752 exec "$WORK/new-server") >/dev/null 2>&1 &
NEW_PID=$!
wait_for http://127.0.0.1:8752/
node "$ROOT/tests/compat/check.js" open http://127.0.0.1:8752 < "$WORK/links.json"
echo "Compatibility check passed"
