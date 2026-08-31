#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DEST="$ROOT/.build/opnsense-plugins"
REPOSITORY=https://github.com/opnsense/plugins.git
REVISION=8e4722853f817032a2c6ad63a67623298dd8d955

command -v git >/dev/null 2>&1 || { echo "missing git" >&2; exit 1; }
mkdir -p "$ROOT/.build"

if [ -e "$DEST" ]; then
    [ -d "$DEST/.git" ] || { echo "build-kit path is not a git checkout: $DEST" >&2; exit 1; }
    [ -z "$(git -C "$DEST" status --porcelain)" ] || {
        echo "refusing to replace a modified build-kit checkout: $DEST" >&2
        exit 1
    }
    current=$(git -C "$DEST" rev-parse HEAD)
    if [ "$current" != "$REVISION" ]; then
        git -C "$DEST" fetch --depth 1 origin "$REVISION"
        git -C "$DEST" checkout --detach --force FETCH_HEAD
    fi
else
    stage=$(mktemp -d "$ROOT/.build/opnsense-plugins.XXXXXX")
    cleanup() {
        status=$?
        trap - EXIT HUP INT TERM
        rm -rf "$stage"
        exit "$status"
    }
    trap cleanup EXIT HUP INT TERM
    git -C "$stage" init -q
    git -C "$stage" remote add origin "$REPOSITORY"
    git -C "$stage" fetch --depth 1 origin "$REVISION"
    git -C "$stage" checkout --detach -q FETCH_HEAD
    [ "$(git -C "$stage" rev-parse HEAD)" = "$REVISION" ]
    mv "$stage" "$DEST"
    stage=
    trap - EXIT HUP INT TERM
fi

[ "$(git -C "$DEST" rev-parse HEAD)" = "$REVISION" ] || {
    echo "unexpected build-kit revision" >&2
    exit 1
}
[ -z "$(git -C "$DEST" status --porcelain)" ] || {
    echo "build-kit checkout is not clean" >&2
    exit 1
}
[ -f "$DEST/Mk/plugins.mk" ]
[ -d "$DEST/Templates" ]
[ -d "$DEST/Scripts" ]
printf '%s\n' "$DEST@$REVISION"
