#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
PLUGINSDIR=${PLUGINSDIR:-$ROOT/.build/opnsense-plugins}
MAKE=${MAKE:-make}
PHP=${PHP:-/usr/local/bin/php}
PKG=${PKG:-/usr/local/sbin/pkg}
VERSION=$(awk '/^PLUGIN_VERSION=/{print $2}' "$ROOT/Makefile")
OUT="$ROOT/dist"
WORK="$ROOT/.build/package"
CANDIDATE="$OUT/os-client-control-$VERSION.pkg"
ROLLBACK="$OUT/os-client-control-$VERSION.rollback.pkg"
INPUT_DIGEST="$CANDIDATE.inputs.sha256"
CONTENT_DIGEST="$CANDIDATE.sha256"
LOCK="$WORK/build.lock"

if [ "$(uname -s)" != "FreeBSD" ]; then
    echo "build-local.sh requires a FreeBSD/OPNsense build host; use tools/deploy.sh for remote OPNsense build/install" >&2
    exit 1
fi
[ -x "$PHP" ] || { echo "missing PHP binary: $PHP" >&2; exit 1; }
[ -x "$PKG" ] || { echo "missing FreeBSD pkg binary: $PKG" >&2; exit 1; }
[ -f "$PLUGINSDIR/Mk/plugins.mk" ] || { echo "missing OPNsense plugin build kit: $PLUGINSDIR" >&2; exit 1; }

mkdir -p "$OUT" "$WORK"
if ! mkdir "$LOCK" 2>/dev/null; then
    echo "build already running or stale lock requires inspection: $LOCK" >&2
    exit 1
fi
TMP=
trap 'rm -rf "${TMP:-}" "$LOCK"' EXIT HUP INT TERM
TMP=$(mktemp -d "$WORK/build.XXXXXX")

list_inputs() {
    find "$ROOT/src" -type f -print
    find "$ROOT/tests" -type f ! -path '*/__pycache__/*' ! -name '*.pyc' ! -name '*.pyo' -print
    printf '%s\n' "$ROOT/Makefile" "$ROOT/pkg-descr" "$ROOT/+POST_INSTALL.post" \
        "$ROOT/+PRE_DEINSTALL.pre" "$ROOT/+POST_DEINSTALL.post" \
        "$ROOT/tools/build-local.sh" "$ROOT/tools/compile-translations.sh"
    find "$PLUGINSDIR/Mk" "$PLUGINSDIR/Templates" "$PLUGINSDIR/Scripts" -type f -print
}

TARGET_INFO="$(/usr/local/sbin/opnsense-version -a)|$(uname -p)|$($PKG -v)"
NEW_DIGEST=$(
    {
        printf 'target=%s\n' "$TARGET_INFO"
        list_inputs | sort | while IFS= read -r file; do
            relative=${file#"$ROOT"/}
            printf '%s %s %s\n' "$(stat -f '%Lp' "$file")" "$(sha256 -q "$file")" "$relative"
        done
    } | sha256 -q
)

if [ -f "$CANDIDATE" ] && [ -f "$INPUT_DIGEST" ] && [ -f "$CONTENT_DIGEST" ] &&
    [ "$(cat "$INPUT_DIGEST")" = "$NEW_DIGEST" ] &&
    [ "$(cat "$CONTENT_DIGEST")" = "$(sha256 -q "$CANDIDATE")" ]; then
    "$PKG" info -F "$CANDIDATE" >/dev/null
    echo "$CANDIDATE"
    exit 0
fi

"$PHP" "$ROOT/tests/run.php"
"$MAKE" -C "$ROOT" \
    PLUGINSDIR="$PLUGINSDIR" \
    WRKDIR="$TMP/work" \
    WRKSRC="$TMP/stage" \
    PKGDIR="$TMP/pkg" \
    package

set -- "$TMP/pkg"/os-client-control-*.pkg
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "canonical plugin build did not produce exactly one package" >&2
    exit 1
fi
"$PKG" info -F "$1" >/dev/null
if [ -f "$CANDIDATE" ]; then
    mv -f "$CANDIDATE" "$ROLLBACK"
    if [ -f "$INPUT_DIGEST" ]; then
        mv -f "$INPUT_DIGEST" "$ROLLBACK.inputs.sha256"
    fi
    if [ -f "$CONTENT_DIGEST" ]; then
        mv -f "$CONTENT_DIGEST" "$ROLLBACK.sha256"
    fi
fi
mv -f "$1" "$CANDIDATE"
printf '%s\n' "$NEW_DIGEST" > "$INPUT_DIGEST"
sha256 -q "$CANDIDATE" > "$CONTENT_DIGEST"
echo "$CANDIDATE"
