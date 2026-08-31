#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
MSGFMT=${MSGFMT:-msgfmt}
PO="$ROOT/translations/ru_RU.po"
MO="$ROOT/src/share/locale/ru_RU/LC_MESSAGES/os-client-control.mo"
PO_DIGEST="$ROOT/translations/ru_RU.po.sha256"
MO_DIGEST="$ROOT/translations/ru_RU.mo.sha256"
TMP=

command -v "$MSGFMT" >/dev/null 2>&1 || {
    echo "missing msgfmt; install gettext tools before updating translations" >&2
    exit 1
}
[ -f "$PO" ] || { echo "missing translation source: $PO" >&2; exit 1; }

mkdir -p "$(dirname -- "$MO")"
TMP=$(mktemp "${TMPDIR:-/tmp}/client-control-locale.XXXXXX")
trap 'rm -f "${TMP:-}"' EXIT HUP INT TERM
"$MSGFMT" --check --check-format --check-header -o "$TMP" "$PO"
if [ ! -f "$MO" ] || ! cmp -s "$TMP" "$MO"; then
    mv -f "$TMP" "$MO"
    TMP=
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$PO" | cut -d ' ' -f 1 > "$PO_DIGEST"
    sha256sum "$MO" | cut -d ' ' -f 1 > "$MO_DIGEST"
else
    sha256 -q "$PO" > "$PO_DIGEST"
    sha256 -q "$MO" > "$MO_DIGEST"
fi
printf '%s\n' "$MO"
