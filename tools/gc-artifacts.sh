#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
MODE=${1:---dry-run}
ACTIVE=${2:-}
OUT="$ROOT/dist"

case "$MODE" in
    --dry-run|--apply) ;;
    *) echo "usage: $0 [--dry-run|--apply] [active-package]" >&2; exit 2 ;;
esac
[ -d "$OUT" ] || exit 0

mtime() {
    if stat -f '%m' "$1" >/dev/null 2>&1; then
        stat -f '%m' "$1"
    else
        stat -c '%Y' "$1"
    fi
}

remove_file() {
    file=$1
    case "$file" in
        "$OUT"/os-client-control-*.pkg) ;;
        *) echo "refusing to remove artifact outside Client Control namespace: $file" >&2; exit 1 ;;
    esac
    if [ "$MODE" = "--apply" ]; then
        rm -f "$file" "$file.inputs.sha256" "$file.sha256" "$file.deploy-inputs.sha256"
    else
        echo "$file"
    fi
}

candidate_records() {
    for file in "$OUT"/os-client-control-*.pkg; do
        [ -f "$file" ] || continue
        case "$file" in *.rollback.pkg) continue ;; esac
        [ "$file" = "$ACTIVE" ] && continue
        [ -f "$file.pin" ] && continue
        printf '%s\t%s\n' "$(mtime "$file")" "$file"
    done
}

rollback_records() {
    for file in "$OUT"/os-client-control-*.rollback.pkg; do
        [ -f "$file" ] || continue
        [ -f "$file.pin" ] && continue
        printf '%s\t%s\n' "$(mtime "$file")" "$file"
    done
}

count=0
candidate_records | sort -rn | while IFS="$(printf '\t')" read -r _ file; do
    count=$((count + 1))
    [ "$count" -le 2 ] && continue
    remove_file "$file"
done

count=0
rollback_records | sort -rn | while IFS="$(printf '\t')" read -r _ file; do
    count=$((count + 1))
    [ "$count" -le 2 ] && continue
    remove_file "$file"
done
