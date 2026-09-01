#!/bin/sh
set -eu

AUDIT_DIR=/var/log/clientcontrol
AUDIT_FILE=$AUDIT_DIR/audit.log
if [ -L "$AUDIT_DIR" ] || [ -L "$AUDIT_FILE" ]; then
    echo 'refusing to repair a symbolic-link Client Control audit path' >&2
    exit 1
fi
if pw usershow wwwonly >/dev/null 2>&1; then
    AUDIT_OWNER=wwwonly
else
    AUDIT_OWNER=www
fi

for audit_path in "$AUDIT_FILE" "$AUDIT_FILE".[0-9]*; do
    [ -f "$audit_path" ] || continue
    [ ! -L "$audit_path" ] || {
        echo "refusing symbolic-link audit generation: $audit_path" >&2
        exit 1
    }
    chown "$AUDIT_OWNER":wheel "$audit_path"
    chmod 0640 "$audit_path"
done
