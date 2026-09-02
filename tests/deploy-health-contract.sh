#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DEPLOY=$ROOT/tools/deploy.sh
HEALTH=$ROOT/src/opnsense/scripts/Volgodon/ClientControl/health.php
POST_INSTALL=$ROOT/+POST_INSTALL.post

extract_function() {
    sed -n "/^$1() {$/,/^}$/p" "$DEPLOY"
}

FUNCTIONS=$(extract_function health_status_ok; extract_function audit_log_degraded)
[ -n "$FUNCTIONS" ] || {
    echo 'deploy health contract functions are missing' >&2
    exit 1
}
eval "$FUNCTIONS"

HEALTHY='{"status":"ok","objects":{},"audit_log":{"status":"ok","message":""}}'
AUDIT_DEGRADED='{"status":"ok","objects":{},"audit_log":{"status":"degraded","message":"bad mode"}}'
CORE_FAILED='{"status":"error","objects":{},"audit_log":{"status":"ok","message":""}}'

health_status_ok "$HEALTHY"
health_status_ok "$AUDIT_DEGRADED"
audit_log_degraded "$AUDIT_DEGRADED"
if health_status_ok "$CORE_FAILED"; then
    echo 'nested audit status must not hide a failed top-level health status' >&2
    exit 1
fi
if audit_log_degraded "$HEALTHY"; then
    echo 'healthy audit storage must not emit a degraded warning' >&2
    exit 1
fi

HEALTH_SOURCE=$(sed -n '1,$p' "$HEALTH")
case "$HEALTH_SOURCE" in
    *"'status' => 'ok',"*'exit(0);'*) ;;
    *)
        echo 'audit degradation must remain JSON-visible with a successful health exit' >&2
        exit 1
        ;;
esac
case "$HEALTH_SOURCE" in
    *"exit(\$status === "*)
        echo 'audit degradation must not control the health process exit code' >&2
        exit 1
        ;;
esac

DEPLOY_SOURCE=$(sed -n '1,$p' "$DEPLOY")
case "$DEPLOY_SOURCE" in
    *'/usr/local/sbin/configctl clientcontrol runtime_guard'*) ;;
    *)
        echo 'deploy health must verify restored runtime firewall guards' >&2
        exit 1
        ;;
esac
POST_INSTALL_SOURCE=$(sed -n '1,$p' "$POST_INSTALL")
case "$POST_INSTALL_SOURCE" in
    *'configctl filter reload'*) ;;
    *)
        echo 'package install must restore filter runtime after deinstall hooks' >&2
        exit 1
        ;;
esac

printf '%s\n' 'ok deploy audit-health contract'
