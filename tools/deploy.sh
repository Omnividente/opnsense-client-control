#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TARGET=${1:?usage: tools/deploy.sh root@opnsense-host}
TARGET_VERSION=${TARGET_VERSION:-24.7}
VERSION=$(awk '/^PLUGIN_VERSION=/{print $2}' "$ROOT/Makefile")
PACKAGE_NAME=os-client-control
OUT="$ROOT/dist"
WORK="$ROOT/.build/deploy"
CANDIDATE="$OUT/$PACKAGE_NAME-$VERSION.pkg"
ROLLBACK="$OUT/$PACKAGE_NAME-$VERSION.rollback.pkg"
INPUT_DIGEST="$CANDIDATE.inputs.sha256"
CONTENT_DIGEST="$CANDIDATE.sha256"
DEPLOY_DIGEST="$CANDIDATE.deploy-inputs.sha256"
LOCK="$WORK/deploy.lock"

remote_ssh() {
    if [ -n "${SSHPASS:-}" ]; then
        sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "$@"
    else
        ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "$@"
    fi
}

remote_scp() {
    if [ -n "${SSHPASS:-}" ]; then
        sshpass -e scp -q -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "$@"
    else
        scp -q -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "$@"
    fi
}

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    else
        sha256 -q "$1"
    fi
}

hash_stream() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | cut -d ' ' -f 1
    else
        sha256 -q
    fi
}

command -v ssh >/dev/null 2>&1 || { echo "missing ssh" >&2; exit 1; }
command -v scp >/dev/null 2>&1 || { echo "missing scp" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "missing tar" >&2; exit 1; }
if [ -n "${SSHPASS:-}" ]; then
    command -v sshpass >/dev/null 2>&1 || { echo "SSHPASS is set but sshpass is unavailable" >&2; exit 1; }
fi
"$ROOT/tools/bootstrap-build-kit.sh" >/dev/null
"$ROOT/tools/compile-translations.sh" >/dev/null

mkdir -p "$OUT" "$WORK"
if ! mkdir "$LOCK" 2>/dev/null; then
    echo "deploy already running or stale lock requires inspection: $LOCK" >&2
    exit 1
fi
TMP=
REMOTE_STAGE=
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$REMOTE_STAGE" ]; then
        remote_ssh "$TARGET" rm -rf -- "$REMOTE_STAGE" >/dev/null 2>&1 || true
    fi
    rm -rf "${TMP:-}" "$LOCK"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM
TMP=$(mktemp -d "$WORK/run.XXXXXX")

REMOTE_STAGE=$(remote_ssh "$TARGET" 'umask 077; mktemp -d /tmp/client-control-deploy.XXXXXX')
case "$REMOTE_STAGE" in
    /tmp/client-control-deploy.*) ;;
    *) echo "unsafe remote stage returned by target: $REMOTE_STAGE" >&2; exit 1 ;;
esac

TARGET_INFO=$(remote_ssh "$TARGET" '/usr/local/sbin/opnsense-version -a; uname -p; /usr/local/sbin/pkg -v')
TARGET_RELEASE=$(printf '%s\n' "$TARGET_INFO" | sed -n '1p')
TARGET_ARCH=$(printf '%s\n' "$TARGET_INFO" | sed -n '2p')
case "$TARGET_RELEASE" in
    "$TARGET_VERSION"*) ;;
    *) echo "unsupported target release: $TARGET_RELEASE (expected $TARGET_VERSION.x)" >&2; exit 1 ;;
esac
[ "$TARGET_ARCH" = "amd64" ] || { echo "unsupported target architecture: $TARGET_ARCH" >&2; exit 1; }

SOURCE_TAR="$TMP/source.tar"
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    --exclude='*/__pycache__' --exclude='*/__pycache__/*' --exclude='*.pyc' --exclude='*.pyo' \
    -cf "$SOURCE_TAR" \
    -C "$ROOT" \
    Makefile pkg-descr +POST_INSTALL.post +PRE_DEINSTALL.pre +POST_DEINSTALL.post src tests translations \
    tools/bootstrap-build-kit.sh tools/build-local.sh tools/compile-translations.sh \
    tools/deploy.sh tools/gc-artifacts.sh \
    .build/opnsense-plugins/Mk .build/opnsense-plugins/Templates .build/opnsense-plugins/Scripts
SOURCE_HASH=$(hash_file "$SOURCE_TAR")
NEW_DEPLOY_DIGEST=$(printf '%s\n%s\n' "$SOURCE_HASH" "$TARGET_INFO" | hash_stream)

REUSE=false
if [ -f "$CANDIDATE" ] && [ -f "$CONTENT_DIGEST" ] && [ -f "$DEPLOY_DIGEST" ] &&
    [ "$(cat "$CONTENT_DIGEST")" = "$(hash_file "$CANDIDATE")" ] &&
    [ "$(cat "$DEPLOY_DIGEST")" = "$NEW_DEPLOY_DIGEST" ]; then
    REUSE=true
    echo "reusing verified candidate $CANDIDATE"
fi

if [ "$REUSE" = false ]; then
    remote_scp "$SOURCE_TAR" "$TARGET:$REMOTE_STAGE/source.tar"
    remote_ssh "$TARGET" sh -s -- "$REMOTE_STAGE" "$VERSION" <<'REMOTE_BUILD'
set -eu
stage=$1
version=$2
root="$stage/security/client-control"
mkdir -p "$root"
tar -xf "$stage/source.tar" -C "$root"
"$root/tools/build-local.sh"
candidate="$root/dist/os-client-control-$version.pkg"
[ -f "$candidate" ] || { echo "remote build did not produce $candidate" >&2; exit 1; }
/usr/local/sbin/pkg info -F "$candidate" >/dev/null
REMOTE_BUILD

    REMOTE_CANDIDATE="$REMOTE_STAGE/security/client-control/dist/$PACKAGE_NAME-$VERSION.pkg"
    remote_scp "$TARGET:$REMOTE_CANDIDATE" "$TMP/candidate.pkg"
    remote_scp "$TARGET:$REMOTE_CANDIDATE.sha256" "$TMP/candidate.pkg.sha256"
    remote_scp "$TARGET:$REMOTE_CANDIDATE.inputs.sha256" "$TMP/candidate.pkg.inputs.sha256"
    [ "$(cat "$TMP/candidate.pkg.sha256")" = "$(hash_file "$TMP/candidate.pkg")" ] || {
        echo "candidate content digest mismatch after transfer" >&2
        exit 1
    }

    if [ -f "$CANDIDATE" ]; then
        mv -f "$CANDIDATE" "$ROLLBACK"
        [ ! -f "$INPUT_DIGEST" ] || mv -f "$INPUT_DIGEST" "$ROLLBACK.inputs.sha256"
        [ ! -f "$CONTENT_DIGEST" ] || mv -f "$CONTENT_DIGEST" "$ROLLBACK.sha256"
        [ ! -f "$DEPLOY_DIGEST" ] || mv -f "$DEPLOY_DIGEST" "$ROLLBACK.deploy-inputs.sha256"
    fi
    mv -f "$TMP/candidate.pkg" "$CANDIDATE"
    mv -f "$TMP/candidate.pkg.sha256" "$CONTENT_DIGEST"
    mv -f "$TMP/candidate.pkg.inputs.sha256" "$INPUT_DIGEST"
    printf '%s\n' "$NEW_DEPLOY_DIGEST" > "$DEPLOY_DIGEST"
fi

EXPECTED_CONTENT=$(cat "$CONTENT_DIGEST")
remote_scp "$CANDIDATE" "$TARGET:$REMOTE_STAGE/candidate.pkg"
remote_ssh "$TARGET" sh -s -- "$REMOTE_STAGE/candidate.pkg" "$EXPECTED_CONTENT" <<'REMOTE_VERIFY'
set -eu
candidate=$1
expected=$2
[ "$(sha256 -q "$candidate")" = "$expected" ]
/usr/local/sbin/pkg info -F "$candidate" >/dev/null
REMOTE_VERIFY

if ! remote_ssh "$TARGET" sh -s -- "$REMOTE_STAGE" "$PACKAGE_NAME" "$TARGET_VERSION" <<'REMOTE_INSTALL'
set -eu
stage=$1
package_name=$2
target_version=$3
candidate="$stage/candidate.pkg"
rollback_dir="$stage/rollback"
had_installed=false
rollback=

health_status_ok() {
    case "$1" in
        '{"status":"ok",'*) return 0 ;;
        *) return 1 ;;
    esac
}

audit_log_degraded() {
    case "$1" in
        *'"audit_log":{"status":"degraded"'*) return 0 ;;
        *) return 1 ;;
    esac
}

health() {
    /usr/local/sbin/pkg info -e "$package_name" || return 1
    /usr/local/sbin/pkg check -s "$package_name" >/dev/null || return 1
    test -x /usr/local/opnsense/scripts/Volgodon/ClientControl/health.php || return 1
    test -f /usr/local/opnsense/mvc/app/controllers/Volgodon/ClientControl/Api/ServiceController.php || return 1
    /usr/local/bin/php -r 'require_once "/usr/local/etc/inc/config.inc"; foreach (["Volgodon\\ClientControl\\IndexController", "Volgodon\\ClientControl\\Api\\ServiceController"] as $class) { new ReflectionClass($class); }' >/dev/null || return 1
    case "$(/usr/local/sbin/opnsense-version -a)" in "$target_version"*) ;; *) return 1 ;; esac
    direct_health=$(/usr/local/opnsense/scripts/Volgodon/ClientControl/health.php) || return 1
    health_status_ok "$direct_health" || return 1
    configd_health=$(/usr/local/sbin/configctl clientcontrol health) || return 1
    health_status_ok "$configd_health" || return 1
    if audit_log_degraded "$direct_health" || audit_log_degraded "$configd_health"; then
        echo 'warning: Client Control audit history is degraded; the healthy package remains installed.' >&2
        echo "$direct_health" >&2
    fi
    runtime_guard=$(/usr/local/sbin/configctl clientcontrol runtime_guard) || return 1
    health_status_ok "$runtime_guard" || return 1
}

if /usr/local/sbin/pkg info -e "$package_name"; then
    had_installed=true
    mkdir -p "$rollback_dir"
    /usr/local/sbin/pkg create -o "$rollback_dir" "$package_name" >/dev/null
    set -- "$rollback_dir"/*.pkg
    [ "$#" -eq 1 ] && [ -f "$1" ] || { echo "could not capture installed rollback package" >&2; exit 1; }
    rollback=$1
fi

install_ok=true
/usr/local/sbin/pkg add -f "$candidate" >/dev/null || install_ok=false
if [ "$install_ok" = true ]; then
    /usr/local/sbin/configctl configd restart >/dev/null
    health || install_ok=false
fi

if [ "$install_ok" != true ]; then
    echo "candidate health check failed; restoring previous package" >&2
    if [ "$had_installed" = true ]; then
        /usr/local/sbin/pkg add -f "$rollback" >/dev/null
        /usr/local/sbin/configctl configd restart >/dev/null
        health || { echo "rollback package also failed health check" >&2; exit 2; }
    else
        /usr/local/sbin/pkg delete -y "$package_name" >/dev/null 2>&1 || true
        /usr/local/sbin/configctl configd restart >/dev/null 2>&1 || true
    fi
    exit 1
fi

/usr/local/sbin/pkg info "$package_name"
/usr/local/sbin/configctl clientcontrol health
REMOTE_INSTALL
then
    echo "deployment failed and the target rollback path was executed" >&2
    exit 1
fi

"$ROOT/tools/gc-artifacts.sh" --apply "$CANDIDATE"
echo "installed and verified $CANDIDATE on $TARGET"
