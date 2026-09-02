#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
PHP=${PHP:-php}
PYTHON=${PYTHON:-python3}
NODE=${NODE:-node}
SHELLCHECK=${SHELLCHECK:-shellcheck}
XMLLINT=${XMLLINT:-xmllint}
ACTIONLINT=${ACTIONLINT:-actionlint}
TMP=

cd "$ROOT"

for tool in git msgfmt find xargs sed "$PHP" "$PYTHON" "$NODE" "$SHELLCHECK" "$XMLLINT" "$ACTIONLINT"; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing GitHub review tool: $tool" >&2
        exit 1
    }
done

TMP=$(mktemp -d "${TMPDIR:-/tmp}/client-control-github-checks.XXXXXX")
trap 'rm -rf "${TMP:-}"' EXIT HUP INT TERM

tool_versions() {
    git --version
    "$PHP" -r 'echo "PHP ", PHP_VERSION, "\n";'
    "$PYTHON" --version 2>&1
    "$NODE" --version
    "$SHELLCHECK" --version | sed -n '2p'
    "$XMLLINT" --version 2>&1 | sed -n '1p'
    msgfmt --version | sed -n '1p'
    "$ACTIONLINT" -version
}

tool_versions
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo '### Validation tool versions'
        echo
        echo '```text'
        tool_versions
        echo '```'
    } >> "$GITHUB_STEP_SUMMARY"
fi

# The PHP snippet is single-quoted deliberately so the shell cannot expand PHP variables.
# shellcheck disable=SC2016
"$PHP" -r '
foreach (["gettext", "SimpleXML"] as $extension) {
    if (!extension_loaded($extension)) {
        fwrite(STDERR, "missing PHP extension: {$extension}\n");
        exit(1);
    }
}
if (setlocale(LC_MESSAGES, "ru_RU.UTF-8") === false) {
    fwrite(STDERR, "missing locale: ru_RU.UTF-8\n");
    exit(1);
}
'

php_lint_tree() {
    find "$@" -type f -name '*.php' -print0 |
        xargs -0 -r -n1 "$PHP" -l
}

printf '%s\n' '<?php function intentionally_broken( {' > "$TMP/invalid.php"
if php_lint_tree "$TMP" >/dev/null 2>&1; then
    echo 'PHP lint negative control unexpectedly passed' >&2
    exit 1
fi
printf 'ok PHP lint negative control\n'
php_lint_tree src tests

find src -type f -name '*.xml' -exec "$XMLLINT" --noout {} +

git ls-files -z -- '*.sh' '+*.pre' '+*.post' |
    xargs -0 -r "$SHELLCHECK"
sh tests/deploy-health-contract.sh
"$NODE" tests/ui-contract.mjs

for executable_hook in \
    src/etc/rc.syshook.d/start/90-clientcontrol \
    src/opnsense/scripts/Volgodon/ClientControl/audit_rotate.sh
do
    executable_index=$(git ls-files -s -- "$executable_hook")
    case "$executable_index" in
        '100755 '*) ;;
        *)
            echo "Client Control runtime hook must be tracked with mode 100755: $executable_hook" >&2
            exit 1
            ;;
    esac
done

"$ACTIONLINT" -color
"$PYTHON" tools/workflow-policy.py --self-test
# Deliberately omit xargs -r: an empty tracked set must invoke the policy and fail closed.
git ls-files -z -- '.github/workflows/*.yml' '.github/workflows/*.yaml' |
    xargs -0 "$PYTHON" tools/workflow-policy.py

"$PYTHON" -m py_compile \
    tests/api-smoke.py \
    tools/review-attestation.py \
    tools/workflow-policy.py
rm -rf tests/__pycache__ tools/__pycache__
"$PYTHON" tools/review-attestation.py --self-test

"$ROOT/tools/compile-translations.sh" >/dev/null
LANG=ru_RU.UTF-8 LC_ALL=ru_RU.UTF-8 "$PHP" tests/run.php

git diff --exit-code -- \
    translations/ru_RU.po.sha256 \
    translations/ru_RU.mo.sha256 \
    src/share/locale/ru_RU/LC_MESSAGES/os-client-control.mo

tracked_artifacts=$(git ls-files -- '*.pkg' '*.txz' '.build/**' 'dist/**')
if [ -n "$tracked_artifacts" ]; then
    echo "generated artifacts must not be committed:" >&2
    printf '%s\n' "$tracked_artifacts" >&2
    exit 1
fi

printf 'ok GitHub-only repository checks\n'
