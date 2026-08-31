#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
PHP=${PHP:-php}
PYTHON=${PYTHON:-python3}
SHELLCHECK=${SHELLCHECK:-shellcheck}
XMLLINT=${XMLLINT:-xmllint}

cd "$ROOT"

for tool in git msgfmt "$PHP" "$PYTHON" "$SHELLCHECK" "$XMLLINT"; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing GitHub review tool: $tool" >&2
        exit 1
    }
done

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

find src tests -type f -name '*.php' -exec "$PHP" -l {} \; >/dev/null
find src -type f -name '*.xml' -exec "$XMLLINT" --noout {} +

"$SHELLCHECK" \
    +POST_DEINSTALL.post \
    +POST_INSTALL.post \
    +PRE_DEINSTALL.pre \
    tools/bootstrap-build-kit.sh \
    tools/build-local.sh \
    tools/compile-translations.sh \
    tools/deploy.sh \
    tools/gc-artifacts.sh \
    tools/github-checks.sh

"$PYTHON" -m py_compile tests/api-smoke.py
rm -rf tests/__pycache__

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
