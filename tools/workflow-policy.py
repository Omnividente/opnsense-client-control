#!/usr/bin/env python3
"""Repository-specific security policy for GitHub Actions workflows."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


USES_RE = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)")
FULL_SHA_ACTION_RE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
PINNED_DOCKER_RE = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")


def permissions(text: str) -> dict[str, str] | None:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line != "permissions:":
            continue
        result: dict[str, str] = {}
        for child in lines[index + 1 :]:
            if not child.strip() or child.lstrip().startswith("#"):
                continue
            if not child.startswith("  "):
                break
            match = re.fullmatch(r"  ([a-z-]+):\s*(read|write|none)\s*", child)
            if match:
                result[match.group(1)] = match.group(2)
        return result
    return None


def workflow_violations(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    name = path.name

    if re.search(r"(?m)^\s*pull_request_target\s*:", text):
        errors.append("pull_request_target is forbidden")
    if re.search(r"(?m)^\s*runs-on\s*:.*\bself-hosted\b", text):
        errors.append("self-hosted runners are forbidden")
    if "${{ secrets." in text:
        errors.append("repository workflows must not read configured secrets")
    if re.search(r"(?m)^\s*continue-on-error\s*:\s*true\s*$", text):
        errors.append("continue-on-error: true can hide a failed check")

    for action in USES_RE.findall(text):
        if action.startswith("./") or PINNED_DOCKER_RE.fullmatch(action):
            continue
        if not FULL_SHA_ACTION_RE.fullmatch(action):
            errors.append(f"remote action is not pinned to a full SHA: {action}")

    granted = permissions(text)
    if granted is None:
        errors.append("top-level permissions block is required")
    else:
        allowed_write = {"issues"} if name == "review-attestation.yml" else set()
        for scope, level in granted.items():
            if level == "write" and scope not in allowed_write:
                errors.append(f"unexpected write permission: {scope}")

    if name == "github-review.yml":
        if not re.search(r"(?m)^  pull_request:\s*$", text):
            errors.append("GitHub-only review must run for pull_request")
        if granted != {"contents": "read"}:
            errors.append("GitHub-only review permissions must be exactly contents: read")

    if name == "review-attestation.yml":
        expected = {
            "actions": "read",
            "contents": "read",
            "issues": "write",
            "pull-requests": "read",
        }
        if granted != expected:
            errors.append("review attestation permissions do not match the narrow policy")
        if not re.search(r"(?m)^  issues:\s*$", text):
            errors.append("review attestation must run for issue events")

    return errors


def self_test() -> None:
    pin = "a" * 40
    safe = f"""name: safe
on:
  pull_request:
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@{pin}
"""
    assert workflow_violations(Path("sample.yml"), safe) == []

    cases = {
        "pull_request_target": safe.replace("pull_request:", "pull_request_target:"),
        "self-hosted": safe.replace("ubuntu-24.04", "self-hosted"),
        "unpinned": safe.replace(f"actions/checkout@{pin}", "actions/checkout@v7"),
        "secret": safe + "      - run: echo '${{ secrets.TOKEN }}'\n",
    }
    for expected, source in cases.items():
        found = workflow_violations(Path("sample.yml"), source)
        assert found, f"policy negative control did not reject {expected}"
    print("ok workflow policy negative controls")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()

    if args.self_test:
        self_test()
    if not args.paths:
        return 0

    failed = False
    for raw_path in args.paths:
        path = Path(raw_path)
        for error in workflow_violations(path, path.read_text(encoding="utf-8")):
            print(f"{path}: {error}", file=sys.stderr)
            failed = True
    if failed:
        return 1
    print(f"ok workflow policy ({len(args.paths)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
