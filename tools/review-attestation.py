#!/usr/bin/env python3
"""Classify GitHub review issues using public commit, PR, and run identities."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


MARKER = "<!-- client-control-review-attestation -->"
SHA_RE = re.compile(
    r"(?ims)^###\s+Проверенный commit SHA\s*$\s*`?([0-9a-f]{40})`?"
)
REVIEWER_RE = re.compile(
    r"(?ims)^###\s+GitHub-логин проверяющего\s*$\s*`?@?([A-Za-z0-9-]+)`?"
)


def extract_review_sha(body: str) -> str | None:
    match = SHA_RE.search(body)
    return match.group(1).lower() if match else None


def extract_declared_reviewer(body: str) -> str | None:
    match = REVIEWER_RE.search(body)
    return match.group(1) if match else None


def classify(issue_author: str, known_authors: set[str], declared: str | None) -> str:
    issue_login = issue_author.casefold()
    known = {login.casefold() for login in known_authors}
    if declared and declared.casefold() != issue_login:
        return "declared-login-mismatch"
    if issue_login in known:
        return "self-review"
    if known:
        return "independent-candidate"
    return "identity-unverified"


def api_json(method: str, path: str, payload: object | None = None) -> Any:
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise RuntimeError("GITHUB_TOKEN is required")
    base = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        base + path,
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "User-Agent": "client-control-review-attestation",
            "X-GitHub-Api-Version": "2026-03-10",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            content = response.read()
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        raise RuntimeError(f"GitHub API {method} {path} failed: {error.code} {detail}") from error
    return json.loads(content) if content else None


def add_login(logins: set[str], node: object) -> None:
    if isinstance(node, dict) and isinstance(node.get("login"), str):
        logins.add(node["login"])


def known_authors(repository: str, sha: str) -> set[str]:
    quoted_sha = urllib.parse.quote(sha, safe="")
    logins: set[str] = set()

    commit = api_json("GET", f"/repos/{repository}/commits/{quoted_sha}")
    add_login(logins, commit.get("author"))
    add_login(logins, commit.get("committer"))

    pulls = api_json("GET", f"/repos/{repository}/commits/{quoted_sha}/pulls")
    for pull in pulls:
        add_login(logins, pull.get("user"))

    query = urllib.parse.urlencode({"head_sha": sha, "per_page": 100})
    runs = api_json("GET", f"/repos/{repository}/actions/runs?{query}")
    for run in runs.get("workflow_runs", []):
        add_login(logins, run.get("actor"))
        add_login(logins, run.get("triggering_actor"))
    return logins


def result_text(status: str) -> str:
    return {
        "self-review": "SELF-REVIEW: автор issue связан с commit, pull request или Actions run.",
        "independent-candidate": "CANDIDATE: публичные GitHub identities не связывают автора issue с проверяемой ревизией.",
        "identity-unverified": "UNVERIFIED: GitHub не дал identity, с которой можно сравнить автора issue.",
        "declared-login-mismatch": "INVALID: заявленный login проверяющего не совпадает с автором issue.",
        "missing-sha": "INVALID: в отчёте нет поля с полным проверяемым commit SHA.",
    }[status]


def attestation_body(
    issue_author: str,
    declared: str | None,
    sha: str | None,
    authors: set[str],
    status: str,
) -> str:
    known = ", ".join(f"@{login}" for login in sorted(authors, key=str.casefold)) or "не найдены"
    reviewed = f"[`{sha}`](https://github.com/{os.environ['GITHUB_REPOSITORY']}/commit/{sha})" if sha else "не определён"
    declared_text = f"@{declared}" if declared else "не указан"
    return f"""{MARKER}
## Автоматическая проверка identity

- Проверяемый commit: {reviewed}
- Автор issue по GitHub event: @{issue_author}
- Login, заявленный в форме: {declared_text}
- Связанные GitHub identities commit/PR/run: {known}
- Результат: **{result_text(status)}**

Форма Issue — только интерфейс ввода: GitHub API может обойти её обязательные поля. Этот комментарий использует фактического автора issue из GitHub event. Статус `CANDIDATE` не доказывает человеческую независимость и не подтверждает полноту ревью; он лишь исключает найденное автоматикой совпадение identities.
"""


def upsert_comment(repository: str, issue_number: int, body: str) -> None:
    comments = api_json("GET", f"/repos/{repository}/issues/{issue_number}/comments?per_page=100")
    for comment in comments:
        if isinstance(comment.get("body"), str) and comment["body"].startswith(MARKER):
            api_json("PATCH", f"/repos/{repository}/issues/comments/{comment['id']}", {"body": body})
            return
    api_json("POST", f"/repos/{repository}/issues/{issue_number}/comments", {"body": body})


def self_test() -> None:
    sha = "54dc64f6bc50e5bb22233786c1ec6496a9fec865"
    body = f"### Проверенный commit SHA\n\n`{sha}`\n\n### GitHub-логин проверяющего\n\n`reviewer`\n"
    assert extract_review_sha(body) == sha
    assert extract_declared_reviewer(body) == "reviewer"
    assert classify("author", {"author"}, "author") == "self-review"
    assert classify("reviewer", {"author"}, "reviewer") == "independent-candidate"
    assert classify("reviewer", set(), "reviewer") == "identity-unverified"
    assert classify("reviewer", {"author"}, "someone-else") == "declared-login-mismatch"
    print("ok review attestation self-tests")


def load_issue() -> tuple[dict[str, Any], int]:
    repository = os.environ["GITHUB_REPOSITORY"]
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    event = json.loads(Path(event_path).read_text(encoding="utf-8")) if event_path else {}
    issue = event.get("issue")
    if isinstance(issue, dict):
        return issue, int(issue["number"])

    raw_number = os.environ.get("REVIEW_ISSUE_NUMBER", "")
    if not raw_number.isdigit():
        raise RuntimeError("REVIEW_ISSUE_NUMBER is required for workflow_dispatch")
    number = int(raw_number)
    return api_json("GET", f"/repos/{repository}/issues/{number}"), number


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0

    repository = os.environ["GITHUB_REPOSITORY"]
    issue, issue_number = load_issue()
    if "pull_request" in issue or not str(issue.get("title", "")).startswith("[Review]"):
        print("issue is not a review report; no attestation needed")
        return 0

    body = str(issue.get("body") or "")
    issue_author = issue["user"]["login"]
    declared = extract_declared_reviewer(body)
    sha = extract_review_sha(body)
    authors: set[str] = set()
    if sha:
        authors = known_authors(repository, sha)
        status = classify(issue_author, authors, declared)
    else:
        status = "missing-sha"

    comment = attestation_body(issue_author, declared, sha, authors, status)
    upsert_comment(repository, issue_number, comment)
    print(f"review attestation: {status}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(comment.replace(MARKER + "\n", ""))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"review attestation failed: {error}", file=sys.stderr)
        raise
