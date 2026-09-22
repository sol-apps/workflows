#!/usr/bin/env python3
"""Publish greenlight-lint on the PR head from the isolated report job."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request


SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^sol-apps/[A-Za-z0-9_.-]+$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--audit-result", required=True)
    parser.add_argument("--run-url", required=True)
    args = parser.parse_args()
    token = os.environ.get("GREENLIGHT_REPORT_TOKEN", "")
    if not token:
        raise RuntimeError("report job received no checks:write token")
    if not REPOSITORY.fullmatch(args.repository):
        raise RuntimeError("report repository is not a sol-apps repository")
    if not SHA.fullmatch(args.head_sha):
        raise RuntimeError("report head SHA is not a full lowercase commit")
    if not args.run_url.startswith(f"https://github.com/{args.repository}/actions/runs/"):
        raise RuntimeError("report workflow URL is outside the target repository")

    passed = args.audit_result == "success"
    payload = {
        "name": "greenlight-lint",
        "head_sha": args.head_sha,
        "status": "completed",
        "conclusion": "success" if passed else "failure",
        "details_url": args.run_url,
        "output": {
            "title": "Greenlight contract verified" if passed else "Greenlight contract rejected",
            "summary": (
                "The permissionless immutable verifier passed."
                if passed else
                f"The permissionless audit job ended as {args.audit_result!r}. Open the workflow run for findings."
            ),
        },
    }
    request = urllib.request.Request(
        f"https://api.github.com/repos/{args.repository}/check-runs",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "greenlight-pr-verifier/1",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 201:
                raise RuntimeError(f"Checks API returned HTTP {response.status}")
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Checks API returned HTTP {error.code}: {body[:1000]}") from error
    print(f"greenlight-lint: {'success' if passed else 'failure'} published for {args.head_sha[:12]}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, urllib.error.URLError) as error:
        print(f"::error::{error}", file=sys.stderr)
        sys.exit(1)
