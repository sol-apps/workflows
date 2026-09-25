#!/usr/bin/env python3
"""Fetch exact public commit archives and run the immutable Greenlight verifier."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Optional, Tuple

from verify import lint_workflow_refs, print_result, verify


SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PB_VERSION = "0.39.5"
PB_LINUX_AMD64_SHA256 = "be407d824bcc41468b99051f356fbba9af7f0efd9b46c168482ae25296e799c7"
MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_TREE_BYTES = 48 * 1024 * 1024
MAX_TREE_FILES = 5000
USER_AGENT = "greenlight-pr-verifier/1"
RELEASE_REPOSITORY = "sol-apps/workflows"


class VerificationSetupError(RuntimeError):
    pass


def _validate_sha(value: str, label: str) -> str:
    if not SHA.fullmatch(value or ""):
        raise VerificationSetupError(f"{label} must be a lowercase full 40-character commit SHA")
    return value


def _validate_repository(value: str, label: str, require_org: bool = False) -> str:
    if not REPOSITORY.fullmatch(value or ""):
        raise VerificationSetupError(f"{label} is not an owner/repository name")
    if require_org and not value.startswith("sol-apps/"):
        raise VerificationSetupError(f"{label} must belong to sol-apps")
    return value


def _download(url: str, destination: Path, limit: int = MAX_DOWNLOAD) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/octet-stream"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response, destination.open("wb") as output:
            final = urllib.parse.urlparse(response.geturl())
            if final.scheme != "https" or final.hostname not in {
                "codeload.github.com", "github.com", "objects.githubusercontent.com",
                "release-assets.githubusercontent.com", "api.github.com",
            }:
                raise VerificationSetupError(f"download redirected to untrusted origin {final.hostname!r}")
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise VerificationSetupError(f"download exceeds {limit // (1024 * 1024)}MB limit")
                output.write(chunk)
    except (OSError, urllib.error.URLError) as error:
        raise VerificationSetupError(f"download failed for {url}: {error}") from error


def _archive(repository: str, commit: str, destination: Path, selected: Optional[str] = None) -> None:
    archive = destination.parent / (destination.name + ".tar.gz")
    url = f"https://codeload.github.com/{repository}/tar.gz/{commit}"
    _download(url, archive)
    destination.mkdir()
    wanted = tuple(PurePosixPath(selected).parts) if selected else ()
    seen = set()
    count = 0
    total = 0
    try:
        with tarfile.open(archive, "r:gz") as source:
            for member in source.getmembers():
                parts = PurePosixPath(member.name).parts
                if len(parts) < 1 or any(part in {"", ".", ".."} for part in parts):
                    raise VerificationSetupError("commit archive contains a non-canonical path")
                relative_parts = parts[1:]
                if wanted:
                    if relative_parts[:len(wanted)] != wanted:
                        continue
                    relative_parts = relative_parts[len(wanted):]
                if not relative_parts:
                    continue
                if any(any(ord(char) < 32 for char in part) for part in relative_parts):
                    raise VerificationSetupError("commit archive contains control characters in a path")
                relative = PurePosixPath(*relative_parts).as_posix()
                if relative in seen:
                    raise VerificationSetupError(f"commit archive repeats {relative!r}")
                seen.add(relative)
                target = destination.joinpath(*relative_parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise VerificationSetupError(f"commit archive contains unsupported link or device {relative!r}")
                count += 1
                total += member.size
                if count > MAX_TREE_FILES or total > MAX_TREE_BYTES:
                    raise VerificationSetupError("commit tree exceeds the verifier's bounded extraction limits")
                if member.size > 512 * 1024:
                    raise VerificationSetupError(f"{relative}: exceeds the generated-app file limit")
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = source.extractfile(member)
                if extracted is None:
                    raise VerificationSetupError(f"could not read {relative!r} from commit archive")
                with target.open("wb") as output:
                    shutil.copyfileobj(extracted, output, length=1024 * 1024)
                target.chmod(0o644)
    except (OSError, tarfile.TarError) as error:
        raise VerificationSetupError(f"invalid commit archive: {error}") from error
    finally:
        archive.unlink(missing_ok=True)


def _is_descendant(base: str, candidate: str) -> bool:
    if base == candidate:
        return True
    url = f"https://api.github.com/repos/{RELEASE_REPOSITORY}/compare/{base}...{candidate}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            value = json.loads(response.read())
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise VerificationSetupError(f"could not verify public verifier-bundle ancestry: {error}") from error
    return value.get("status") in {"identical", "ahead"}


def _trusted_refs(base: Path, head: Path, running_action_ref: str, requested_template_ref: str) -> Tuple[str, str]:
    base_refs = lint_workflow_refs(base / ".github/workflows/lint.yml")
    head_refs = lint_workflow_refs(head / ".github/workflows/lint.yml")
    _validate_sha(running_action_ref, "running action ref")
    _validate_sha(requested_template_ref, "template ref input")
    if base_refs is None:
        raise VerificationSetupError("the reviewed base does not contain the immutable Greenlight workflow contract")
    if base_refs[0] != running_action_ref:
        raise VerificationSetupError("the running action ref differs from the reviewed base workflow pin")
    if base_refs[1] != requested_template_ref:
        raise VerificationSetupError("the template ref input differs from the reviewed base workflow pin")
    if head_refs is None:
        return base_refs
    for label, old, new in (
        ("verifier action", base_refs[0], head_refs[0]),
        ("canonical template", base_refs[1], head_refs[1]),
    ):
        if not _is_descendant(old, new):
            raise VerificationSetupError(
                f"the PR moves the {label} pin backward or off the reviewed public verifier-bundle history"
            )
    return head_refs


def _pocketbase(lab: Path) -> Path:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise VerificationSetupError("the immutable action supports the declared ubuntu-latest linux_amd64 runner only")
    archive = lab / "pocketbase.zip"
    url = f"https://github.com/pocketbase/pocketbase/releases/download/v{PB_VERSION}/pocketbase_{PB_VERSION}_linux_amd64.zip"
    _download(url, archive)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != PB_LINUX_AMD64_SHA256:
        raise VerificationSetupError(f"PocketBase archive checksum mismatch: got {digest}")
    try:
        with zipfile.ZipFile(archive) as package:
            info = package.getinfo("pocketbase")
            if info.file_size > 100 * 1024 * 1024:
                raise VerificationSetupError("PocketBase binary exceeds expected size")
            binary = lab / "pocketbase"
            with package.open(info) as source, binary.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
    except (KeyError, OSError, zipfile.BadZipFile) as error:
        raise VerificationSetupError(f"invalid PocketBase release archive: {error}") from error
    binary.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    version = subprocess_version(binary)
    if version != f"pocketbase version {PB_VERSION}":
        raise VerificationSetupError(f"unexpected PocketBase binary version: {version!r}")
    return binary


def subprocess_version(binary: Path) -> str:
    import subprocess
    try:
        completed = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=10, check=True)
    except (OSError, subprocess.SubprocessError) as error:
        raise VerificationSetupError(f"could not execute PocketBase: {error}") from error
    return completed.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--head-repository", required=True)
    parser.add_argument("--pull-request", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--template-ref", required=True)
    parser.add_argument("--running-action-ref", required=True)
    args = parser.parse_args()

    repository = _validate_repository(args.repository, "base repository", require_org=True)
    head_repository = _validate_repository(args.head_repository, "head repository")
    base_sha = _validate_sha(args.base_sha, "base SHA")
    head_sha = _validate_sha(args.head_sha, "head SHA")
    if not re.fullmatch(r"[1-9][0-9]*", args.pull_request or ""):
        raise VerificationSetupError("pull request number is invalid")

    with tempfile.TemporaryDirectory(prefix="greenlight-pr-") as directory:
        lab = Path(directory)
        base = lab / "base"
        head = lab / "head"
        template = lab / "template"
        _archive(repository, base_sha, base)
        _archive(head_repository, head_sha, head)
        _, template_ref = _trusted_refs(
            base, head, args.running_action_ref, args.template_ref
        )
        _archive(RELEASE_REPOSITORY, template_ref, template, selected="greenlight/app-template")
        pb = _pocketbase(lab)
        result = verify(base, head, template, str(pb))
        spec = {}
        try:
            spec = json.loads((head / "spec.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            pass
        mode = ((spec.get("access") or {}).get("mode", "?") if isinstance(spec, dict) else "?")
        tier = spec.get("tier", "?") if isinstance(spec, dict) else "?"
        return print_result(result, len([p for p in head.rglob("*") if p.is_file()]), tier, mode)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except VerificationSetupError as error:
        print(f"::error::{error}", file=sys.stderr)
        sys.exit(1)
