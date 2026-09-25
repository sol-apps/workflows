#!/usr/bin/env python3
"""Verify one Greenlight app tree against its reviewed base and trusted template.

This module is deliberately stdlib-only.  The GitHub action downloads exact commit
archives and a checksum-pinned PocketBase binary before calling ``verify``.  Tests can
call the same entry point with local directories and the pinned development binary.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


TIERS = {"green", "amber", "red"}
RUNTIME_SHAPES = {"static", "datastore", "identity", "scheduler", "endpoint"}
DATA_REACH = {"invented", "own", "reads_sor", "writes_sor", "sends_outward"}
REQUIRED_SPEC_KEYS = (
    "title", "slug", "description", "access", "runtime_shape",
    "data_reach", "blast_radius", "scopes", "tier", "rationale",
)
PROTECTED_FILES = (
    "pb-auth.js",
    "pb_hooks/identity.pb.js",
    "pb_migrations/1756540000_identity.js",
)
REQUIRED_FILES = PROTECTED_FILES
PROTECTED_PREFIXES = (".github/", "design-system/", ".claude/", "vendor/")
CANONICAL_ALWAYS = (".github/lint.py",)
PLACEHOLDER_EXEMPT = {"AGENT.md", "spec.json.example", "DESIGN-SYSTEM-VERSION"}
BANNED_BASENAMES = {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
BINARY_MAGIC = (b"\x7fELF", b"MZ", b"\xca\xfe\xba\xbe", b"PK\x03\x04", b"\x1f\x8b")
MAX_FILE_BYTES = 512 * 1024
RULE_OPERATIONS = ("list", "view", "create", "update", "delete")
COLLECTION_SURFACE = re.compile(r"^(list|view|create|update|delete):([a-z][a-z0-9_]*)$")
STATIC_CHARACTERS = re.compile(r"^/[A-Za-z0-9._~/-]*$")
HOOK_RULES = (
    (
        re.compile(r"\$os\.(?!getenv\b)\w+"),
        "$os.* is forbidden in hooks (only $os.getenv is allowed) — no shelling out or filesystem access",
        lambda spec: True,
    ),
    (
        re.compile(r"\bcronAdd\s*\("),
        "cronAdd requires runtime_shape 'scheduler' in spec.json",
        lambda spec: spec.get("runtime_shape") != "scheduler",
    ),
    (
        re.compile(r"\$http\.send\s*\("),
        "$http.send requires a net:<host> scope in spec.json",
        lambda spec: not any(str(scope).startswith("net:") for scope in (spec.get("scopes") or [])),
    ),
)
REQUIRE_CALL = re.compile(r"""\brequire\s*\(\s*(?!__hooks\b)(.+?)\)""")
WORKFLOW_CONTRACT = Path(__file__).with_name("lint-workflow.yml.template")


@dataclass
class Result:
    failures: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def fail(self, message: str) -> None:
        self.failures.append(message)

    def note(self, message: str) -> None:
        self.notes.append(message)


@dataclass(frozen=True)
class AccessPolicy:
    mode: str
    static_gets: Set[str]
    collection_operations: Set[str]


def _relative_files(root: Path) -> List[str]:
    files: List[str] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if path.is_symlink():
            files.append(relative)
        elif path.is_file():
            files.append(relative)
    return sorted(files)


def _same_file(left: Path, right: Path) -> bool:
    if left.is_symlink() or right.is_symlink():
        return left.is_symlink() and right.is_symlink() and os.readlink(left) == os.readlink(right)
    if not left.is_file() or not right.is_file():
        return not left.exists() and not right.exists()
    if left.stat().st_size != right.stat().st_size:
        return False
    return left.read_bytes() == right.read_bytes()


def _changed_files(base: Path, head: Path) -> List[str]:
    paths = set(_relative_files(base)) | set(_relative_files(head))
    return sorted(path for path in paths if not _same_file(base / path, head / path))


def _read_json(path: Path) -> Optional[dict]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def lint_workflow_refs(path: Path) -> Optional[Tuple[str, str]]:
    """Return (action ref, template ref) only for the exact trusted caller shape."""
    try:
        contract = WORKFLOW_CONTRACT.read_text(encoding="utf-8")
        actual = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    pattern = re.escape(contract)
    pattern = pattern.replace(re.escape("{{ACTION_REF}}"), r"([0-9a-f]{40})")
    pattern = pattern.replace(re.escape("{{TEMPLATE_REF}}"), r"([0-9a-f]{40})")
    match = re.fullmatch(pattern, actual)
    if not match:
        return None
    return match.group(1), match.group(2)


def canonical_static_get(surface: str) -> Tuple[Optional[str], Optional[str]]:
    """Return a canonical static declaration or an explanation of why it is invalid.

    Static declarations are logical browser entry routes, not an asset inventory.
    PocketBase serves ``index.html`` as its fallback, so there are infinitely many
    working URL aliases; only routes deliberately presented by the app belong here.
    """
    if not surface.startswith("GET "):
        return None, "static surfaces use the exact prefix 'GET '"
    path = surface[4:]
    if not path or not STATIC_CHARACTERS.fullmatch(path):
        return None, "the path must be an ASCII origin-relative path without query, fragment, encoding, or backslash"
    if "//" in path:
        return None, "repeated slashes are not canonical"
    if path == "/api" or path.startswith("/api/"):
        return None, "PocketBase API paths are declared as collection operations"
    if path == "/_" or path.startswith("/_/"):
        return None, "PocketBase's operator interface is never an app surface"
    segments = path.split("/")[1:]
    if any(segment in {".", ".."} for segment in segments):
        return None, "dot segments are not canonical"
    normalized = posixpath.normpath(path)
    if path.endswith("/") and path != "/":
        normalized += "/"
    if normalized != path:
        return None, "the path is not in canonical form"
    if path == "/index.html":
        return None, "declare the root page as 'GET /'"
    if path.endswith("/index.html"):
        return None, "declare a directory index with its trailing-slash route"
    return "GET " + path, None


def parse_access(spec: dict, previous: Optional[dict], result: Result) -> Optional[AccessPolicy]:
    access = spec.get("access")
    if access is None and previous is not None and previous.get("access") is None:
        result.note("legacy spec has no access.mode — runtime remains explicitly unclassified")
        return None
    if not isinstance(access, dict):
        result.fail("spec.json access must be an object with mode and anonymous fields")
        return None
    mode = access.get("mode")
    if mode not in {"keycloak", "public"}:
        result.fail("spec.json access.mode must be 'keycloak' or 'public' (missing never means public)")
        return None
    raw = access.get("anonymous")
    if not isinstance(raw, list) or any(not isinstance(item, str) or not item for item in (raw or [])):
        result.fail("spec.json access.anonymous must be an array of non-empty canonical strings")
        return None

    static_gets: Set[str] = set()
    operations: Set[str] = set()
    seen: Set[str] = set()
    for item in raw:
        if item != item.strip():
            result.fail(f"access.anonymous entry {item!r} has surrounding whitespace; declarations must be canonical")
            continue
        if item in seen:
            result.fail(f"access.anonymous contains duplicate declaration {item!r}")
            continue
        seen.add(item)
        if item.lower() in {"all", "everything", "*"}:
            result.fail("access.anonymous must name individual surfaces; 'all' and '*' are not declarations")
            continue
        match = COLLECTION_SURFACE.fullmatch(item)
        if match:
            if match.group(2) == "users":
                result.fail("the users collection cannot be anonymous; public mode closes every account and login surface")
            operations.add(item)
            continue
        canonical, error = canonical_static_get(item)
        if error:
            result.fail(f"invalid anonymous surface {item!r}: {error}")
        else:
            static_gets.add(canonical or item)

    if mode == "keycloak" and raw:
        result.fail("keycloak apps must use access.anonymous: []")
    if mode == "public":
        if not raw:
            result.fail("public apps must enumerate each intended anonymous surface")
        if "GET /" not in static_gets:
            result.fail("public apps must declare 'GET /'; the generated static entrypoint is always reachable")

    if previous is not None:
        old_access = previous.get("access")
        old_mode = (old_access or {}).get("mode") if isinstance(old_access, dict) else "legacy"
        if old_mode == "legacy" and mode == "public":
            result.fail("a legacy app cannot be made public by the generic pipeline; use an app-specific staged migration")
        elif old_mode != "legacy" and old_mode != mode:
            result.fail("access.mode changes require an app-specific staged migration; the generic pipeline refuses them")
        elif old_mode == "legacy" and mode == "keycloak":
            transition = access.get("transition")
            if not isinstance(transition, dict) or any(
                not isinstance(transition.get(key), str) or not transition.get(key).strip()
                for key in ("data", "tokens", "rollback")
            ):
                result.fail("classifying a legacy Keycloak app requires non-empty access.transition.data, tokens and rollback")

    return AccessPolicy(mode=mode, static_gets=static_gets, collection_operations=operations)


def load_spec(head: Path, base: Path, result: Result) -> Tuple[Optional[dict], Optional[AccessPolicy]]:
    path = head / "spec.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        result.fail("spec.json is missing — every generated app declares what it does before it ships")
        return None, None
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        result.fail(f"spec.json is not valid UTF-8 JSON: {error}")
        return None, None
    if not isinstance(value, dict):
        result.fail("spec.json must be a JSON object")
        return None, None

    previous = _read_json(base / "spec.json")
    for key in REQUIRED_SPEC_KEYS:
        if key not in value and not (key == "access" and previous is not None and previous.get("access") is None):
            result.fail(f"spec.json is missing the required key {key!r}")
    if value.get("tier") not in TIERS:
        result.fail(f"spec.json tier must be one of {sorted(TIERS)}, got {value.get('tier')!r}")
    if value.get("runtime_shape") not in RUNTIME_SHAPES:
        result.fail(f"spec.json runtime_shape must be one of {sorted(RUNTIME_SHAPES)}, got {value.get('runtime_shape')!r}")
    if value.get("data_reach") not in DATA_REACH:
        result.fail(f"spec.json data_reach must be one of {sorted(DATA_REACH)}, got {value.get('data_reach')!r}")
    if not isinstance(value.get("scopes"), list):
        result.fail("spec.json scopes must be an array")
    if not str(value.get("rationale", "")).strip():
        result.fail("spec.json rationale must explain why the app landed on its tier")
    return value, parse_access(value, previous, result)


def check_repo_shape(head: Path, files: Sequence[str], result: Result) -> None:
    for relative in files:
        path = head / relative
        if path.is_symlink():
            result.fail(f"{relative}: symbolic links are not allowed in generated apps")
            continue
        base = posixpath.basename(relative)
        if base in BANNED_BASENAMES or relative.startswith("node_modules/") or "/node_modules/" in relative:
            result.fail(f"{relative}: generated apps are node-free and cannot carry package-manager files")
        try:
            size = path.stat().st_size
            first = path.read_bytes()[:4]
        except OSError as error:
            result.fail(f"{relative}: cannot inspect tracked file: {error}")
            continue
        if size > MAX_FILE_BYTES:
            result.fail(f"{relative}: {size // 1024}KB exceeds the {MAX_FILE_BYTES // 1024}KB file limit")
        if any(first.startswith(magic) for magic in BINARY_MAGIC):
            result.fail(f"{relative}: generated apps ship source, not binaries or archives")


def check_placeholders(head: Path, files: Sequence[str], result: Result) -> None:
    pattern = re.compile(r"\{\{[A-Z_]+\}\}")
    for relative in files:
        if relative.startswith(".github/") or relative in PLACEHOLDER_EXEMPT:
            continue
        try:
            text = (head / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        found = sorted(set(pattern.findall(text)))
        if found:
            result.fail(f"{relative}: unreplaced template placeholders {', '.join(found)}")


def pocketbase_backed(tree: Path) -> bool:
    """Whether a reviewed tree carries any part of the PocketBase server seam."""
    if (tree / "pb-auth.js").exists():
        return True
    for prefix in ("pb_hooks", "pb_migrations"):
        directory = tree / prefix
        if directory.is_dir() and any(path.is_file() for path in directory.rglob("*")):
            return True
    return False


def check_protected(base: Path, head: Path, template: Path, result: Result) -> bool:
    changed = _changed_files(base, head)
    requires_identity = pocketbase_backed(base) or pocketbase_backed(head)
    if requires_identity:
        for required in REQUIRED_FILES:
            if not (head / required).is_file() or (head / required).is_symlink():
                result.fail(f"{required} is missing — every PocketBase-backed app ships the platform identity layer")

    # Pre-existing drift in CI is never grandfathered. Identity becomes equally
    # mandatory and canonical as soon as either the reviewed base or proposed tree
    # carries any PocketBase server surface. A truly static public owner app can
    # therefore be backfilled without creating a database merely to satisfy lint,
    # while deleting every identity file from an existing app still fails.
    for relative in CANONICAL_ALWAYS:
        if not _same_file(head / relative, template / relative):
            result.fail(f"{relative}: must exactly match the trusted template commit")
    if requires_identity:
        for relative in PROTECTED_FILES:
            if not _same_file(head / relative, template / relative):
                result.fail(f"{relative}: must exactly match the trusted template commit")

    if lint_workflow_refs(head / ".github/workflows/lint.yml") is None:
        result.fail(
            ".github/workflows/lint.yml: must be the base-branch pull_request_target caller "
            "with full public verifier-bundle pins and split audit/report permissions"
        )

    for relative in changed:
        if relative == ".github/workflows/lint.yml" or relative in CANONICAL_ALWAYS:
            continue
        if not (relative.startswith(PROTECTED_PREFIXES) or relative in PROTECTED_FILES):
            continue
        canonical = template / relative
        current = head / relative
        if _same_file(current, canonical):
            result.note(f"{relative}: converged to the trusted template commit")
        else:
            result.fail(f"{relative}: protected CI, identity, design, instruction, and vendor paths may only converge to the trusted template")
    return requires_identity


def check_hooks(head: Path, files: Sequence[str], spec: dict, policy: Optional[AccessPolicy], result: Result) -> None:
    for relative in files:
        if not relative.startswith("pb_hooks/") or not relative.endswith(".js"):
            continue
        try:
            lines = (head / relative).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as error:
            result.fail(f"{relative}: cannot inspect hook: {error}")
            continue
        if policy and policy.mode == "public" and relative not in PROTECTED_FILES:
            if any(re.search(r"\brouterAdd\s*\(", line) for line in lines):
                result.fail(f"{relative}: public v1 does not allow custom hook routes; use declared PocketBase collection operations")
        for number, line in enumerate(lines, 1):
            for pattern, message, applies in HOOK_RULES:
                if pattern.search(line) and applies(spec):
                    result.fail(f"{relative}:{number}: {message}")
            match = REQUIRE_CALL.search(line)
            if match:
                result.fail(f"{relative}:{number}: require() may only load files under __hooks (got {match.group(1).strip()})")


def check_users_reach(
    head: Path,
    files: Sequence[str],
    policy: Optional[AccessPolicy],
    result: Result,
) -> None:
    hits: List[str] = []
    pattern = re.compile(r"""["']users["']|\busers\b\s*\)""")
    for relative in files:
        if relative in PROTECTED_FILES or not relative.endswith(".js"):
            continue
        if not (relative.startswith("pb_hooks/") or relative.startswith("pb_migrations/")):
            continue
        try:
            text = (head / relative).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "users" in text and pattern.search(text):
            hits.append(relative)
    if not hits:
        return
    message = "app-owned files reach the users collection: " + ", ".join(sorted(hits))
    if policy and policy.mode == "public":
        result.fail(message + " — public apps have no account or identity surface")
    else:
        result.note(message)


def check_public_static(
    files: Sequence[str],
    policy: AccessPolicy,
    result: Result,
) -> None:
    """Match every shipped HTML entrypoint to one reviewed anonymous route."""
    actual: Set[str] = set()
    for relative in files:
        if not relative.endswith(".html"):
            continue
        if relative == "index.html":
            actual.add("GET /")
        elif relative.endswith("/index.html"):
            actual.add("GET /" + relative[:-len("index.html")])
        else:
            actual.add("GET /" + relative)

    undeclared = sorted(actual - policy.static_gets)
    absent = sorted(policy.static_gets - actual)
    if undeclared:
        result.fail("HTML entrypoints absent from access.anonymous: " + ", ".join(undeclared))
    if absent:
        result.fail("access.anonymous declares static entrypoints that are not shipped: " + ", ".join(absent))
    if not undeclared and not absent:
        result.note(f"public static policy matches {len(actual)} shipped HTML entrypoint(s)")


def _clean_pocketbase_env(home: Path) -> Dict[str, str]:
    # PR migrations receive no Actions token, credentials, event payload path, or host
    # home directory.  The two Greenlight values are the exact production/public mode
    # whose final schema is being reviewed.
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "TMPDIR": str(home),
        "LANG": "C.UTF-8",
        "GREENLIGHT_IDENTITY_MODE": "production",
        "GREENLIGHT_ACCESS_MODE": "public",
    }


def _run_checked(command: Sequence[str], env: Dict[str, str], timeout: int, label: str) -> subprocess.CompletedProcess:
    try:
        completed = subprocess.run(
            list(command), env=env, text=True, capture_output=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"{label} exceeded {timeout}s") from error
    if completed.returncode:
        output = (completed.stdout + "\n" + completed.stderr).strip()
        raise RuntimeError(f"{label} failed ({completed.returncode}): {output[-4000:]}")
    return completed


def _request_json(method: str, url: str, body: Optional[dict] = None, token: str = "") -> Tuple[int, dict]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", token)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read()
            return response.status, json.loads(raw or b"{}")
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            parsed = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            parsed = {"body": raw.decode("utf-8", errors="replace")}
        return error.code, parsed


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _collection_rows(pb: str, head: Path) -> List[dict]:
    with tempfile.TemporaryDirectory(prefix="greenlight-schema-audit-") as directory:
        lab = Path(directory)
        data = lab / "pb_data"
        home = lab / "home"
        home.mkdir()
        env = _clean_pocketbase_env(home)
        email = "verifier@invalid.example"
        password = "Verifier-" + secrets.token_urlsafe(24)
        common = [
            "--dir", str(data),
            "--hooksDir", str(head / "pb_hooks"),
            "--migrationsDir", str(head / "pb_migrations"),
        ]
        _run_checked([pb, "superuser", "upsert", email, password] + common, env, 40, "PocketBase migrations")

        port = _free_port()
        command = [
            pb, "serve", "--http", f"127.0.0.1:{port}",
            "--publicDir", str(head),
        ] + common
        log_path = lab / "pocketbase.log"
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, text=True)
            try:
                base_url = f"http://127.0.0.1:{port}"
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        break
                    try:
                        if _request_json("GET", base_url + "/api/health")[0] == 200:
                            break
                    except (OSError, urllib.error.URLError):
                        pass
                    time.sleep(0.1)
                else:
                    raise RuntimeError("PocketBase did not become healthy within 20s")
                if process.poll() is not None:
                    raise RuntimeError("PocketBase exited before its health endpoint became ready")

                status, auth = _request_json(
                    "POST", base_url + "/api/collections/_superusers/auth-with-password",
                    {"identity": email, "password": password},
                )
                if status != 200 or not auth.get("token"):
                    raise RuntimeError(f"disposable operator authentication failed with HTTP {status}")
                status, body = _request_json(
                    "GET", base_url + "/api/collections?perPage=500&skipTotal=1",
                    token=auth["token"],
                )
                if status != 200 or not isinstance(body.get("items"), list):
                    raise RuntimeError(f"collection inventory failed with HTTP {status}")
                return body["items"]
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                log.flush()
                if process.returncode not in (0, -15) and log_path.exists():
                    tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
                    if tail:
                        raise RuntimeError("PocketBase audit process failed: " + tail)


def check_public_schema(pb: str, head: Path, policy: AccessPolicy, result: Result) -> None:
    try:
        collections = _collection_rows(pb, head)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        result.fail(f"public schema could not be audited with PocketBase 0.39.5: {error}")
        return

    by_name = {row.get("name"): row for row in collections if isinstance(row, dict)}
    users = by_name.get("users")
    if not users or users.get("type") != "auth":
        result.fail("the canonical users auth collection is missing or has the wrong type")
    else:
        if users.get("authRule") is not None:
            result.fail("users.authRule must be null in public mode")
        if (users.get("passwordAuth") or {}).get("enabled") is not False:
            result.fail("users.passwordAuth.enabled must be false in public mode")
        if (users.get("oauth2") or {}).get("enabled") is not False:
            result.fail("users.oauth2.enabled must be false in public mode")
        for operation in RULE_OPERATIONS:
            if users.get(operation + "Rule") is not None:
                result.fail(f"users.{operation}Rule must be null in public mode")

    auth_collections = sorted(
        str(row.get("name")) for row in collections
        if row.get("type") == "auth" and row.get("name") not in {"users", "_superusers"}
    )
    if auth_collections:
        result.fail("public apps cannot add auth collections: " + ", ".join(auth_collections))

    actual: Set[str] = set()
    for row in collections:
        name = row.get("name")
        if not isinstance(name, str) or name in {"users", "_superusers"} or name.startswith("_"):
            continue
        for operation in RULE_OPERATIONS:
            if row.get(operation + "Rule") is not None:
                actual.add(f"{operation}:{name}")

    declared = policy.collection_operations
    undeclared = sorted(actual - declared)
    absent = sorted(declared - actual)
    if undeclared:
        result.fail("migrations expose collection operations absent from access.anonymous: " + ", ".join(undeclared))
    if absent:
        result.fail("access.anonymous declares collection operations whose final rule is null: " + ", ".join(absent))
    if not undeclared and not absent:
        result.note(f"public collection policy matches {len(declared)} declared operation(s)")


def verify(base: Path, head: Path, template: Path, pocketbase: str) -> Result:
    result = Result()
    files = _relative_files(head)
    spec, policy = load_spec(head, base, result)
    check_repo_shape(head, files, result)
    check_placeholders(head, files, result)
    backed = check_protected(base, head, template, result)
    if spec is not None:
        check_hooks(head, files, spec, policy, result)
    check_users_reach(head, files, policy, result)

    if policy and policy.mode == "public":
        check_public_static(files, policy, result)

    # Static failures do not make a migration safe to run.  Run PR code only after the
    # cheap controls have established its bounded shape and protected seams.
    if not result.failures and policy and policy.mode == "public":
        if backed:
            check_public_schema(pocketbase, head, policy, result)
        elif policy.collection_operations:
            result.fail("a static app cannot declare PocketBase collection operations")
    return result


def print_result(result: Result, file_count: int, tier: str = "?", mode: str = "?") -> int:
    for message in result.notes:
        print("note: " + message)
    if result.failures:
        print(f"\ngreenlight-lint: {len(result.failures)} problem(s)\n")
        for message in result.failures:
            print("  ✗ " + message)
        print("\nThe PR does not match the reviewed app contract. Fix the code or update")
        print("the spec so the reviewer can see the exact surface that would ship.")
        return 1
    print(f"greenlight-lint: clean — {file_count} files, declared tier {tier!r}, access {mode!r}")
    return 0
