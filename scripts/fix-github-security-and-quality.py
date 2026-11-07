#!/usr/bin/env python3
"""Unattended GitHub Security and quality remediator for crontab.

First squash-merges green PRs from the official github.com/apps/dependabot
App (delegates to merge-dependabot-prs.py; identity is fail-closed there).
Then reads open items from the repository Security and quality tab
(Dependabot alerts, CodeQL code scanning, GitHub Code Quality, secret
scanning), applies remediations that can be done without a human, opens
one PR, waits for CI, and squash-merges.

Dependabot PR merge runs even when later alert remediations fail, so a
resolver conflict in uv.lock cannot leave official green Dependabot PRs
unmerged. Unsatisfiable Python bumps are skipped per package.

Cron (UTC). The daily remediator is 00:55; Dependabot's weekly sweep is
Monday 06:00, so merge-dependabot-prs.py also runs every 30 minutes:

    55 0 * * * HOME=/root /home/codex/wairz/scripts/fix-github-security-and-quality.py \\
        >>/var/log/wairz-security-quality.log 2>&1
    */30 * * * * HOME=/root /home/codex/wairz/scripts/merge-dependabot-prs.py \\
        >>/var/log/wairz-merge-dependabot.log 2>&1

Requires: git, gh (authenticated with repo + workflow scopes), uv, npm.
No TTY, no prompts. Overlapping runs self-skip via flock.

Cron must run as the user whose ``gh auth status`` succeeds. HOME has to
be set so gh can read ``~/.config/gh/hosts.yml`` (or export GH_TOKEN).
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
BRANCH = "fix/security-and-quality"
LOCK_PATH = Path("/tmp/wairz-fix-github-security-and-quality.lock")
MERGER = Path(__file__).resolve().parent / "merge-dependabot-prs.py"
MERGER_TIMEOUT_SEC = 300
POLL_SEC = 30
DEFAULT_CI_TIMEOUT_SEC = 90 * 60
CHECKS_GRACE_SEC = 90
CANCEL_GRACE_SEC = 120

PIP_ECOSYSTEMS = {"pip", "pipenv", "poetry", "uv"}
NPM_ECOSYSTEMS = {"npm", "yarn", "pnpm"}


# ---------------------------------------------------------------------------
# logging / process helpers
# ---------------------------------------------------------------------------

def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"{ts} {msg}", flush=True)


def configure_noninteractive() -> None:
    os.environ.setdefault("PATH", "")
    extra = [
        str(Path.home() / ".local" / "bin"),
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
    ]
    os.environ["PATH"] = ":".join(extra + os.environ["PATH"].split(":"))
    os.environ["GIT_TERMINAL_PROMPT"] = "0"
    os.environ["GIT_EDITOR"] = "true"
    os.environ["EDITOR"] = "true"
    os.environ["VISUAL"] = "true"
    os.environ["GH_PROMPT_DISABLED"] = "1"
    os.environ["GH_PAGER"] = "cat"
    os.environ["PAGER"] = "cat"
    os.environ["CI"] = "true"
    os.environ["NPM_CONFIG_FUND"] = "false"
    os.environ["NPM_CONFIG_AUDIT"] = "false"
    os.environ["NPM_CONFIG_UPDATE_NOTIFIER"] = "false"
    try:
        sys.stdin.close()
    except Exception:
        pass
    sys.stdin = open(os.devnull)


def acquire_lock() -> Any:
    fh = open(LOCK_PATH, "w")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log("another run holds the lock; exiting")
        sys.exit(0)
    fh.write(str(os.getpid()))
    fh.flush()
    return fh


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    input_text: str | None = None,
    check: bool = True,
    timeout: int = 120,
    quiet: bool = False,
) -> subprocess.CompletedProcess[str]:
    printable = " ".join(cmd)
    if not quiet:
        log(f"+ {printable}")
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"timed out after {timeout}s: {printable}") from exc
    if proc.returncode != 0:
        err = (proc.stderr or "").strip()
        out = (proc.stdout or "").strip()
        detail = err or out or f"exit {proc.returncode}"
        if check:
            raise RuntimeError(f"command failed ({proc.returncode}): {printable}\n{detail}")
    return proc


def which_or_die(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"required tool not found on PATH: {name}")
    return path


def _short_exc(exc: BaseException) -> str:
    text = str(exc).strip().replace("\n", " | ")
    return text[:500]


def merge_green_dependabot_prs(*, dry_run: bool) -> None:
    """Merge official green Dependabot PRs before alert remediation.

    Failures here must not abort the remediator: the sibling merger has its
    own flock, and a uv.lock conflict later must not strand green PRs.
    Stdio is inherited so cron logs capture the merger's decisions.
    """
    if not MERGER.is_file():
        log(f"dependabot merger not found at {MERGER}; skipping PR merge")
        return
    cmd = [sys.executable, str(MERGER)]
    if dry_run:
        cmd.append("--dry-run")
    log("merging green official Dependabot PRs (before alert remediation)")
    try:
        proc = subprocess.run(cmd, cwd=str(REPO), timeout=MERGER_TIMEOUT_SEC, check=False)
    except subprocess.TimeoutExpired:
        log(f"dependabot merger timed out after {MERGER_TIMEOUT_SEC}s; continuing")
        return
    if proc.returncode != 0:
        log(
            f"dependabot merger exited {proc.returncode}; "
            "continuing with alert remediation"
        )
        return
    log("dependabot merger finished")


# ---------------------------------------------------------------------------
# GitHub REST via `gh api` (works on gh 2.4 as well as current)
# ---------------------------------------------------------------------------

class GitHubError(RuntimeError):
    def __init__(self, status: int | None, message: str, body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


def gh_api(
    endpoint: str,
    method: str = "GET",
    body: Any | None = None,
    headers: list[str] | None = None,
    allow_statuses: tuple[int, ...] = (),
) -> Any:
    cmd = [
        "gh", "api", "--method", method, endpoint,
        "-H", "Accept: application/vnd.github+json",
        "--include",
    ]
    if headers:
        for h in headers:
            cmd.extend(["-H", h])
    input_text = None
    if body is not None:
        cmd.extend(["--input", "-"])
        input_text = json.dumps(body)
    proc = run(
        cmd,
        cwd=REPO,
        input_text=input_text,
        check=False,
        timeout=90,
        quiet=True,
    )
    raw = proc.stdout or ""
    status, payload = _split_gh_include(raw)
    if proc.returncode != 0 and status not in allow_statuses:
        if isinstance(payload, dict):
            msg = str(payload.get("message") or payload)
        else:
            msg = ((proc.stderr or "") + "\n" + raw)[-500:]
        raise GitHubError(status, f"gh api {method} {endpoint} -> {status}: {msg}", payload)
    return payload


def _split_gh_include(raw: str) -> tuple[int | None, Any]:
    """Parse `gh api --include` output into (status, json-or-text)."""
    if not raw:
        return None, None
    # Headers then blank line then body. gh may concatenate pages; we only
    # ever send one request here.
    parts = raw.split("\r\n\r\n", 1)
    if len(parts) == 1:
        parts = raw.split("\n\n", 1)
    header, body = (parts[0], parts[1] if len(parts) > 1 else "")
    status = None
    for line in header.splitlines():
        m = re.match(r"HTTP/\S+\s+(\d+)", line)
        if m:
            status = int(m.group(1))
    body = body.strip()
    if not body:
        return status, None
    try:
        return status, json.loads(body)
    except json.JSONDecodeError:
        return status, body


def gh_api_paged(endpoint: str, headers: list[str] | None = None) -> list[Any]:
    """List endpoints. Uses Link-header pagination (Dependabot rejects `page=`)."""
    sep = "&" if "?" in endpoint else "?"
    url = f"{endpoint}{sep}per_page=100"
    cmd = [
        "gh", "api", "--paginate", "--method", "GET", url,
        "-H", "Accept: application/vnd.github+json",
    ]
    if headers:
        for h in headers:
            cmd.extend(["-H", h])
    proc = run(cmd, cwd=REPO, check=False, timeout=180, quiet=True)
    raw = (proc.stdout or "").strip()
    if proc.returncode != 0:
        err_body: Any = None
        try:
            err_body = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            err_body = None
        status = None
        if isinstance(err_body, dict):
            try:
                status = int(err_body.get("status") or 0) or None
            except (TypeError, ValueError):
                status = None
            if status in (404, 403) or str(err_body.get("status")) in {"404", "403"}:
                return []
            msg = str(err_body.get("message") or err_body)
        else:
            msg = ((proc.stderr or "") + "\n" + raw)[-500:]
        raise GitHubError(status, f"gh api GET {url} failed: {msg}", err_body)
    return _parse_paginated_arrays(raw)


def _parse_paginated_arrays(raw: str) -> list[Any]:
    raw = raw.strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # gh 2.4 --paginate concatenates JSON arrays as `][`.
        merged = re.sub(r"\]\s*\[", ",", raw)
        data = json.loads(merged)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and data.get("message"):
        return []
    return []


# ---------------------------------------------------------------------------
# version helpers
# ---------------------------------------------------------------------------

def version_key(value: str) -> tuple[int, ...]:
    value = (value or "").strip().lstrip("vV")
    nums: list[int] = []
    for part in re.split(r"[.\-+_]", value):
        if part.isdigit():
            nums.append(int(part))
        elif nums:
            break
    return tuple(nums) if nums else (0,)


def version_ge(a: str, b: str) -> bool:
    return version_key(a) >= version_key(b)


def max_version(versions: list[str]) -> str:
    return max(versions, key=version_key)


# ---------------------------------------------------------------------------
# pyproject.toml / package.json editors
# ---------------------------------------------------------------------------

# Dependabot.yml: major bumps need review. Cap unattended floors at the
# next major of the patched version so `uv lock` cannot jump mcp 1.x → 2.x.


def capped_spec(version: str) -> str:
    major = version_key(version)[0]
    return f">={version},<{major + 1}"


def raise_floor(text: str, package: str, new_version: str) -> str:
    pattern = re.compile(
        rf'(["\'])({re.escape(package)})(\[[^\]]+\])?(>=[0-9][0-9A-Za-z._-]*(?:,<[0-9][0-9A-Za-z._-]*)?)',
        re.IGNORECASE,
    )

    def repl(match: re.Match[str]) -> str:
        current_spec = match.group(4)
        current_lower_m = re.match(r">=([0-9][0-9A-Za-z._-]*)", current_spec)
        current_lower = current_lower_m.group(1) if current_lower_m else "0"
        lower = current_lower if version_ge(current_lower, new_version) else new_version
        extras = match.group(3) or ""
        return f"{match.group(1)}{match.group(2)}{extras}{capped_spec(lower)}"

    return pattern.sub(repl, text)


def is_direct_python_dep(pyproject: str, package: str) -> bool:
    match = re.search(r"^dependencies\s*=\s*\[(.*?)^\]", pyproject, re.M | re.S)
    if not match:
        return False
    return re.search(
        rf'["\']{re.escape(package)}(?:\[[^\]]+\])?(?:>=|==|~=|<|>)',
        match.group(1),
        re.I,
    ) is not None


def upsert_constraint(text: str, package: str, spec: str) -> str:
    """Insert or replace a `[tool.uv] constraint-dependencies` entry.

    `spec` is the version clause only, e.g. `>=1.4.2`.
    """
    match = re.search(r"constraint-dependencies\s*=\s*\[(.*?)\]", text, re.S)
    if not match:
        block = (
            "\nconstraint-dependencies = [\n"
            f'    "{package}{spec}",\n'
            "]\n"
        )
        tool_uv = re.search(r"\[tool\.uv\][^\[]*", text)
        if tool_uv:
            insert_at = tool_uv.end()
            return text[:insert_at].rstrip() + "\n" + block + text[insert_at:]
        return text.rstrip() + "\n\n[tool.uv]\n" + block

    inner = match.group(1)
    entries = re.findall(r'"([^"]+)"', inner)
    found = False
    updated: list[str] = []
    pkg_l = package.lower()
    for entry in entries:
        name_m = re.match(r"([A-Za-z0-9._-]+)(\[[^\]]+\])?", entry)
        if not name_m:
            updated.append(entry)
            continue
        name, extras = name_m.group(1), name_m.group(2) or ""
        if name.lower() == pkg_l:
            updated.append(f"{name}{extras}{spec}")
            found = True
        else:
            updated.append(entry)
    if not found:
        updated.append(f"{package}{spec}")
        updated.sort(key=str.lower)
    rendered = "constraint-dependencies = [\n" + "".join(
        f'    "{e}",\n' for e in updated
    ) + "]"
    return text[: match.start()] + rendered + text[match.end() :]


def uv_lock_version(lock_text: str, package: str) -> str | None:
    match = re.search(
        rf'^name = "{re.escape(package)}"\nversion = "([^"]+)"',
        lock_text,
        re.M | re.I,
    )
    return match.group(1) if match else None


def npm_lock_versions(lock: dict[str, Any], package: str) -> list[str]:
    found: list[str] = []
    for key, meta in (lock.get("packages") or {}).items():
        if not isinstance(meta, dict):
            continue
        name = key.rsplit("node_modules/", 1)[-1] if "node_modules/" in key else ""
        if name == package and "version" in meta:
            found.append(str(meta["version"]))
    return found


# ---------------------------------------------------------------------------
# issue models
# ---------------------------------------------------------------------------

@dataclass
class DepAlert:
    number: int
    package: str
    ecosystem: str
    manifest: str
    patched: str | None
    severity: str
    summary: str
    ghsa: str
    html_url: str


@dataclass
class CodeScanAlert:
    number: int
    rule_id: str
    severity: str
    path: str
    message: str
    html_url: str


@dataclass
class QualityFinding:
    number: int
    rule_id: str
    severity: str
    path: str
    message: str


@dataclass
class SecretAlert:
    number: int
    secret_type: str
    html_url: str


@dataclass
class Plan:
    dependabot: list[DepAlert] = field(default_factory=list)
    code_scanning: list[CodeScanAlert] = field(default_factory=list)
    quality: list[QualityFinding] = field(default_factory=list)
    secrets: list[SecretAlert] = field(default_factory=list)
    pip_bumps: dict[str, str] = field(default_factory=dict)
    npm_bumps: dict[str, str] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)

    @property
    def has_fixable(self) -> bool:
        return bool(self.pip_bumps or self.npm_bumps or self.code_scanning)


# ---------------------------------------------------------------------------
# collectors
# ---------------------------------------------------------------------------

def collect_plan() -> Plan:
    plan = Plan()
    plan.dependabot = _collect_dependabot()
    plan.code_scanning = _collect_code_scanning()
    plan.quality = _collect_code_quality()
    plan.secrets = _collect_secrets()
    _group_dependabot(plan)
    return plan


def _collect_dependabot() -> list[DepAlert]:
    raw = gh_api_paged("repos/{owner}/{repo}/dependabot/alerts?state=open")
    alerts: list[DepAlert] = []
    for item in raw:
        dep = item.get("dependency") or {}
        pkg = (dep.get("package") or {})
        vuln = item.get("security_vulnerability") or {}
        patched_obj = vuln.get("first_patched_version") or {}
        advisory = item.get("security_advisory") or {}
        alerts.append(
            DepAlert(
                number=int(item["number"]),
                package=str(pkg.get("name") or ""),
                ecosystem=str(pkg.get("ecosystem") or "").lower(),
                manifest=str(dep.get("manifest_path") or ""),
                patched=(patched_obj.get("identifier") if isinstance(patched_obj, dict) else None),
                severity=str(advisory.get("severity") or vuln.get("severity") or "unknown"),
                summary=str(advisory.get("summary") or ""),
                ghsa=str(advisory.get("ghsa_id") or ""),
                html_url=str(item.get("html_url") or ""),
            )
        )
    return alerts


def _collect_code_scanning() -> list[CodeScanAlert]:
    raw = gh_api_paged("repos/{owner}/{repo}/code-scanning/alerts?state=open")
    alerts: list[CodeScanAlert] = []
    for item in raw:
        rule = item.get("rule") or {}
        inst = item.get("most_recent_instance") or {}
        loc = inst.get("location") or {}
        msg = (inst.get("message") or {}).get("text") or ""
        sev = rule.get("security_severity_level") or rule.get("severity") or "unknown"
        alerts.append(
            CodeScanAlert(
                number=int(item["number"]),
                rule_id=str(rule.get("id") or rule.get("name") or "unknown"),
                severity=str(sev),
                path=str(loc.get("path") or ""),
                message=str(msg),
                html_url=str(item.get("html_url") or ""),
            )
        )
    return alerts


def _collect_code_quality() -> list[QualityFinding]:
    try:
        raw = gh_api_paged(
            "repos/{owner}/{repo}/code-quality/findings?state=open",
            headers=["X-GitHub-Api-Version: 2026-03-10"],
        )
    except GitHubError as exc:
        if exc.status in (404, 403):
            log("code quality findings API not available; skipping")
            return []
        raise
    findings: list[QualityFinding] = []
    for item in raw:
        rule = item.get("rule") or {}
        loc = item.get("location") or {}
        msg = item.get("message") or {}
        text = msg.get("text") if isinstance(msg, dict) else (msg or "")
        findings.append(
            QualityFinding(
                number=int(item.get("number") or 0),
                rule_id=str(rule.get("id") or ""),
                severity=str(rule.get("severity") or "unknown"),
                path=str(loc.get("path") or ""),
                message=str(text),
            )
        )
    return findings


def _collect_secrets() -> list[SecretAlert]:
    try:
        raw = gh_api_paged("repos/{owner}/{repo}/secret-scanning/alerts?state=open")
    except GitHubError as exc:
        if exc.status in (404, 403):
            return []
        raise
    out: list[SecretAlert] = []
    for item in raw:
        out.append(
            SecretAlert(
                number=int(item.get("number") or 0),
                secret_type=str(item.get("secret_type_display_name") or item.get("secret_type") or "secret"),
                html_url=str(item.get("html_url") or ""),
            )
        )
    return out


def _group_dependabot(plan: Plan) -> None:
    by_key: dict[tuple[str, str], list[DepAlert]] = {}
    for alert in plan.dependabot:
        key = (alert.ecosystem, alert.package.lower())
        by_key.setdefault(key, []).append(alert)
    for (ecosystem, package), group in sorted(by_key.items()):
        patched_versions = [a.patched for a in group if a.patched]
        if not patched_versions:
            nums = ", ".join(f"#{a.number}" for a in group)
            plan.skipped.append(
                f"{ecosystem}:{package} (alerts {nums}) has no first_patched_version"
            )
            continue
        target = max_version(patched_versions)
        if ecosystem in PIP_ECOSYSTEMS:
            plan.pip_bumps[package] = target
        elif ecosystem in NPM_ECOSYSTEMS:
            plan.npm_bumps[package] = target
        else:
            nums = ", ".join(f"#{a.number}" for a in group)
            plan.skipped.append(
                f"unsupported ecosystem {ecosystem} for {package} (alerts {nums})"
            )


# ---------------------------------------------------------------------------
# apply remediations
# ---------------------------------------------------------------------------

def _apply_python_specs(text: str, bumps: dict[str, str]) -> tuple[str, list[str]]:
    notes: list[str] = []
    for package, version in sorted(bumps.items()):
        spec = capped_spec(version)
        if is_direct_python_dep(text, package):
            before = text
            text = raise_floor(text, package, version)
            if text == before:
                notes.append(f"{package}: floor already {spec}")
            else:
                notes.append(f"{package}: raised floor to {spec}")
        else:
            text = upsert_constraint(text, package, spec)
            notes.append(f"{package}: constraint {spec} (transitive)")
    return text, notes


def _uv_lock_upgrade(packages: list[str]) -> None:
    cmd = ["uv", "lock"]
    for package in packages:
        cmd.extend(["--upgrade-package", package])
    run(cmd, cwd=REPO / "backend", timeout=180)


def _verify_python_lock(bumps: dict[str, str]) -> list[str]:
    lock_text = (REPO / "backend" / "uv.lock").read_text()
    notes: list[str] = []
    for package, version in bumps.items():
        locked = uv_lock_version(lock_text, package)
        if locked is None:
            raise RuntimeError(f"uv.lock has no package named {package} after lock")
        if not version_ge(locked, version):
            raise RuntimeError(
                f"uv.lock {package}=={locked} is older than required {version}"
            )
        notes.append(f"{package}: uv.lock resolved {locked}")
    return notes


def apply_python_bumps(bumps: dict[str, str]) -> list[str]:
    if not bumps:
        return []
    pyproject_path = REPO / "backend" / "pyproject.toml"
    lock_path = REPO / "backend" / "uv.lock"
    original_pyproject = pyproject_path.read_text()
    original_lock = lock_path.read_text()
    text, notes = _apply_python_specs(original_pyproject, bumps)
    pyproject_path.write_text(text)
    try:
        _uv_lock_upgrade(sorted(bumps))
        notes.extend(_verify_python_lock(bumps))
        return notes
    except Exception as exc:
        log(f"bulk uv lock failed; retrying per package: {_short_exc(exc)}")
        pyproject_path.write_text(original_pyproject)
        lock_path.write_text(original_lock)

    notes = []
    good_pyproject = original_pyproject
    good_lock = original_lock
    applied = 0
    for package, version in sorted(bumps.items()):
        text, pkg_notes = _apply_python_specs(good_pyproject, {package: version})
        pyproject_path.write_text(text)
        try:
            _uv_lock_upgrade([package])
            verify = _verify_python_lock({package: version})
        except Exception as pkg_exc:
            log(f"skip unsatisfiable python bump {package}>={version}: {_short_exc(pkg_exc)}")
            notes.append(f"{package}: skipped (unsatisfiable with current lock)")
            pyproject_path.write_text(good_pyproject)
            lock_path.write_text(good_lock)
            continue
        notes.extend(pkg_notes)
        notes.extend(verify)
        applied += 1
        good_pyproject = pyproject_path.read_text()
        good_lock = lock_path.read_text()
    if applied == 0:
        log("no python bumps could be locked; pyproject and uv.lock restored")
    return notes


def apply_npm_bumps(bumps: dict[str, str]) -> list[str]:
    if not bumps:
        return []
    pkg_path = REPO / "frontend" / "package.json"
    pkg = json.loads(pkg_path.read_text())
    overrides = pkg.setdefault("overrides", {})
    notes: list[str] = []
    for package, version in sorted(bumps.items()):
        existing = overrides.get(package)
        if isinstance(existing, dict):
            notes.append(f"{package}: nested override left untouched")
            continue
        overrides[package] = version
        notes.append(f"{package}: override {existing!r} -> {version!r}")
    pkg_path.write_text(json.dumps(pkg, indent=2) + "\n")
    run(
        ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
        cwd=REPO / "frontend",
        timeout=180,
    )
    lock = json.loads((REPO / "frontend" / "package-lock.json").read_text())
    for package, version in bumps.items():
        found = npm_lock_versions(lock, package)
        if not found:
            notes.append(f"{package}: not present in package-lock.json after refresh")
            continue
        old = [v for v in found if not version_ge(v, version)]
        if old:
            raise RuntimeError(
                f"package-lock.json still has {package} {old} (need >={version})"
            )
        notes.append(f"{package}: lockfile versions {sorted(set(found))}")
    return notes


def apply_code_scanning_autofix(alerts: list[CodeScanAlert], branch: str) -> list[str]:
    notes: list[str] = []
    for alert in alerts:
        note = _autofix_one(alert, branch)
        notes.append(note)
    return notes


def _autofix_one(alert: CodeScanAlert, branch: str) -> str:
    endpoint = f"repos/{{owner}}/{{repo}}/code-scanning/alerts/{alert.number}/autofix"
    try:
        generated = gh_api(endpoint, method="POST", allow_statuses=(200, 202, 404, 403, 422))
    except GitHubError as exc:
        return f"#{alert.number} {alert.rule_id}: generate failed ({exc.status})"
    if isinstance(generated, dict) and generated.get("message"):
        msg = generated.get("message")
        return f"#{alert.number} {alert.rule_id}: {msg}"

    deadline = time.time() + 120
    status = (generated or {}).get("status") if isinstance(generated, dict) else None
    while status in (None, "pending", "generating") and time.time() < deadline:
        time.sleep(4)
        current = gh_api(endpoint, allow_statuses=(200, 404))
        if not isinstance(current, dict):
            break
        status = current.get("status")
        if status in ("success", "error", "failure"):
            generated = current
            break
    if status != "success":
        return f"#{alert.number} {alert.rule_id}: autofix status={status!r}"

    try:
        gh_api(
            endpoint + "/commits",
            method="POST",
            body={
                "target_ref": f"refs/heads/{branch}",
                "message": f"fix: CodeQL autofix for {alert.rule_id} (alert #{alert.number})",
            },
            allow_statuses=(201, 200, 422, 403, 404),
        )
    except GitHubError as exc:
        return f"#{alert.number} {alert.rule_id}: commit failed ({exc.status})"
    return f"#{alert.number} {alert.rule_id}: autofix committed"


# ---------------------------------------------------------------------------
# git / PR / CI
# ---------------------------------------------------------------------------

def git(*args: str, check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return run(["git", "-C", str(REPO), *args], check=check, timeout=timeout)


def working_tree_dirty() -> bool:
    proc = git("status", "--porcelain", "--untracked-files=no")
    return bool((proc.stdout or "").strip())


def ensure_git_identity() -> None:
    name = (git("config", "user.name", check=False).stdout or "").strip()
    email = (git("config", "user.email", check=False).stdout or "").strip()
    if not name or not email:
        raise RuntimeError("git user.name and user.email must be set for unattended commits")


def current_branch() -> str:
    return (git("rev-parse", "--abbrev-ref", "HEAD").stdout or "").strip()


def head_sha() -> str:
    return (git("rev-parse", "HEAD").stdout or "").strip()


def prepare_branch() -> None:
    if working_tree_dirty():
        raise RuntimeError("working tree has tracked modifications; aborting")
    git("fetch", "origin", "--prune", timeout=120)
    if current_branch() != "main":
        git("checkout", "main")
    git("pull", "--ff-only", "origin", "main", timeout=120)

    remote = git("ls-remote", "--heads", "origin", BRANCH, check=False)
    remote_exists = bool((remote.stdout or "").strip())

    open_pr = existing_open_pr()
    if open_pr and remote_exists:
        git("checkout", "-B", BRANCH, f"origin/{BRANCH}")
        rebase = git("rebase", "origin/main", check=False, timeout=120)
        if rebase.returncode != 0:
            git("rebase", "--abort", check=False)
            raise RuntimeError("rebase onto origin/main failed; leaving existing PR alone")
        log(f"reusing open PR #{open_pr['number']} on {BRANCH}")
        return

    git("checkout", "-B", BRANCH, "origin/main")
    log(f"created branch {BRANCH} from origin/main")


def existing_open_pr() -> dict[str, Any] | None:
    owner_repo = repo_slug()
    owner = owner_repo.split("/")[0]
    pulls = gh_api(
        f"repos/{{owner}}/{{repo}}/pulls?head={owner}:{BRANCH}&state=open&per_page=5",
        allow_statuses=(200,),
    )
    if isinstance(pulls, list) and pulls:
        return pulls[0]
    return None


def repo_slug() -> str:
    url = (git("remote", "get-url", "origin").stdout or "").strip()
    # git@github.com:Owner/repo.git or https://github.com/Owner/repo.git
    m = re.search(r"github\.com[:/](.+?)(?:\.git)?$", url)
    if not m:
        raise RuntimeError(f"cannot parse origin URL: {url}")
    return m.group(1).rstrip("/")


def commit_local_changes(message: str) -> bool:
    git("add", "--", "backend/pyproject.toml", "backend/uv.lock", "frontend/package.json", "frontend/package-lock.json")
    staged = git("diff", "--cached", "--name-only")
    names = [n for n in (staged.stdout or "").splitlines() if n.strip()]
    if not names:
        log("no staged lockfile/manifest changes")
        return False
    git("commit", "-m", message)
    log("committed: " + ", ".join(names))
    return True


def push_branch() -> None:
    # force-with-lease is safe: this branch is owned by the bot.
    git("push", "-u", "--force-with-lease", "origin", BRANCH, timeout=120)


def ensure_pr(title: str, body: str) -> dict[str, Any]:
    existing = existing_open_pr()
    if existing:
        number = existing["number"]
        gh_api(
            f"repos/{{owner}}/{{repo}}/pulls/{number}",
            method="PATCH",
            body={"title": title, "body": body},
        )
        log(f"updated PR #{number}")
        return gh_api(f"repos/{{owner}}/{{repo}}/pulls/{number}")
    created = gh_api(
        "repos/{owner}/{repo}/pulls",
        method="POST",
        body={"title": title, "body": body, "head": BRANCH, "base": "main"},
    )
    log(f"opened PR #{created['number']} {created.get('html_url')}")
    return created


def wait_for_green(pr_number: int, timeout_sec: int) -> str:
    """Poll check-runs on the PR head until green. Returns the green SHA."""
    deadline = time.time() + timeout_sec
    reran: set[int] = set()
    last_sig = ""
    cancelled_since: float | None = None

    while time.time() < deadline:
        pr = gh_api(f"repos/{{owner}}/{{repo}}/pulls/{pr_number}")
        if pr.get("merged") or pr.get("state") == "closed" and pr.get("merged_at"):
            log(f"PR #{pr_number} already merged")
            return pr.get("merge_commit_sha") or ""
        if pr.get("state") == "closed":
            raise RuntimeError(f"PR #{pr_number} was closed before merge")
        sha = (pr.get("head") or {}).get("sha") or ""
        if not sha:
            time.sleep(POLL_SEC)
            continue

        runs = _commit_check_runs(sha)
        statuses = _commit_combined_status(sha)
        summary = _summarize_checks(runs, statuses)
        sig = f"{sha[:12]}:{summary['signature']}"
        if sig != last_sig:
            log(
                f"checks sha={sha[:12]} pending={len(summary['pending'])} "
                f"failed={len(summary['failed'])} passed={len(summary['passed'])} "
                f"cancelled={len(summary['cancelled'])}"
            )
            last_sig = sig

        if summary["pending"]:
            cancelled_since = None
            time.sleep(POLL_SEC)
            continue

        if summary["failed"]:
            run_ids = _workflow_run_ids(sha)
            retried = False
            for run_id in run_ids:
                if run_id in reran:
                    continue
                log(f"rerunning failed jobs on workflow run {run_id}")
                gh_api(
                    f"repos/{{owner}}/{{repo}}/actions/runs/{run_id}/rerun-failed-jobs",
                    method="POST",
                    allow_statuses=(201, 202, 403, 409, 422),
                )
                reran.add(run_id)
                retried = True
            if retried:
                time.sleep(POLL_SEC)
                continue
            failed_names = ", ".join(summary["failed"][:8])
            raise RuntimeError(f"CI failed after retry: {failed_names}")

        if summary["passed"]:
            log(f"CI green on {sha[:12]}")
            return sha

        if summary["cancelled"]:
            if cancelled_since is None:
                cancelled_since = time.time()
            if time.time() - cancelled_since < CANCEL_GRACE_SEC:
                time.sleep(POLL_SEC)
                continue
            raise RuntimeError("CI checks cancelled and no replacement run started")

        # No checks registered yet — keep waiting until the outer deadline.
        time.sleep(POLL_SEC)

    raise RuntimeError(f"timed out waiting for CI on PR #{pr_number}")


def _commit_check_runs(sha: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    page = 1
    while page <= 10:
        payload = gh_api(
            f"repos/{{owner}}/{{repo}}/commits/{sha}/check-runs?per_page=100&page={page}"
        )
        if not isinstance(payload, dict):
            break
        chunk = payload.get("check_runs") or []
        items.extend(chunk)
        if len(chunk) < 100:
            break
        page += 1
    return items


def _commit_combined_status(sha: str) -> dict[str, Any]:
    payload = gh_api(f"repos/{{owner}}/{{repo}}/commits/{sha}/status")
    return payload if isinstance(payload, dict) else {}


def _summarize_checks(
    runs: list[dict[str, Any]], statuses: dict[str, Any]
) -> dict[str, Any]:
    pending: list[str] = []
    failed: list[str] = []
    passed: list[str] = []
    cancelled: list[str] = []
    ok_conclusions = {"success", "skipped", "neutral"}
    bad_conclusions = {"failure", "timed_out", "action_required", "stale", "startup_failure"}
    for run in runs:
        name = str(run.get("name") or run.get("id"))
        status = str(run.get("status") or "").lower()
        conclusion = str(run.get("conclusion") or "").lower()
        if status in {"queued", "in_progress", "waiting", "pending", "requested"}:
            pending.append(name)
        elif conclusion in ok_conclusions:
            passed.append(name)
        elif conclusion in {"cancelled", "canceled"}:
            cancelled.append(name)
        elif conclusion in bad_conclusions:
            failed.append(name)
        elif status == "completed" and not conclusion:
            pending.append(name)
        else:
            pending.append(name)
    for st in statuses.get("statuses") or []:
        name = str(st.get("context") or st.get("id"))
        state = str(st.get("state") or "").lower()
        if state in {"pending", "expected"}:
            pending.append(name)
        elif state == "success":
            passed.append(name)
        elif state in {"failure", "error"}:
            failed.append(name)
    signature = "|".join(
        [
            "p=" + ",".join(sorted(pending)),
            "f=" + ",".join(sorted(failed)),
            "c=" + ",".join(sorted(cancelled)),
            "ok=" + str(len(passed)),
        ]
    )
    return {
        "pending": pending,
        "failed": failed,
        "passed": passed,
        "cancelled": cancelled,
        "signature": signature,
    }


def _workflow_run_ids(sha: str) -> list[int]:
    payload = gh_api(
        f"repos/{{owner}}/{{repo}}/actions/runs?head_sha={sha}&per_page=20"
    )
    if not isinstance(payload, dict):
        return []
    ids: list[int] = []
    for item in payload.get("workflow_runs") or []:
        conclusion = str(item.get("conclusion") or "").lower()
        if conclusion in {"failure", "timed_out", "startup_failure"}:
            try:
                ids.append(int(item["id"]))
            except (KeyError, TypeError, ValueError):
                continue
    return ids


def merge_pr(pr_number: int, title: str) -> None:
    # REST merge is non-interactive on every gh version.
    result = gh_api(
        f"repos/{{owner}}/{{repo}}/pulls/{pr_number}/merge",
        method="PUT",
        body={
            "merge_method": "squash",
            "commit_title": title,
            "commit_message": "",
        },
        allow_statuses=(200, 405, 409),
    )
    if isinstance(result, dict) and result.get("merged"):
        log(f"merged PR #{pr_number} sha={result.get('sha')}")
    else:
        msg = result.get("message") if isinstance(result, dict) else result
        raise RuntimeError(f"merge did not succeed: {msg}")
    gh_api(
        f"repos/{{owner}}/{{repo}}/git/refs/heads/{BRANCH}",
        method="DELETE",
        allow_statuses=(204, 404, 422),
    )
    git("checkout", "main")
    git("pull", "--ff-only", "origin", "main", timeout=120)
    git("branch", "-D", BRANCH, check=False)


# ---------------------------------------------------------------------------
# PR text
# ---------------------------------------------------------------------------

def render_plan(plan: Plan) -> str:
    lines = ["## Security and quality plan", ""]
    if plan.dependabot:
        lines.append(f"Open Dependabot alerts: **{len(plan.dependabot)}**")
        lines.append("")
        lines.append("| Alert | Sev | Package | Ecosystem | Patched | Summary |")
        lines.append("|-------|-----|---------|-----------|---------|---------|")
        for a in plan.dependabot:
            summary = a.summary.replace("|", "/")[:80]
            lines.append(
                f"| [#{a.number}]({a.html_url}) | {a.severity} | `{a.package}` | {a.ecosystem} | `{a.patched or '—'}` | {summary} |"
            )
        lines.append("")
    if plan.pip_bumps:
        lines.append("### Python floors / constraints")
        lines.append("")
        lines.append("| Package | Target |")
        lines.append("|---------|--------|")
        for pkg, ver in sorted(plan.pip_bumps.items()):
            lines.append(f"| `{pkg}` | `{ver}` |")
        lines.append("")
    if plan.npm_bumps:
        lines.append("### npm overrides")
        lines.append("")
        lines.append("| Package | Target |")
        lines.append("|---------|--------|")
        for pkg, ver in sorted(plan.npm_bumps.items()):
            lines.append(f"| `{pkg}` | `{ver}` |")
        lines.append("")
    if plan.code_scanning:
        lines.append(f"Open code scanning alerts: **{len(plan.code_scanning)}**")
        lines.append("")
        for a in plan.code_scanning:
            lines.append(f"- [#{a.number}]({a.html_url}) `{a.rule_id}` ({a.severity}) `{a.path}`")
        lines.append("")
    if plan.quality:
        lines.append(f"Open code quality findings: **{len(plan.quality)}** (no unattended autofix; logged)")
        lines.append("")
    if plan.secrets:
        lines.append("Open secret scanning alerts (not rewritten by this script):")
        for s in plan.secrets:
            lines.append(f"- #{s.number} (details redacted)")
        lines.append("")
    if plan.skipped:
        lines.append("### Skipped")
        lines.append("")
        for row in plan.skipped:
            lines.append(f"- {row}")
        lines.append("")
    return "\n".join(lines)


def build_pr_body(plan: Plan, notes: list[str]) -> str:
    parts = [
        "Unattended remediation from `scripts/fix-github-security-and-quality.py`.",
        "",
        render_plan(plan),
        "### Applied",
        "",
    ]
    if notes:
        parts.extend(f"- {n}" for n in notes)
    else:
        parts.append("- (no local notes)")
    parts.extend(
        [
            "",
            "## Test plan",
            "",
            "- [ ] CI Lint",
            "- [ ] CI Backend Tests (if backend lockfile changed)",
            "- [ ] CI CodeQL",
            "- [ ] Dependabot alerts auto-close after merge",
            "",
        ]
    )
    return "\n".join(parts)


def build_title(plan: Plan) -> str:
    n_dep = len(plan.dependabot)
    n_ql = len(plan.code_scanning)
    if n_dep and n_ql:
        return f"fix(security): remediate {n_dep} Dependabot and {n_ql} CodeQL alerts"
    if n_ql:
        return f"fix(security): remediate {n_ql} CodeQL alerts"
    return f"fix(deps): remediate {n_dep} open Dependabot alerts"


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------

def self_test() -> None:
    sample = """dependencies = [
    "pyjwt[crypto]>=2.9.0",
    "mcp[cli]>=1.28.1",
]
[tool.uv]
override-dependencies = [
    "mcp[cli]>=1.28.1",
]
constraint-dependencies = [
    "anyio>=4.14.2,<4.15",
    "pip>=26.2.0",
]
"""
    text = raise_floor(sample, "pyjwt", "2.15.0")
    assert "pyjwt[crypto]>=2.15.0,<3" in text, text
    text = raise_floor(text, "mcp", "1.30.0")
    assert text.count("mcp[cli]>=1.30.0,<2") == 2, text
    assert is_direct_python_dep(sample, "pyjwt")
    assert is_direct_python_dep(sample, "mcp")
    assert not is_direct_python_dep(sample, "mako")
    text = upsert_constraint(text, "mako", capped_spec("1.4.2"))
    assert '"mako>=1.4.2,<2"' in text, text
    text = upsert_constraint(text, "urllib3", capped_spec("2.8.0"))
    assert '"urllib3>=2.8.0,<3"' in text
    text = upsert_constraint(text, "mako", capped_spec("1.4.3"))
    assert '"mako>=1.4.3,<2"' in text
    assert "1.4.2" not in text
    assert '"anyio>=4.14.2,<4.15"' in text
    assert '"pip>=26.2.0"' in text
    assert capped_spec("1.30.0") == ">=1.30.0,<2"
    assert version_ge("2.15.0", "2.14.0")
    assert max_version(["2.14.0", "2.15.0", "2.13.0"]) == "2.15.0"
    assert _short_exc(RuntimeError("a\nb")) == "a | b"
    edited, notes = _apply_python_specs(sample, {"mako": "1.4.2"})
    assert '"mako>=1.4.2,<2"' in edited
    assert notes == ["mako: constraint >=1.4.2,<2 (transitive)"]
    if MERGER.is_file():
        proc = subprocess.run(
            [sys.executable, str(MERGER), "--self-test"],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "self-test ok" in (proc.stdout or "")
    log("self-test ok")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--dry-run", action="store_true", help="print the plan and exit")
    parser.add_argument("--no-merge", action="store_true", help="open/update the PR but do not merge")
    parser.add_argument("--self-test", action="store_true", help="run editor unit checks and exit")
    parser.add_argument(
        "--ci-timeout",
        type=int,
        default=int(os.environ.get("WAIRZ_SEC_CI_TIMEOUT_SEC", DEFAULT_CI_TIMEOUT_SEC)),
        help="seconds to wait for CI (default 5400)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0

    configure_noninteractive()
    lock_fh = acquire_lock()
    try:
        os.chdir(REPO)
        which_or_die("git")
        which_or_die("gh")
        log(f"repo={REPO} branch={BRANCH}")
        merge_green_dependabot_prs(dry_run=args.dry_run)
        plan = collect_plan()
        log(
            f"open: dependabot={len(plan.dependabot)} code-scanning={len(plan.code_scanning)} "
            f"quality={len(plan.quality)} secrets={len(plan.secrets)}"
        )
        log(f"fixable: pip={plan.pip_bumps} npm={plan.npm_bumps}")
        for row in plan.skipped:
            log(f"skip: {row}")
        for secret in plan.secrets:
            log(f"SECRET still open: #{secret.number} {secret.secret_type} {secret.html_url}")
        for finding in plan.quality:
            log(f"quality (unautomated): #{finding.number} {finding.rule_id} {finding.path}")

        print(render_plan(plan))
        if args.dry_run:
            log("dry-run: no changes")
            return 0
        if not plan.has_fixable:
            log("nothing fixable; done")
            return 0

        which_or_die("uv")
        which_or_die("npm")
        ensure_git_identity()
        title = build_title(plan)
        prepare_branch()
        notes: list[str] = []
        try:
            notes.extend(apply_python_bumps(plan.pip_bumps))
            notes.extend(apply_npm_bumps(plan.npm_bumps))
            committed = commit_local_changes(title)
        except Exception:
            git(
                "checkout", "--",
                "backend/pyproject.toml",
                "backend/uv.lock",
                "frontend/package.json",
                "frontend/package-lock.json",
                check=False,
            )
            if current_branch() == BRANCH:
                git("checkout", "main", check=False)
            raise
        push_branch()
        if plan.code_scanning:
            notes.extend(apply_code_scanning_autofix(plan.code_scanning, BRANCH))
            git("fetch", "origin", BRANCH, timeout=120)
            git("pull", "--ff-only", "origin", BRANCH, timeout=120)

        ahead = git("rev-list", "--count", f"origin/main..HEAD")
        count = int((ahead.stdout or "0").strip() or "0")
        if count == 0 and not committed:
            log("branch has no commits beyond main; nothing to PR")
            git("checkout", "main")
            return 0

        body = build_pr_body(plan, notes)
        pr = ensure_pr(title, body)
        number = int(pr["number"])
        log(f"babysitting PR #{number} for up to {args.ci_timeout}s")
        wait_for_green(number, args.ci_timeout)
        if args.no_merge:
            log("--no-merge: leaving PR open")
            return 0
        merge_pr(number, title)
        log("done")
        return 0
    finally:
        try:
            lock_fh.close()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("interrupted")
        sys.exit(130)
    except Exception as exc:
        log(f"FAILED: {exc}")
        raise
