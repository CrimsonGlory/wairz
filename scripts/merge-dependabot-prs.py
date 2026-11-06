#!/usr/bin/env python3
"""Merge green PRs from the official GitHub Dependabot App only.

Identity is fail-closed. A pull request is eligible only when the REST
``user`` object (and every commit's GitHub-linked ``author``) matches the
published github.com/apps/dependabot bot on every pinned field:

    login     == "dependabot[bot]"            # exact; no casefold, no strip
    id        == 49699333                     # GitHub-documented bot user id
    node_id   == "MDM6Qm90NDk2OTkzMzM="
    type      == "Bot"
    html_url  == "https://github.com/apps/dependabot"

Those pins are the official GitHub App at https://github.com/apps/dependabot
(App id 29110, owned by the ``github`` org, id 9919). Lookalikes that this
script will never merge:

    dependabot                 org 27347476   https://github.com/dependabot
    dependabot-bot             user 36207117  signing account, not the App
    dependabot-preview[bot]    bot 27856297   retired Preview App
    github-actions[bot]        bot 41898282

A login of ``dependabot[bot]`` with the wrong id / html_url / type is
treated as an impersonation attempt and skipped (logged as SECURITY).

Every commit must also be GitHub-verified (App-signed). The spoofable git
author string is ignored; only the GitHub-linked account plus the
``verification.verified`` flag count. The GitHub-linked committer must be
either ``dependabot[bot]`` or GitHub's official ``web-flow`` user (id
19864447) — Dependabot's own commits are authored by the App and committed
by web-flow with ``GitHub <noreply@github.com>``. Merge sends the verified
head SHA so a push between the check and the merge is rejected (HTTP 409).

Cron (every 30 minutes; pending CI is retried on the next tick — this
script does not wait):

    */30 * * * * /home/codex/wairz/scripts/merge-dependabot-prs.py \\
        >>/var/log/wairz-merge-dependabot.log 2>&1

Requires: gh (authenticated with repo scope). HOME must be set so gh can
read ~/.config/gh/hosts.yml, or export GH_TOKEN. No TTY, no prompts.
Overlapping runs self-skip via flock. github.com only — the numeric pins
are not valid on GitHub Enterprise.
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parent.parent
LOCK_PATH = Path("/tmp/wairz-merge-dependabot-prs.lock")

# Official github.com/apps/dependabot bot user. Values taken from
# GET https://api.github.com/users/dependabot%5Bbot%5D and
# GET https://api.github.com/apps/dependabot (public, stable since 2019).
# GitHub's own docs cite user id 49699333 for this bot
# (actions/create-github-app-token README).
OFFICIAL_LOGIN = "dependabot[bot]"
OFFICIAL_USER_ID = 49699333
OFFICIAL_NODE_ID = "MDM6Qm90NDk2OTkzMzM="
OFFICIAL_TYPE = "Bot"
OFFICIAL_HTML_URL = "https://github.com/apps/dependabot"
OFFICIAL_EMAIL = "49699333+dependabot[bot]@users.noreply.github.com"
OFFICIAL_APP_SLUG = "dependabot"
OFFICIAL_APP_ID = 29110
OFFICIAL_APP_OWNER_LOGIN = "github"
OFFICIAL_APP_OWNER_ID = 9919
OFFICIAL_AVATAR_APP_MARKER = "/in/29110"

# GitHub's official web committer. Dependabot (and other GitHub Apps) author
# commits; GitHub commits them as web-flow and signs with the GitHub PGP key.
# GET https://api.github.com/users/web-flow
WEB_FLOW_LOGIN = "web-flow"
WEB_FLOW_USER_ID = 19864447
WEB_FLOW_NODE_ID = "MDQ6VXNlcjE5ODY0NDQ3"
WEB_FLOW_TYPE = "User"
WEB_FLOW_HTML_URL = "https://github.com/web-flow"
WEB_FLOW_GIT_NAME = "GitHub"
WEB_FLOW_GIT_EMAIL = "noreply@github.com"

ALLOWED_BASE_HOSTS = {"github.com", "www.github.com", "api.github.com"}

HEAD_REF_PREFIX = "dependabot/"

FROM_TO_RE = re.compile(
    r"\bfrom\s+v?(\d+)(?:\.\d+)*\s+to\s+v?(\d+)(?:\.\d+)*\b",
    re.IGNORECASE,
)


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
    os.environ["GH_PROMPT_DISABLED"] = "1"
    os.environ["GH_PAGER"] = "cat"
    os.environ["PAGER"] = "cat"
    os.environ["CI"] = "true"
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
            check=False,
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


# ---------------------------------------------------------------------------
# GitHub REST via `gh api`
# ---------------------------------------------------------------------------

class GitHubError(RuntimeError):
    def __init__(self, status: int | None, message: str, body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


class MergeDeclined(RuntimeError):
    """GitHub refused the merge; the next cron tick should retry."""


def gh_api(
    endpoint: str,
    method: str = "GET",
    body: Any | None = None,
    allow_statuses: tuple[int, ...] = (),
) -> Any:
    cmd = [
        "gh", "api", "--method", method, endpoint,
        "-H", "Accept: application/vnd.github+json",
        "--include",
    ]
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
    if not raw:
        return None, None
    parts = raw.split("\r\n\r\n", 1)
    if len(parts) == 1:
        parts = raw.split("\n\n", 1)
    header, body = (parts[0], parts[1] if len(parts) > 1 else "")
    status = None
    for line in header.splitlines():
        match = re.match(r"HTTP/\S+\s+(\d+)", line)
        if match:
            status = int(match.group(1))
    body = body.strip()
    if not body:
        return status, None
    try:
        return status, json.loads(body)
    except json.JSONDecodeError:
        return status, body


def gh_api_list(endpoint: str) -> list[Any]:
    sep = "&" if "?" in endpoint else "?"
    url = f"{endpoint}{sep}per_page=100"
    cmd = [
        "gh", "api", "--paginate", "--method", "GET", url,
        "-H", "Accept: application/vnd.github+json",
    ]
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
        merged = re.sub(r"\]\s*\[", ",", raw)
        data = json.loads(merged)
    if isinstance(data, list):
        return data
    return []


# ---------------------------------------------------------------------------
# Official Dependabot identity
# ---------------------------------------------------------------------------

def dependabot_identity_error(user: Any, *, what: str = "user") -> str | None:
    """Return a reason if ``user`` is not the official github.com/apps/dependabot bot.

    Every pinned field must match. Login is compared with exact string
    equality (no casefold, no strip, no Unicode normalisation) so a
    homoglyph or ``Dependabot[bot]`` / ``dependabot`` cannot pass.
    """
    if not isinstance(user, dict):
        return f"{what} is missing or not an object"
    login = user.get("login")
    if login != OFFICIAL_LOGIN:
        return (
            f"{what}.login={login!r} is not exactly {OFFICIAL_LOGIN!r}"
        )
    try:
        user_id = int(user["id"])
    except (KeyError, TypeError, ValueError):
        return f"{what}.id={user.get('id')!r} is not the official id {OFFICIAL_USER_ID}"
    if user_id != OFFICIAL_USER_ID:
        return (
            f"{what}.id={user_id} is not the official id {OFFICIAL_USER_ID} "
            f"(login matched {OFFICIAL_LOGIN!r} — treating as impersonation)"
        )
    if user.get("type") != OFFICIAL_TYPE:
        return f"{what}.type={user.get('type')!r} is not {OFFICIAL_TYPE!r}"
    html_url = user.get("html_url")
    if not isinstance(html_url, str) or _norm_url(html_url) != OFFICIAL_HTML_URL:
        return (
            f"{what}.html_url={html_url!r} is not {OFFICIAL_HTML_URL!r} "
            "(official App URL, not a user profile)"
        )
    if user.get("node_id") != OFFICIAL_NODE_ID:
        return f"{what}.node_id={user.get('node_id')!r} is not {OFFICIAL_NODE_ID!r}"
    avatar = user.get("avatar_url")
    if not isinstance(avatar, str) or OFFICIAL_AVATAR_APP_MARKER not in avatar:
        return (
            f"{what}.avatar_url={avatar!r} does not contain "
            f"{OFFICIAL_AVATAR_APP_MARKER} (GitHub App id {OFFICIAL_APP_ID})"
        )
    return None


def _norm_url(url: str) -> str:
    return url.strip().rstrip("/")


def web_flow_identity_error(user: Any, *, what: str = "user") -> str | None:
    """Return a reason if ``user`` is not GitHub's official web-flow committer."""
    if not isinstance(user, dict):
        return f"{what} is missing or not an object"
    if user.get("login") != WEB_FLOW_LOGIN:
        return f"{what}.login={user.get('login')!r} is not exactly {WEB_FLOW_LOGIN!r}"
    try:
        user_id = int(user["id"])
    except (KeyError, TypeError, ValueError):
        return f"{what}.id={user.get('id')!r} is not the official id {WEB_FLOW_USER_ID}"
    if user_id != WEB_FLOW_USER_ID:
        return f"{what}.id={user_id} is not the official id {WEB_FLOW_USER_ID}"
    if user.get("type") != WEB_FLOW_TYPE:
        return f"{what}.type={user.get('type')!r} is not {WEB_FLOW_TYPE!r}"
    html_url = user.get("html_url")
    if not isinstance(html_url, str) or _norm_url(html_url) != WEB_FLOW_HTML_URL:
        return f"{what}.html_url={html_url!r} is not {WEB_FLOW_HTML_URL!r}"
    if user.get("node_id") != WEB_FLOW_NODE_ID:
        return f"{what}.node_id={user.get('node_id')!r} is not {WEB_FLOW_NODE_ID!r}"
    return None


def committer_identity_error(user: Any, *, what: str = "committer") -> str | None:
    """Committer must be official Dependabot or official GitHub web-flow."""
    dep_err = dependabot_identity_error(user, what=what)
    if dep_err is None:
        return None
    wf_err = web_flow_identity_error(user, what=what)
    if wf_err is None:
        return None
    login = user.get("login") if isinstance(user, dict) else None
    return (
        f"{what} is neither official {OFFICIAL_LOGIN} nor official "
        f"{WEB_FLOW_LOGIN} (login={login!r}; dependabot: {dep_err}; "
        f"web-flow: {wf_err})"
    )


def commit_identity_error(commit: Any, index: int) -> str | None:
    """Fail closed unless this commit is GitHub-verified official Dependabot.

    Uses the GitHub-linked ``author`` account (API ``commit.author``), not
    the spoofable git ``commit.commit.author`` name/email pair, AND requires
    GitHub's ``verification.verified`` flag so a collaborator cannot push a
    commit with Dependabot's noreply email and ride an existing Dependabot PR.

    The GitHub-linked committer is allowed to be Dependabot itself or
    GitHub's ``web-flow`` account (the signer of App-created commits).
    """
    if not isinstance(commit, dict):
        return f"commit[{index}] is not an object"
    sha = str(commit.get("sha") or "")[:12]
    label = f"commit[{index}] {sha}".strip()
    inner = commit.get("commit") if isinstance(commit.get("commit"), dict) else {}
    verification = inner.get("verification") if isinstance(inner, dict) else None
    if not isinstance(verification, dict) or verification.get("verified") is not True:
        reason = None
        if isinstance(verification, dict):
            reason = verification.get("reason")
        return (
            f"{label} is not GitHub-verified "
            f"(verified={None if not isinstance(verification, dict) else verification.get('verified')}"
            f", reason={reason!r})"
        )
    err = dependabot_identity_error(commit.get("author"), what=f"{label}.author")
    if err:
        return err
    committer = commit.get("committer")
    if committer is not None:
        err = committer_identity_error(committer, what=f"{label}.committer")
        if err:
            return err
    git_author = inner.get("author") if isinstance(inner, dict) else None
    if isinstance(git_author, dict):
        email = git_author.get("email")
        if email is not None and email != OFFICIAL_EMAIL:
            return (
                f"{label} git author email {email!r} is not {OFFICIAL_EMAIL!r}"
            )
    git_committer = inner.get("committer") if isinstance(inner, dict) else None
    if isinstance(git_committer, dict) and isinstance(committer, dict):
        git_email = git_committer.get("email")
        git_name = git_committer.get("name")
        if committer.get("login") == WEB_FLOW_LOGIN:
            if git_email is not None and git_email != WEB_FLOW_GIT_EMAIL:
                return (
                    f"{label} git committer email {git_email!r} is not "
                    f"{WEB_FLOW_GIT_EMAIL!r}"
                )
            if git_name is not None and git_name != WEB_FLOW_GIT_NAME:
                return (
                    f"{label} git committer name {git_name!r} is not "
                    f"{WEB_FLOW_GIT_NAME!r}"
                )
        elif committer.get("login") == OFFICIAL_LOGIN:
            if git_email is not None and git_email != OFFICIAL_EMAIL:
                return (
                    f"{label} git committer email {git_email!r} is not "
                    f"{OFFICIAL_EMAIL!r}"
                )
    return None


def is_major_update_title(title: str) -> bool:
    """True when the Dependabot title bumps the leftmost version component."""
    for match in FROM_TO_RE.finditer(title or ""):
        if match.group(1) != match.group(2):
            return True
    return False


# ---------------------------------------------------------------------------
# CI
# ---------------------------------------------------------------------------

def summarize_checks(
    runs: list[dict[str, Any]], statuses: dict[str, Any]
) -> dict[str, Any]:
    pending: list[str] = []
    failed: list[str] = []
    passed: list[str] = []
    cancelled: list[str] = []
    bad_conclusions = {
        "failure", "timed_out", "action_required", "stale", "startup_failure",
    }
    for check_run in runs:
        name = str(check_run.get("name") or check_run.get("id"))
        status = str(check_run.get("status") or "").lower()
        conclusion = str(check_run.get("conclusion") or "").lower()
        if status in {"queued", "in_progress", "waiting", "pending", "requested"}:
            pending.append(name)
        elif conclusion == "success":
            passed.append(name)
        elif conclusion in {"skipped", "neutral"}:
            # Counted as non-blocking, not as a passing test.
            pass
        elif conclusion in {"cancelled", "canceled"}:
            cancelled.append(name)
        elif conclusion in bad_conclusions:
            failed.append(name)
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
    return {
        "pending": pending,
        "failed": failed,
        "passed": passed,
        "cancelled": cancelled,
    }


def checks_ready_to_merge(summary: dict[str, Any]) -> str | None:
    """Return a skip reason, or None if CI is green enough to merge.

    Pending → skip this tick (cron retries). Failed → do not merge.
    Zero passing checks → do not merge (Actions may be disabled / not started).
    Leftover cancelled runs are ignorable once a replacement has passed.
    """
    if summary["pending"]:
        names = ", ".join(summary["pending"][:8])
        return f"CI pending: {names}"
    if summary["failed"]:
        names = ", ".join(summary["failed"][:8])
        return f"CI failed: {names}"
    if not summary["passed"]:
        extra = ""
        if summary["cancelled"]:
            extra = f" (cancelled={len(summary['cancelled'])})"
        return f"no passing checks{extra}"
    return None


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------

@dataclass
class Decision:
    number: int
    title: str
    action: str  # merge | skip | reject
    reason: str
    sha: str = ""
    url: str = ""


def classify_pr(
    pr: dict[str, Any],
    commits: list[Any],
    check_runs: list[dict[str, Any]],
    combined_status: dict[str, Any],
    *,
    default_branch: str,
) -> Decision:
    number = int(pr.get("number") or 0)
    title = str(pr.get("title") or "")
    url = str(pr.get("html_url") or "")
    head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
    base = pr.get("base") if isinstance(pr.get("base"), dict) else {}
    sha = str(head.get("sha") or "")

    def skip(reason: str) -> Decision:
        return Decision(number, title, "skip", reason, sha=sha, url=url)

    def reject(reason: str) -> Decision:
        return Decision(number, title, "reject", reason, sha=sha, url=url)

    if pr.get("merged") or pr.get("merged_at"):
        return skip("already merged")
    if pr.get("state") != "open":
        return skip(f"state={pr.get('state')!r}")
    if pr.get("draft"):
        return skip("draft")
    if pr.get("locked"):
        return skip("locked")

    ident = dependabot_identity_error(pr.get("user"), what="pr.user")
    if ident:
        login = (pr.get("user") or {}).get("login") if isinstance(pr.get("user"), dict) else None
        if isinstance(login, str) and "dependabot" in login.lower():
            return reject(ident)
        return skip(ident)

    base_ref = str(base.get("ref") or "")
    if base_ref != default_branch:
        return skip(f"base {base_ref!r} is not default branch {default_branch!r}")

    head_ref = str(head.get("ref") or "")
    if not head_ref.startswith(HEAD_REF_PREFIX):
        return reject(
            f"head ref {head_ref!r} does not start with {HEAD_REF_PREFIX!r}"
        )

    head_repo = head.get("repo") if isinstance(head.get("repo"), dict) else None
    base_repo = base.get("repo") if isinstance(base.get("repo"), dict) else None
    if not head_repo or not base_repo:
        return skip("missing head/base repo")
    if head_repo.get("full_name") != base_repo.get("full_name"):
        return reject(
            f"head repo {head_repo.get('full_name')!r} is a fork; "
            "official Dependabot opens in-repo branches"
        )

    if is_major_update_title(title):
        return skip("major-version bump (manual review)")

    if not commits:
        return skip("no commits")
    if len(commits) > 50:
        return skip(f"unusually many commits ({len(commits)})")
    for index, commit in enumerate(commits):
        err = commit_identity_error(commit, index)
        if err:
            return reject(err)

    if not sha:
        return skip("missing head sha")

    mergeable = pr.get("mergeable")
    mergeable_state = str(pr.get("mergeable_state") or "")
    if mergeable is False or mergeable_state == "dirty":
        return skip("merge conflict")
    if mergeable_state in {"draft"}:
        return skip("draft")
    if mergeable is None or mergeable_state in {"unknown", ""}:
        return skip("mergeability not computed yet")

    summary = summarize_checks(check_runs, combined_status)
    ci_reason = checks_ready_to_merge(summary)
    if ci_reason:
        return skip(ci_reason)

    return Decision(
        number,
        title,
        "merge",
        f"official {OFFICIAL_LOGIN} + {len(summary['passed'])} passing checks",
        sha=sha,
        url=url,
    )


def merge_payload(sha: str, method: str = "squash") -> dict[str, str]:
    """Body for PUT /pulls/{n}/merge. ``sha`` is the TOCTOU pin."""
    return {"merge_method": method, "sha": sha}


# ---------------------------------------------------------------------------
# Live App pin (fail closed if GitHub's published App record drifts)
# ---------------------------------------------------------------------------

def assert_official_app(app: Any) -> None:
    if not isinstance(app, dict):
        raise RuntimeError("GET /apps/dependabot did not return an object")
    slug = app.get("slug")
    if slug != OFFICIAL_APP_SLUG:
        raise RuntimeError(
            f"apps/dependabot slug={slug!r} is not {OFFICIAL_APP_SLUG!r}"
        )
    try:
        app_id = int(app["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(f"apps/dependabot id missing: {app.get('id')!r}") from exc
    if app_id != OFFICIAL_APP_ID:
        raise RuntimeError(
            f"apps/dependabot id={app_id} is not official App id {OFFICIAL_APP_ID}"
        )
    html_url = app.get("html_url")
    if not isinstance(html_url, str) or _norm_url(html_url) != OFFICIAL_HTML_URL:
        raise RuntimeError(
            f"apps/dependabot html_url={html_url!r} is not {OFFICIAL_HTML_URL!r}"
        )
    owner = app.get("owner") if isinstance(app.get("owner"), dict) else {}
    if owner.get("login") != OFFICIAL_APP_OWNER_LOGIN:
        raise RuntimeError(
            f"apps/dependabot owner.login={owner.get('login')!r} "
            f"is not {OFFICIAL_APP_OWNER_LOGIN!r}"
        )
    try:
        owner_id = int(owner["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("apps/dependabot owner.id missing") from exc
    if owner_id != OFFICIAL_APP_OWNER_ID:
        raise RuntimeError(
            f"apps/dependabot owner.id={owner_id} is not {OFFICIAL_APP_OWNER_ID}"
        )


def assert_github_dot_com(repo_url: str) -> None:
    host = (urlparse(repo_url).hostname or "").lower()
    if host not in ALLOWED_BASE_HOSTS:
        raise RuntimeError(
            f"repo host {host!r} is not github.com; official Dependabot "
            f"user id {OFFICIAL_USER_ID} is github.com-specific"
        )


# ---------------------------------------------------------------------------
# self-test (Rule #46 canaries live here)
# ---------------------------------------------------------------------------

def _official_user(**overrides: Any) -> dict[str, Any]:
    user = {
        "login": OFFICIAL_LOGIN,
        "id": OFFICIAL_USER_ID,
        "node_id": OFFICIAL_NODE_ID,
        "type": OFFICIAL_TYPE,
        "html_url": OFFICIAL_HTML_URL,
        "avatar_url": f"https://avatars.githubusercontent.com{OFFICIAL_AVATAR_APP_MARKER}?v=4",
    }
    user.update(overrides)
    return user


def _web_flow_user(**overrides: Any) -> dict[str, Any]:
    user = {
        "login": WEB_FLOW_LOGIN,
        "id": WEB_FLOW_USER_ID,
        "node_id": WEB_FLOW_NODE_ID,
        "type": WEB_FLOW_TYPE,
        "html_url": WEB_FLOW_HTML_URL,
    }
    user.update(overrides)
    return user


def _verified_commit(user: dict[str, Any] | None = None, **overrides: Any) -> dict[str, Any]:
    actor = user if user is not None else _official_user()
    commit = {
        "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "author": actor,
        "committer": actor,
        "commit": {
            "author": {"name": OFFICIAL_LOGIN, "email": OFFICIAL_EMAIL},
            "verification": {"verified": True, "reason": "valid"},
        },
    }
    commit.update(overrides)
    return commit


def self_test() -> None:
    assert dependabot_identity_error(_official_user()) is None

    # Exact-login canary: anything other than dependabot[bot] is rejected,
    # including the GitHub App's GraphQL bare login and every public lookalike.
    lookalikes = [
        {"login": "dependabot", "id": 27347476, "type": "Organization",
         "html_url": "https://github.com/dependabot", "node_id": "MDEyOk9yZ2FuaXphdGlvbjI3MzQ3NDc2"},
        {"login": "dependabot-bot", "id": 36207117, "type": "User",
         "html_url": "https://github.com/dependabot-bot", "node_id": "MDQ6VXNlcjM2MjA3MTE3"},
        {"login": "dependabot-preview[bot]", "id": 27856297, "type": "Bot",
         "html_url": "https://github.com/apps/dependabot-preview",
         "node_id": "MDM6Qm90Mjc4NTYyOTc="},
        {"login": "github-actions[bot]", "id": 41898282, "type": "Bot",
         "html_url": "https://github.com/apps/github-actions"},
        {"login": "Dependabot[bot]", "id": OFFICIAL_USER_ID, "type": "Bot",
         "html_url": OFFICIAL_HTML_URL, "node_id": OFFICIAL_NODE_ID},
        {"login": "dependabot[bot] ", "id": OFFICIAL_USER_ID, "type": "Bot",
         "html_url": OFFICIAL_HTML_URL, "node_id": OFFICIAL_NODE_ID},
        {"login": "dependabot[bot]", "id": OFFICIAL_USER_ID, "type": "Bot",
         "html_url": "https://github.com/dependabot[bot]", "node_id": OFFICIAL_NODE_ID},
    ]
    for fake in lookalikes:
        err = dependabot_identity_error(fake)
        assert err, f"lookalike was accepted: {fake!r}"

    # Impersonation canary (Rule #46): right login, wrong id MUST be rejected.
    impersonator = _official_user(id=1)
    impersonator_err = dependabot_identity_error(impersonator)
    assert impersonator_err and "impersonation" in impersonator_err, impersonator_err

    assert dependabot_identity_error(_official_user(type="User"))
    assert dependabot_identity_error(_official_user(node_id="MDQ6VXNlcjE="))
    assert dependabot_identity_error(_official_user(node_id=None))
    assert dependabot_identity_error(_official_user(avatar_url="https://avatars.githubusercontent.com/u/1?v=4"))
    assert dependabot_identity_error(_official_user(avatar_url=None))
    assert dependabot_identity_error(None)
    assert dependabot_identity_error("dependabot[bot]")
    assert dependabot_identity_error({})

    # Trailing slash on the official App URL is tolerated; a user profile is not.
    assert dependabot_identity_error(_official_user(html_url=OFFICIAL_HTML_URL + "/")) is None

    good_commit = _verified_commit()
    assert commit_identity_error(good_commit, 0) is None

    unsigned = _verified_commit()
    unsigned["commit"]["verification"] = {"verified": False, "reason": "unsigned"}
    assert commit_identity_error(unsigned, 0)

    missing_ver = _verified_commit()
    missing_ver["commit"]["verification"] = {"verified": True, "reason": "valid"}
    missing_ver["author"] = _official_user(id=41898282, login="github-actions[bot]")
    assert commit_identity_error(missing_ver, 0)

    spoofed_email = _verified_commit()
    spoofed_email["commit"]["author"]["email"] = "attacker@example.com"
    assert commit_identity_error(spoofed_email, 0)

    # Real Dependabot shape: App authors, GitHub web-flow commits + signs.
    realistic = _verified_commit()
    realistic["committer"] = _web_flow_user()
    realistic["commit"]["committer"] = {
        "name": WEB_FLOW_GIT_NAME,
        "email": WEB_FLOW_GIT_EMAIL,
    }
    assert commit_identity_error(realistic, 0) is None
    assert web_flow_identity_error(_web_flow_user()) is None
    assert web_flow_identity_error(_web_flow_user(id=1))
    assert web_flow_identity_error(_official_user())

    human_committer = _verified_commit()
    human_committer["committer"] = {
        "login": "alice", "id": 2, "type": "User",
        "html_url": "https://github.com/alice",
    }
    assert commit_identity_error(human_committer, 0)

    actions_committer = _verified_commit()
    actions_committer["committer"] = {
        "login": "github-actions[bot]", "id": 41898282, "type": "Bot",
        "html_url": "https://github.com/apps/github-actions",
    }
    assert commit_identity_error(actions_committer, 0)

    bad_web_flow_email = _verified_commit()
    bad_web_flow_email["committer"] = _web_flow_user()
    bad_web_flow_email["commit"]["committer"] = {
        "name": WEB_FLOW_GIT_NAME,
        "email": "attacker@example.com",
    }
    assert commit_identity_error(bad_web_flow_email, 0)

    assert is_major_update_title("Bump actions/checkout from 4 to 5")
    assert is_major_update_title("Bump foo from 1.2.3 to 2.0.0")
    assert not is_major_update_title("Bump foo from 1.2.3 to 1.3.0")
    assert not is_major_update_title("Bump the python-minor-patch group with 5 updates")

    green = checks_ready_to_merge(
        summarize_checks(
            [{"name": "Lint", "status": "completed", "conclusion": "success"}],
            {},
        )
    )
    assert green is None, green
    pending = checks_ready_to_merge(
        summarize_checks(
            [{"name": "Lint", "status": "in_progress", "conclusion": None}],
            {},
        )
    )
    assert pending and "pending" in pending
    failed = checks_ready_to_merge(
        summarize_checks(
            [{"name": "Pytest", "status": "completed", "conclusion": "failure"}],
            {},
        )
    )
    assert failed and "failed" in failed
    empty = checks_ready_to_merge(summarize_checks([], {}))
    assert empty and "no passing checks" in empty
    skipped_only = checks_ready_to_merge(
        summarize_checks(
            [{"name": "E2E", "status": "completed", "conclusion": "skipped"}],
            {},
        )
    )
    assert skipped_only and "no passing checks" in skipped_only

    payload = merge_payload("abc123")
    assert payload == {"merge_method": "squash", "sha": "abc123"}

    app = {
        "id": OFFICIAL_APP_ID,
        "slug": OFFICIAL_APP_SLUG,
        "html_url": OFFICIAL_HTML_URL,
        "owner": {"login": OFFICIAL_APP_OWNER_LOGIN, "id": OFFICIAL_APP_OWNER_ID},
    }
    assert_official_app(app)
    try:
        assert_official_app({**app, "slug": "dependabot-preview"})
        raise AssertionError("preview app pin was accepted")
    except RuntimeError:
        pass

    try:
        assert_github_dot_com("https://git.example.internal/acme/wairz")
        raise AssertionError("GHE host was accepted")
    except RuntimeError:
        pass
    assert_github_dot_com("https://github.com/acme/wairz")

    # classify_pr: official author + verified commit + green CI → merge
    pr = {
        "number": 1,
        "title": "Bump foo from 1.2.3 to 1.2.4",
        "html_url": "https://github.com/acme/wairz/pull/1",
        "state": "open",
        "draft": False,
        "merged": False,
        "user": _official_user(),
        "mergeable": True,
        "mergeable_state": "clean",
        "head": {
            "sha": "abc",
            "ref": "dependabot/pip/backend/foo-1.2.4",
            "repo": {"full_name": "acme/wairz"},
        },
        "base": {
            "ref": "main",
            "repo": {"full_name": "acme/wairz"},
        },
    }
    runs = [{"name": "Lint", "status": "completed", "conclusion": "success"}]
    decision = classify_pr(pr, [_verified_commit()], runs, {}, default_branch="main")
    assert decision.action == "merge", decision

    human = dict(pr)
    human["user"] = {"login": "alice", "id": 2, "type": "User",
                     "html_url": "https://github.com/alice"}
    decision = classify_pr(human, [_verified_commit()], runs, {}, default_branch="main")
    assert decision.action == "skip", decision

    preview = dict(pr)
    preview["user"] = {
        "login": "dependabot-preview[bot]",
        "id": 27856297,
        "type": "Bot",
        "html_url": "https://github.com/apps/dependabot-preview",
        "node_id": "MDM6Qm90Mjc4NTYyOTc=",
    }
    decision = classify_pr(preview, [_verified_commit()], runs, {}, default_branch="main")
    assert decision.action == "reject", decision

    impersonated = dict(pr)
    impersonated["user"] = _official_user(id=1)
    decision = classify_pr(
        impersonated, [_verified_commit()], runs, {}, default_branch="main",
    )
    assert decision.action == "reject" and "impersonation" in decision.reason, decision

    extra = dict(pr)
    human_commit = _verified_commit(
        {"login": "alice", "id": 2, "type": "User", "html_url": "https://github.com/alice"}
    )
    decision = classify_pr(
        extra, [_verified_commit(), human_commit], runs, {}, default_branch="main",
    )
    assert decision.action == "reject", decision

    human_listed = dict(human)
    human_listed["number"] = 2
    preview_listed = dict(preview)
    preview_listed["number"] = 3
    numbers, early = prefilter_list_payload(
        [human_listed, pr, preview_listed],
        None,
    )
    assert numbers == [1, 3], numbers  # official + dependabot-like still fetched
    assert len(early) == 1 and early[0].number == 2 and early[0].action == "skip", early

    major = dict(pr)
    major["title"] = "Bump foo from 1.2.3 to 2.0.0"
    decision = classify_pr(major, [_verified_commit()], runs, {}, default_branch="main")
    assert decision.action == "skip" and "major" in decision.reason, decision

    log("self-test ok")


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

def repo_default_branch(repo: dict[str, Any]) -> str:
    return str(repo.get("default_branch") or "main")


def fetch_pr_bundle(number: int) -> tuple[dict[str, Any], list[Any], list[dict[str, Any]], dict[str, Any]]:
    pr = gh_api(f"repos/{{owner}}/{{repo}}/pulls/{number}")
    if not isinstance(pr, dict):
        raise RuntimeError(f"PR #{number} did not return an object")
    commits = gh_api_list(f"repos/{{owner}}/{{repo}}/pulls/{number}/commits")
    sha = ((pr.get("head") or {}) if isinstance(pr.get("head"), dict) else {}).get("sha") or ""
    check_runs: list[dict[str, Any]] = []
    combined: dict[str, Any] = {}
    if sha:
        check_runs = _commit_check_runs(str(sha))
        combined_payload = gh_api(f"repos/{{owner}}/{{repo}}/commits/{sha}/status")
        combined = combined_payload if isinstance(combined_payload, dict) else {}
    return pr, commits, check_runs, combined


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


def merge_pr(number: int, sha: str) -> str:
    result = gh_api(
        f"repos/{{owner}}/{{repo}}/pulls/{number}/merge",
        method="PUT",
        body=merge_payload(sha),
        allow_statuses=(200, 405, 409, 422),
    )
    if isinstance(result, dict) and result.get("merged"):
        merged_sha = str(result.get("sha") or "")
        log(f"merged PR #{number} sha={merged_sha}")
        return merged_sha
    msg = str(result.get("message") if isinstance(result, dict) else result)
    lowered = msg.lower()
    if "already merged" in lowered:
        log(f"PR #{number} already merged")
        return ""
    raise MergeDeclined(f"merge of #{number} declined: {msg}")


def _login_of(user: Any) -> str | None:
    if isinstance(user, dict) and isinstance(user.get("login"), str):
        return user["login"]
    return None


def _dependabot_like_login(login: str | None) -> bool:
    return isinstance(login, str) and "dependabot" in login.lower()


def prefilter_list_payload(
    pulls: list[Any], only: int | None
) -> tuple[list[int], list[Decision]]:
    """Drop obvious non-Dependabot PRs before fetching commits/checks.

    Identity is re-checked on the full PR payload before merge; this is
    only an API-volume filter. Dependabot-like lookalikes are still
    returned so classify_pr can SECURITY-reject them on the full object.
    """
    decisions: list[Decision] = []
    numbers: list[int] = []
    for pr in pulls:
        if not isinstance(pr, dict):
            continue
        try:
            number = int(pr["number"])
        except (KeyError, TypeError, ValueError):
            continue
        if only is not None and number != only:
            continue
        login = _login_of(pr.get("user"))
        ident = dependabot_identity_error(pr.get("user"), what="pr.user")
        if ident and not _dependabot_like_login(login):
            decisions.append(
                Decision(
                    number,
                    str(pr.get("title") or ""),
                    "skip",
                    ident,
                    url=str(pr.get("html_url") or ""),
                )
            )
            continue
        numbers.append(number)
    return numbers, decisions


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge green PRs from the official github.com/apps/dependabot bot."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="classify PRs and print decisions; do not merge",
    )
    parser.add_argument(
        "--pr",
        type=int,
        default=None,
        help="consider only this PR number (still identity-gated)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run identity / CI / merge-payload unit checks and exit",
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
        which_or_die("gh")
        repo = gh_api("repos/{owner}/{repo}")
        if not isinstance(repo, dict):
            raise RuntimeError("repos/{owner}/{repo} did not return an object")
        assert_github_dot_com(str(repo.get("html_url") or repo.get("url") or ""))
        default_branch = repo_default_branch(repo)
        log(
            f"repo={repo.get('full_name')} default_branch={default_branch} "
            f"official={OFFICIAL_LOGIN} id={OFFICIAL_USER_ID} app=/{OFFICIAL_APP_SLUG}"
        )

        app = gh_api(f"apps/{OFFICIAL_APP_SLUG}")
        assert_official_app(app)
        log(
            f"confirmed GitHub App slug={app.get('slug')} id={app.get('id')} "
            f"owner={((app.get('owner') or {}).get('login'))}"
        )

        if args.pr is not None:
            numbers = [args.pr]
            early = []
            log(f"inspecting PR #{args.pr} only")
        else:
            pulls = gh_api_list("repos/{owner}/{repo}/pulls?state=open")
            numbers, early = prefilter_list_payload(pulls, None)
            log(
                f"open PRs listed={len(pulls)} "
                f"candidates={len(numbers)} prefiltered={len(early)}"
            )
        merged = 0
        skipped = 0
        rejected = 0
        errors = 0

        def apply_decision(decision: Decision) -> None:
            nonlocal merged, skipped, rejected, errors
            prefix = f"PR #{decision.number} {decision.title!r}"
            if decision.action == "merge":
                log(f"{prefix}: MERGE {decision.reason} sha={decision.sha[:12]}")
                if args.dry_run:
                    log(f"{prefix}: dry-run, not merging")
                    return
                try:
                    merge_pr(decision.number, decision.sha)
                    merged += 1
                except MergeDeclined as exc:
                    log(f"{prefix}: skip: {exc}")
                    skipped += 1
                except Exception as exc:
                    log(f"{prefix}: merge failed: {exc}")
                    errors += 1
            elif decision.action == "reject":
                log(f"{prefix}: SECURITY reject: {decision.reason}")
                rejected += 1
            else:
                log(f"{prefix}: skip: {decision.reason}")
                skipped += 1

        for decision in early:
            apply_decision(decision)
        for number in numbers:
            try:
                pr, commits, check_runs, combined = fetch_pr_bundle(number)
            except Exception as exc:
                log(f"PR #{number}: failed to fetch: {exc}")
                errors += 1
                continue
            apply_decision(
                classify_pr(
                    pr, commits, check_runs, combined,
                    default_branch=default_branch,
                )
            )
        log(
            f"done merged={merged} skipped={skipped} rejected={rejected} errors={errors}"
        )
        return 1 if errors else 0
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
