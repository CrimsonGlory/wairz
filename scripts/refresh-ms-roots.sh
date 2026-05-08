#!/bin/bash
# Quarterly cron: verify the bundled Microsoft trust anchors in
# backend/ms-anchors/ are still current vs. Microsoft's canonical sources.
#
# Phase β.10 (CLAUDE.md Rule #37 candidate — offline-trust-anchor discipline).
# The wairz worker image bakes the UEFI DBX revocation list at build time so
# DBX matching runs FULLY OFFLINE at scan time. This script is the host-side
# refresh path; the worker image itself never reaches out to Microsoft.
#
# What it does (default, no flags):
#   1. Atomically downloads the live DBXUpdate.bin from Microsoft's
#      canonical repo (via the URL pinned in backend/ms-anchors/
#      dbxupdate.bin.url) to a /tmp staging area (.tmp suffix, then
#      rename per Rule #19 evidence-first atomic-write discipline).
#   2. Computes the live SHA256 and compares against the pinned hash in
#      backend/ms-anchors/dbxupdate.bin.sha256.
#   3. If MATCH → exits 0 ("bundle current, no action needed").
#   4. If MISMATCH → exits non-zero, prints the operator workflow for
#      reviewing + applying the new pin. The cron alert fires; an
#      operator manually reviews the new bundle, replaces the pinned
#      copy, and rebuilds.
#
# Optional flags:
#   --apply    On mismatch, automatically replace backend/ms-anchors/
#              dbxupdate.bin + dbxupdate.bin.sha256 with the live values.
#              Operator must still git-commit + rebuild manually.
#   --rebuild  After a successful match (or after --apply succeeds), run
#              `docker compose build --no-cache --pull worker backend`
#              to refresh the image. Quiet on no-op match; loud on
#              rebuild failure.
#   --quiet    Suppress informational lines; only print on action / error.
#
# Recommended cron line (UTC, 03:30 first Sunday of every quarter):
#
#   30 3 1-7 1,4,7,10 0 [REPO_PATH]/scripts/refresh-ms-roots.sh \
#       2>&1 | logger -t wairz-refresh-ms-roots
#
# Refresh schedule rationale: Microsoft publishes new DBXUpdate.bin
# revisions a few times per year (typically tied to KB cumulative
# updates that revoke compromised UEFI bootloaders). Quarterly catches
# every release with ample drift-investigation lead time.
#
# Sources:
#   github.com/microsoft/secureboot_objects (UEFI Forum redirected operators
#   here in 2024; canonical source for DBX since ~Apr 2024).
#
# Exit codes:
#   0   Bundle is current, OR --apply succeeded.
#   1   Mismatch + no --apply (operator review required).
#   2   Network / parse / file-system error.
#   3   --rebuild requested but `docker compose build` failed.

set -eu

# ── Path / constants ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ANCHORS_DIR="$REPO_ROOT/backend/ms-anchors"
PINNED_BIN="$ANCHORS_DIR/dbxupdate.bin"
PINNED_SHA256="$ANCHORS_DIR/dbxupdate.bin.sha256"
PINNED_URL_FILE="$ANCHORS_DIR/dbxupdate.bin.url"

APPLY=0
REBUILD=0
QUIET=0
for arg in "$@"; do
    case "$arg" in
        --apply)   APPLY=1 ;;
        --rebuild) REBUILD=1 ;;
        --quiet)   QUIET=1 ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "ERROR: unknown flag: $arg (use --help for usage)" >&2
            exit 2
            ;;
    esac
done

# ── Helpers ──────────────────────────────────────────────────────────────
log() {
    if [ "$QUIET" -eq 0 ]; then
        echo "[refresh-ms-roots] $*"
    fi
}

err() {
    echo "[refresh-ms-roots] ERROR: $*" >&2
}

require_file() {
    if [ ! -f "$1" ]; then
        err "missing pinned file: $1"
        exit 2
    fi
}

# ── Sanity-check the repo state ──────────────────────────────────────────
require_file "$PINNED_BIN"
require_file "$PINNED_SHA256"
require_file "$PINNED_URL_FILE"

LIVE_URL="$(head -n1 "$PINNED_URL_FILE")"
PINNED_HASH="$(awk '{print $1}' "$PINNED_SHA256")"

if [ -z "$LIVE_URL" ] || [ -z "$PINNED_HASH" ]; then
    err "pinned URL or SHA256 is empty in backend/ms-anchors/"
    exit 2
fi

log "pinned hash: $PINNED_HASH"
log "live URL:    $LIVE_URL"

# ── Atomic download to /tmp staging ─────────────────────────────────────
STAGING_DIR="$(mktemp -d -t refresh-ms-roots.XXXXXX)"
# Ensure the tmp dir is cleaned up on any exit.
trap 'rm -rf "$STAGING_DIR"' EXIT

STAGING_TMP="$STAGING_DIR/dbxupdate.bin.tmp"
STAGING_FINAL="$STAGING_DIR/dbxupdate.bin"

log "downloading live bundle to $STAGING_TMP"
# Rule #35a: capture exit code without piping. curl writes to a tmp file;
# the trailing `|| DOWNLOAD_RC=$?` form preserves set -e for everything
# else AND lets us inspect the curl exit explicitly.
DOWNLOAD_RC=0
curl --proto '=https' --tlsv1.2 -fsSL --max-time 60 \
     -o "$STAGING_TMP" "$LIVE_URL" > /tmp/refresh-ms-roots.curl.out 2>&1 \
     || DOWNLOAD_RC=$?
if [ "$DOWNLOAD_RC" -ne 0 ]; then
    err "curl exited $DOWNLOAD_RC; see /tmp/refresh-ms-roots.curl.out"
    cat /tmp/refresh-ms-roots.curl.out >&2 || true
    exit 2
fi

if [ ! -s "$STAGING_TMP" ]; then
    err "downloaded artifact is empty"
    exit 2
fi

# Atomic rename (.tmp → final). Within the same filesystem, mv is atomic.
mv "$STAGING_TMP" "$STAGING_FINAL"
LIVE_HASH="$(sha256sum "$STAGING_FINAL" | awk '{print $1}')"
LIVE_SIZE="$(stat -c %s "$STAGING_FINAL")"
log "live hash:   $LIVE_HASH (size=$LIVE_SIZE bytes)"

# ── Compare and report ──────────────────────────────────────────────────
if [ "$LIVE_HASH" = "$PINNED_HASH" ]; then
    log "MATCH — bundle is current; no operator action required"
    if [ "$REBUILD" -eq 1 ]; then
        log "running docker compose build --no-cache --pull worker backend …"
        REBUILD_RC=0
        ( cd "$REPO_ROOT" && docker compose build --no-cache --pull worker backend ) \
            > /tmp/refresh-ms-roots.rebuild.out 2>&1 \
            || REBUILD_RC=$?
        if [ "$REBUILD_RC" -ne 0 ]; then
            err "docker compose build failed (rc=$REBUILD_RC); see /tmp/refresh-ms-roots.rebuild.out"
            tail -40 /tmp/refresh-ms-roots.rebuild.out >&2 || true
            exit 3
        fi
        log "rebuild OK"
    fi
    exit 0
fi

# ── Mismatch path ───────────────────────────────────────────────────────
echo ""
echo "[refresh-ms-roots] !!! DBX BUNDLE DRIFT DETECTED !!!"
echo "  pinned: $PINNED_HASH (in backend/ms-anchors/dbxupdate.bin.sha256)"
echo "  live:   $LIVE_HASH (just downloaded from $LIVE_URL)"
echo "  size:   $LIVE_SIZE bytes (vs pinned $(stat -c %s "$PINNED_BIN") bytes)"
echo ""

if [ "$APPLY" -eq 0 ]; then
    cat <<EOF
[refresh-ms-roots] OPERATOR WORKFLOW (no --apply):

  1. Inspect the new bundle for plausibility (size in range, parses cleanly):
       python3 -c "from app.services.dbx_service import _strip_authenticated_variable_wrapper, _parse_bundle_bytes; \\
                   buf=open('$STAGING_FINAL','rb').read(); \\
                   p=_parse_bundle_bytes(_strip_authenticated_variable_wrapper(buf)); \\
                   print(p['entries_scanned'], 'entries:', \\
                         len(p['x509_serials']), 'x509,', \\
                         len(p['sha256_hashes']), 'sha256')"

  2. If the new bundle looks legitimate, replace the pinned copy:
       cp '$STAGING_FINAL' '$PINNED_BIN'
       (cd '$ANCHORS_DIR' && sha256sum dbxupdate.bin > dbxupdate.bin.sha256)
       git add backend/ms-anchors/dbxupdate.bin backend/ms-anchors/dbxupdate.bin.sha256
       git commit -m "chore(ms-anchors): refresh DBX bundle ($PINNED_HASH → $LIVE_HASH)"

  3. Rebuild the worker + backend (CLAUDE.md Rule #8):
       docker compose build --no-cache --pull worker backend
       docker compose up -d worker backend

  4. Verify the boot-time probe in main.py reports the new size + mtime:
       docker compose logs backend 2>&1 | grep "DBX bundle ready"

  Or re-run this script with --apply --rebuild to skip steps 2-3.

EOF
    exit 1
fi

# --apply path
log "--apply: replacing pinned bundle + sha256"
cp "$STAGING_FINAL" "$PINNED_BIN"
(cd "$ANCHORS_DIR" && sha256sum dbxupdate.bin > dbxupdate.bin.sha256)
log "pinned bundle replaced; new sha256 = $(awk '{print $1}' "$PINNED_SHA256")"

if [ "$REBUILD" -eq 1 ]; then
    log "running docker compose build --no-cache --pull worker backend …"
    REBUILD_RC=0
    ( cd "$REPO_ROOT" && docker compose build --no-cache --pull worker backend ) \
        > /tmp/refresh-ms-roots.rebuild.out 2>&1 \
        || REBUILD_RC=$?
    if [ "$REBUILD_RC" -ne 0 ]; then
        err "docker compose build failed (rc=$REBUILD_RC); see /tmp/refresh-ms-roots.rebuild.out"
        tail -40 /tmp/refresh-ms-roots.rebuild.out >&2 || true
        exit 3
    fi
    log "rebuild OK; remember to: docker compose up -d worker backend"
fi

log "Operator: don't forget to commit the updated backend/ms-anchors/ pin"
exit 0
