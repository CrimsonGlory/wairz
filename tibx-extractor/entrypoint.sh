#!/usr/bin/env bash
# wairz tibx-extractor entrypoint
#
# Resolves tibxread inside the bind-mounted /opt/acronis (BYOB mode) and
# executes it with caller-supplied arguments. Stdout is redirected to
# /work/disk.raw inside the writable named volume; stderr is preserved
# on the container's stderr for the worker to capture via container.logs.
#
# Exit codes:
#   0   — tibxread succeeded; /work/disk.raw populated.
#   2   — tibxread binary not found inside /opt/acronis (operator hasn't
#         set WAIRZ_TIBX_AGENT_PATH OR the host install is incomplete).
#   3   — /work mount is missing or not writable.
#   4   — bad argv (no subcommand passed).
#   N   — passthrough of tibxread's own exit code.
#
# Companion to CLAUDE.md Rule #36 Exception 3 — the container is the
# security boundary; this script DOES invoke an operator-supplied
# binary, but only inside the network_mode=none + cap_drop ALL
# sandbox the docker-compose service declares. Wairz worker code
# never invokes this script directly; it spawns the container via
# `client.containers.run` and reads /work/disk.raw afterward.

set -euo pipefail

print_usage() {
    cat <<EOF
wairz tibx-extractor side-container

Usage (via worker `client.containers.run`):

  wairz-tibx-extractor get content \\
      --loc <dir-inside-/data/firmware> \\
      --arc <master.tibx basename> \\
      --backup <recovery_point_id> \\
      --disk <disk_number>
  → writes raw disk bytes to /work/disk.raw

  wairz-tibx-extractor list backups \\
      --loc <dir-inside-/data/firmware> \\
      --arc <master.tibx basename>
  → prints recovery-point IDs to stdout (JSON)

  wairz-tibx-extractor list content \\
      --loc <dir-inside-/data/firmware> \\
      --arc <master.tibx basename> \\
      --backup <recovery_point_id>
  → prints disk listing to stdout (JSON)

Environment:
  /opt/acronis    bind-mounted operator Acronis install (BYOB)
  /data/firmware  bind-mounted customer firmware tree (read-only)
  /work           output named volume (writable; disk.raw lands here)

If /opt/acronis is empty (operator hasn't set WAIRZ_TIBX_AGENT_PATH),
exit 2 with an actionable error.
EOF
}

# Help mode — also fires on default CMD ["--help"]
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    print_usage
    exit 0
fi

# Pre-flight: /work must be writable for the output to land.
if [[ ! -d /work ]]; then
    echo "tibx-extractor: /work mount missing — docker-compose must mount the tibx_work named volume at /work" >&2
    exit 3
fi
if ! touch /work/.tibx_extractor_writable_probe 2>/dev/null; then
    echo "tibx-extractor: /work not writable — check docker-compose volume permissions (expected uid:gid 65534:65534)" >&2
    exit 3
fi
rm -f /work/.tibx_extractor_writable_probe

# Pre-flight: /opt/acronis must carry a tibxread binary.
#
# The Acronis Agent for Linux installs to /usr/lib/Acronis/BackupAndRecovery
# on the host; the operator points WAIRZ_TIBX_AGENT_PATH at that
# directory and docker-compose bind-mounts it at /opt/acronis. The
# binary's exact name + relative path matches what the host install
# carries — typically /opt/acronis/tibxread but Acronis has shipped
# under sub-dirs in the past. Search both layouts.
TIBXREAD_PATH=""
if [[ -x /opt/acronis/tibxread ]]; then
    TIBXREAD_PATH=/opt/acronis/tibxread
elif [[ -x /opt/acronis/Common/tibxread ]]; then
    TIBXREAD_PATH=/opt/acronis/Common/tibxread
elif [[ -x /opt/acronis/Agent/tibxread ]]; then
    TIBXREAD_PATH=/opt/acronis/Agent/tibxread
else
    # Fall back: scan up to 3 levels deep for any tibxread.
    TIBXREAD_PATH=$(find /opt/acronis -maxdepth 3 -name tibxread -type f -perm -u+x 2>/dev/null | head -n1 || true)
fi

if [[ -z "${TIBXREAD_PATH}" || ! -x "${TIBXREAD_PATH}" ]]; then
    cat >&2 <<EOF
tibx-extractor: tibxread binary not found inside /opt/acronis

The wairz tibx-extractor side-container runs in BYOB mode (Bring Your
Own Binary): the operator must install Acronis Cyber Protection Agent
for Linux on the build host AND point WAIRZ_TIBX_AGENT_PATH at the
canonical install directory (typically /usr/lib/Acronis/BackupAndRecovery).

The docker-compose 'tibx-extractor' service bind-mounts that directory
to /opt/acronis read-only at container start. If you see this error,
either:

  1. WAIRZ_TIBX_AGENT_PATH is unset / set to /dev/null (default).
     Install Acronis Agent for Linux (30-day free trial available at
     https://www.acronis.com/en-us/products/cyber-protect/) and set
     the env var in your .env file.

  2. The Acronis install path on the host does not match the expected
     layout. Verify by running 'find / -name tibxread -executable'
     on the host; point WAIRZ_TIBX_AGENT_PATH at the parent of the
     binary.

CLAUDE.md Rule #37 + EULA: wairz does NOT bundle Acronis binaries;
operator-supplied binaries via bind mount are the only supported
shipping mode.
EOF
    exit 2
fi

# Validate that the first arg is one of the documented subcommands.
SUBCMD="${1:-}"
case "${SUBCMD}" in
    get|list|calculate)
        : # Recognised; pass everything through.
        ;;
    "")
        echo "tibx-extractor: no subcommand passed — see --help" >&2
        exit 4
        ;;
    *)
        echo "tibx-extractor: unknown subcommand '${SUBCMD}' — see --help" >&2
        exit 4
        ;;
esac

# 'get content' is the only subcommand whose stdout is binary disk bytes;
# the worker wants those captured into /work/disk.raw. 'list backups' and
# 'list content' produce JSON stdout that the worker reads via
# container.logs(stream=False). Decide based on the subcommand pair.
SUBSUBCMD="${2:-}"
if [[ "${SUBCMD}" == "get" && "${SUBSUBCMD}" == "content" ]]; then
    # Binary stdout → file. stdbuf -o0 to avoid buffering on a multi-GB
    # stream. Errors go to stderr (captured by the worker via
    # container.logs(stderr=True)).
    exec stdbuf -o0 "${TIBXREAD_PATH}" "$@" > /work/disk.raw
else
    # JSON / metadata subcommands — let the worker read stdout via logs.
    exec "${TIBXREAD_PATH}" "$@"
fi
