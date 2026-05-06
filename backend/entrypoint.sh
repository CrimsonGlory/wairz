#!/bin/sh
set -e

# Fix Docker socket group at runtime so emulation/fuzzing work regardless
# of the host's docker GID. Runs as root, then drops to wairz.
if [ -S /var/run/docker.sock ]; then
    SOCK_GID=$(stat -c %g /var/run/docker.sock)
    CUR_GID=$(getent group docker 2>/dev/null | cut -d: -f3)
    if [ -n "$SOCK_GID" ] && [ "$SOCK_GID" != "${CUR_GID:-}" ]; then
        groupmod -g "$SOCK_GID" docker 2>/dev/null || groupadd -g "$SOCK_GID" docker 2>/dev/null || true
        usermod -aG docker wairz 2>/dev/null || true
    fi
fi

# Ensure /tmp/wairz-dumps exists and is writable by the wairz user. The
# directory is a host bind-mount (docker-compose.yml backend + worker
# services) shared with the host-side device-acquisition bridge. When
# the host directory is created by root (or hasn't been created at all)
# the in-container wairz UID can't write into it, so device dumps fail
# at the first write. mkdir -p is idempotent; chown is non-recursive
# (cheap, and the per-dump-id subdirs created by the bridge are already
# correctly owned).
mkdir -p /tmp/wairz-dumps
chown wairz:wairz /tmp/wairz-dumps 2>/dev/null || true

# Use the pre-built venv directly instead of `uv run` which recreates the
# venv and wipes manually-installed packages (Qiling, keystone-engine).
#
# Alembic migration is no longer run here — the ``migrator`` one-shot service
# in docker-compose.yml handles schema upgrades exactly once before backend +
# worker start (Phase 3 / O2). Backend + worker depend_on migrator with
# ``condition: service_completed_successfully``.
exec su -s /bin/sh wairz -c '.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000'
