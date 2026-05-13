# wairz tibx-extractor side-container (Phase λ.μ — BYOB-SC)
#
# Hardened Alpine sandbox that runs Acronis tibxread against a customer-
# supplied .tibx file and writes the recovered disk bytes to a named volume.
# The worker tier reads from the same named volume and copies the result
# into the firmware's extraction_dir.
#
# Architecture per CLAUDE.md Rule #36 amendment Exception 3 (sandboxed
# vendor parser binaries operating on customer data AS DATA inside an
# isolated side-container). Companion to wairz emulation / fuzzing /
# system-emulation side-containers.
#
# Two operating modes:
#
#   1. BYOB (bring-your-own-binary). Operator installs Acronis Cyber
#      Protection Agent for Linux on the host once, sets
#      WAIRZ_TIBX_AGENT_PATH=/usr/lib/Acronis/BackupAndRecovery, and the
#      docker-compose service bind-mounts that directory read-only at
#      /opt/acronis. entrypoint.sh resolves tibxread inside /opt/acronis.
#
#   2. Pre-bundled (future). A future image revision could COPY a
#      vendor-supplied tibxread under /usr/local/bin/. Per operator
#      EULA review, this is permitted; defer until the binary is in
#      hand.
#
# Per Rule #36: this container is the SECURITY BOUNDARY. The wairz
# worker NEVER invokes tibxread directly; the container's
# network_mode=none + cap_drop ALL + read_only + non-root user means
# even a compromised tibxread cannot reach the wairz worker, network,
# or write to anything outside the /work named volume.
#
# Per Rule #37: tibxread runs with no network access. Customer .tibx
# bytes never leave the worker host. Output bytes flow only into the
# bind-mounted named volume that the worker re-reads.

FROM alpine:3.20

# Minimal runtime: sh (busybox), bash for entrypoint.sh, coreutils for
# stdbuf+ls+stat+dd, ca-certificates for any future Acronis-side TLS,
# tini as PID-1 reaper (matches the emulation / fuzzing precedent).
RUN apk add --no-cache \
        bash \
        coreutils \
        ca-certificates \
        tini \
    && rm -rf /var/cache/apk/*

# Non-root operator. UID 65534 is "nobody" on most Linux distros; we
# pin it explicitly to match the docker-compose `user: 65534:65534`
# entry so volume permissions resolve cleanly.
RUN addgroup -g 65534 -S nogroup 2>/dev/null || true \
    && adduser -u 65534 -S -G nogroup nobody 2>/dev/null || true

# Mount points the docker-compose service will populate at runtime:
#   /opt/acronis     — operator-supplied Acronis install (read-only bind)
#   /data/firmware   — customer firmware data (read-only named volume)
#   /work            — output named volume (writable; container's only
#                      writable path besides tmpfs /tmp)
RUN mkdir -p /opt/acronis /data/firmware /work \
    && chown nobody:nogroup /work

COPY --chmod=0555 entrypoint.sh /usr/local/bin/entrypoint.sh

USER 65534:65534

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]

# Default command is help text — the worker overrides with the actual
# tibxread argv at runtime via `client.containers.run(command=[...])`.
CMD ["--help"]
