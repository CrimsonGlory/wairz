# =============================================================================
# Wairz harness-build sandbox
#
# Cross-compiles a fuzzing harness that links a firmware shared library, for
# the firmware's architecture, using Bootlin "stable" toolchains pinned to an
# OLD glibc (2.27). Firmware userlands are typically built against an older
# glibc (e.g. 2.25); a harness built with a modern toolchain requires newer
# symbol versions (GLIBC_2.34+) that the firmware libc lacks, so it won't run
# under qemu-user against the firmware libraries. The Bootlin toolchains emit
# binaries needing only base symbol versions (GLIBC_2.4 on ARM), which run
# against any reasonably modern firmware libc.
#
# Never runs from compose — the backend spawns it network-less via the Docker
# SDK (mirrors the carving sandbox), mounts the firmware rootfs read-only and a
# writable carved/ output dir, builds the harness ELF, and exits.
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: fetch + unpack the per-architecture cross toolchains
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS toolchains

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget bzip2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG BOOTLIN=https://toolchains.bootlin.com/downloads/releases/toolchains

# "<bootlin-arch>:<tarball-stem>:<wairz-arch-key>"
# wairz-arch-key matches the firmware architecture the backend resolves
# (arm soft-float→armel, arm hard-float→armhf, aarch64, mips, mipsel).
RUN set -eu; mkdir -p /opt/toolchains; \
    for spec in \
        "armv7-eabihf:armv7-eabihf--glibc--stable-2018.11-1:armhf" \
        "armv5-eabi:armv5-eabi--glibc--stable-2018.11-1:armel" \
        "aarch64:aarch64--glibc--stable-2018.11-1:aarch64" \
        "mips32el:mips32el--glibc--stable-2018.11-1:mipsel" \
        "mips32:mips32--glibc--stable-2018.11-1:mips" ; do \
        barch="${spec%%:*}"; rest="${spec#*:}"; name="${rest%%:*}"; key="${rest##*:}"; \
        echo "Fetching $key toolchain ($name)"; \
        wget -q "$BOOTLIN/$barch/tarballs/$name.tar.bz2" -O /tmp/tc.tar.bz2; \
        mkdir -p "/opt/toolchains/$key"; \
        tar xf /tmp/tc.tar.bz2 -C "/opt/toolchains/$key" --strip-components=1; \
        rm -f /tmp/tc.tar.bz2; \
        # Trim weight: drop docs and the host-side debugger/gdb data.
        rm -rf "/opt/toolchains/$key/share/doc" "/opt/toolchains/$key/share/gdb" \
               "/opt/toolchains/$key/share/locale" 2>/dev/null || true; \
    done

# ---------------------------------------------------------------------------
# Stage 2: lean runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-user-static binutils file \
    && rm -rf /var/lib/apt/lists/*

COPY --from=toolchains /opt/toolchains /opt/toolchains
COPY build-harness.sh /opt/build-harness.sh
RUN chmod +x /opt/build-harness.sh \
    && useradd -m -u 1000 builder \
    && mkdir -p /carved && chown builder:builder /carved

CMD ["sleep", "infinity"]
