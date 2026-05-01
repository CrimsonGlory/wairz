# =============================================================================
# Wairz Carving Sandbox
#
# A locked-down environment where the AI agent can run binwalk, dd, python3
# (with cryptography), and friends against the raw firmware image. One
# long-running container per active project; containers are spawned by the
# backend's CarvingService via the Docker SDK and isolated with:
#
#   - network_mode=none
#   - cap_drop=ALL, no-new-privileges
#   - non-root user (uid 1000)
#   - read-only root FS, writable bind only at /carved/, tmpfs at /tmp
#   - bind mounts: /image/firmware.bin (RO), /extracted/ (RO), /carved/ (RW)
#
# The agent invokes commands via `docker exec`, so the container ENTRYPOINT
# just keeps the process alive.
# =============================================================================

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Core analysis toolset. Picked to cover what the carving briefing
# (WAIRZ_CARVING_BRIEFING.md) called out as needed:
#
#   binwalk + magic        — signature scan and -e extraction
#   dd, xxd, hexdump       — raw-byte read/write
#   file, strings, grep    — basic triage
#   binutils               — readelf, objdump for ELF inspection
#   python3 + crypto libs  — AES/XXTEA/XOR decryption, scripting
#   lz4 / xz / zstd        — common firmware compression formats
#   squashfs-tools         — unsquashfs
#   jefferson              — jffs2 (installed via pip below)
#   ubi_reader             — UBIFS (installed via pip below)
#   mtd-utils              — mtdinfo, ubinfo, etc.
#   u-boot-tools           — mkimage for parsing/creating uImage
#   p7zip-full, libarchive-tools, cpio — generic archive handling
#   jq                     — JSON manipulation in shell
RUN apt-get update && apt-get install -y --no-install-recommends \
        binwalk \
        bsdmainutils \
        coreutils \
        cpio \
        file \
        grep \
        jq \
        less \
        libarchive-tools \
        lz4 \
        mtd-utils \
        p7zip-full \
        python3 \
        python3-pip \
        squashfs-tools \
        u-boot-tools \
        binutils \
        vim-common \
        xxd \
        xz-utils \
        zstd \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Python crypto + filesystem unpackers. --break-system-packages because
# Debian bookworm ships PEP 668's externally-managed-environment marker;
# the container is single-purpose so a system-wide install is fine.
RUN pip3 install --no-cache-dir --break-system-packages \
        cryptography \
        pycryptodome \
        jefferson \
        ubi_reader

# Non-root user. Permissions on /carved/ are set by the backend before the
# bind mount is attached; uid/gid 1000 matches the typical host user so
# files written from the container are readable from the backend.
RUN groupadd -g 1000 wairz && useradd -m -u 1000 -g 1000 -s /bin/bash wairz

# /carved/ is the only writable bind mount; /tmp is provided by the runtime
# as a tmpfs. Everything else (root FS, /image/, /extracted/) is read-only.
RUN mkdir -p /carved /image /extracted \
    && chown wairz:wairz /carved

USER wairz
WORKDIR /carved

# Keep the container alive so the backend can `docker exec` into it. Exec
# style avoids a shell wrapper that would absorb signals.
CMD ["sleep", "infinity"]
