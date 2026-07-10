# =============================================================================
# FirmAE System Emulation Container for Wairz
#
# Wraps FirmAE (https://github.com/pr0v3rbs/FirmAE) in a Docker container
# with a Flask API shim for automated full-system firmware emulation.
#
# Multi-stage build:
#   Stage 1 — Build libnvram cross-compiled .so files (cross-compilers discarded)
#   Stage 2 — Runtime image with FirmAE, QEMU, PostgreSQL, Flask shim
#
# Requires: --privileged (or NET_ADMIN + SYS_ADMIN + MKNOD caps + /dev/net/tun)
# =============================================================================

# ---------------------------------------------------------------------------
# Builder stage: cross-compile libnvram for all target architectures
# ---------------------------------------------------------------------------
FROM ubuntu:26.04 AS libnvram-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc-mipsel-linux-gnu gcc-mips-linux-gnu \
    gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/pr0v3rbs/FirmAE.git /opt/FirmAE

RUN mkdir -p /out && \
    if [ -d "/opt/FirmAE/src/libnvram" ]; then \
        cd /opt/FirmAE/src/libnvram && \
        CC=mipsel-linux-gnu-gcc make 2>/dev/null && \
            cp libnvram.so /out/libnvram.so.mipsel; \
        make clean 2>/dev/null; \
        CC=mips-linux-gnu-gcc make 2>/dev/null && \
            cp libnvram.so /out/libnvram.so.mips; \
        make clean 2>/dev/null; \
        CC=arm-linux-gnueabi-gcc make 2>/dev/null && \
            cp libnvram.so /out/libnvram.so.armel; \
        make clean 2>/dev/null; \
    fi && \
    if [ -d "/opt/FirmAE/src/console" ]; then \
        cd /opt/FirmAE/src/console && make 2>/dev/null || true; \
    fi

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive
ENV FIRMAE_DIR=/opt/FirmAE
ENV PGDATA=/var/lib/postgresql/15/firmae
ENV PGUSER=postgres
ENV FLASK_APP=/opt/shim/app.py

# ---------------------------------------------------------------------------
# 1. System dependencies
# ---------------------------------------------------------------------------

# Add PostgreSQL apt repo (postgresql-15 not in default jammy repos)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gnupg2 lsb-release curl ca-certificates \
    && echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
       > /etc/apt/sources.list.d/pgdg.list \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
       | gpg --dearmor -o /etc/apt/trusted.gpg.d/postgresql.gpg \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    # PostgreSQL 15
    postgresql-15 postgresql-client-15 \
    # QEMU system emulators
    qemu-system-arm qemu-system-mips qemu-system-x86 \
    qemu-utils \
    # Networking tools
    nmap socat iproute2 iptables bridge-utils net-tools iputils-ping tcpdump \
    busybox-static \
    # FirmAE dependencies
    binwalk \
    python3 python3-pip python3-venv python3-psycopg2 \
    git wget curl \
    unzip p7zip-full \
    mtd-utils gzip bzip2 arj lhasa \
    squashfs-tools \
    e2fsprogs \
    kpartx \
    uml-utilities \
    sudo bc file cpio fdisk bash-static \
    lsof procps \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 2. Clone FirmAE
# ---------------------------------------------------------------------------
RUN git clone --depth 1 https://github.com/pr0v3rbs/FirmAE.git ${FIRMAE_DIR}

WORKDIR ${FIRMAE_DIR}

# ---------------------------------------------------------------------------
# 3. Copy pre-built libnvram binaries from builder stage
# ---------------------------------------------------------------------------
# Cross-compilers are only in the builder stage — not in the final image.
RUN mkdir -p ${FIRMAE_DIR}/binaries
COPY --from=libnvram-builder /out/libnvram.so.* ${FIRMAE_DIR}/binaries/

# ---------------------------------------------------------------------------
# 3b. Patch FirmAE for Docker compatibility (no kpartx/loop partitions)
# ---------------------------------------------------------------------------
COPY patches/ /tmp/patches/
RUN chmod +x /tmp/patches/*.sh && \
    /tmp/patches/docker-compat.sh ${FIRMAE_DIR} && \
    rm -rf /tmp/patches

# ---------------------------------------------------------------------------
# 4. Download pre-built FirmAE kernels
# ---------------------------------------------------------------------------
RUN mkdir -p ${FIRMAE_DIR}/binaries && \
    cd ${FIRMAE_DIR} && \
    # FirmAE stores kernels in its binaries/ directory
    # Download kernel images if the download script exists
    if [ -f "${FIRMAE_DIR}/download.sh" ]; then \
        bash ${FIRMAE_DIR}/download.sh 2>/dev/null || true; \
    fi

# ---------------------------------------------------------------------------
# 5. Initialize PostgreSQL data directory
# ---------------------------------------------------------------------------
RUN mkdir -p ${PGDATA} /run/postgresql && \
    chown -R postgres:postgres /var/lib/postgresql /run/postgresql && \
    su - postgres -c "/usr/lib/postgresql/15/bin/initdb -D ${PGDATA}"

# ---------------------------------------------------------------------------
# 6. Install Flask API shim dependencies
# ---------------------------------------------------------------------------
RUN pip3 install --no-cache-dir \
    flask \
    gunicorn \
    psycopg2-binary \
    python-magic

# ---------------------------------------------------------------------------
# 7. Copy shim application and entrypoint
# ---------------------------------------------------------------------------
COPY shim/ /opt/shim/
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh /opt/shim/*.py 2>/dev/null || true

# ---------------------------------------------------------------------------
# 8. Create working directories and set permissions
# ---------------------------------------------------------------------------
RUN mkdir -p /firmwares /data/logs /data/scratch && \
    # FirmAE needs write access to its own directories
    chmod -R 777 ${FIRMAE_DIR}/scratch 2>/dev/null || mkdir -p ${FIRMAE_DIR}/scratch && chmod 777 ${FIRMAE_DIR}/scratch && \
    chmod -R 777 ${FIRMAE_DIR}/images 2>/dev/null || mkdir -p ${FIRMAE_DIR}/images && chmod 777 ${FIRMAE_DIR}/images

# Expose Flask shim API
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

ENTRYPOINT ["/opt/entrypoint.sh"]
