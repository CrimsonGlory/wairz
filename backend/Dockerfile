# ---------------------------------------------------------------------------
# Builder stage: UEFIExtract + UEFIFind (cmake + qt6 only needed at build time)
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS uefi-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake qt6-base-dev git ca-certificates build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/LongSoft/UEFITool.git /tmp/UEFITool && \
    cd /tmp/UEFITool && \
    cmake -DCMAKE_BUILD_TYPE=Release . && \
    make -j$(nproc) UEFIExtract UEFIFind && \
    cp UEFIExtract/uefiextract /out-uefiextract && \
    cp UEFIFind/uefifind /out-uefifind && \
    chmod +x /out-uefiextract /out-uefifind

# ---------------------------------------------------------------------------
# Main image
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS base

# Install system dependencies for firmware analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    sleuthkit \
    squashfs-tools \
    cramfsswap \
    util-linux-extra \
    mtd-utils \
    e2fsprogs \
    cpio \
    p7zip-full \
    wimtools \
    cabextract \
    lzop \
    lz4 \
    zstd \
    lziprecover \
    unar \
    partclone \
    srecord \
    file \
    libmagic1 \
    build-essential \
    git \
    zlib1g-dev \
    liblzma-dev \
    liblzo2-dev \
    liblz4-dev \
    libzstd-dev \
    wget \
    curl \
    unzip \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    libyara-dev \
    shellcheck \
    pkg-config \
    libfontconfig1-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/* \
    && printf '#!/bin/sh\n# Wrapper: translates cramfsck -x <dir> <file> to fsck.cramfs --extract=<dir> <file>\nif [ "$1" = "-x" ]; then shift; dir="$1"; shift; exec fsck.cramfs --extract="$dir" "$@"; fi\nexec fsck.cramfs "$@"\n' > /usr/local/bin/cramfsck \
    && chmod +x /usr/local/bin/cramfsck

# Install binwalk3 Rust CLI from source (multi-arch: builds natively on both
# x86_64 and ARM64). The pip package only ships Windows binaries; Linux needs
# a source build. pkg-config + libfontconfig1-dev installed in base apt block.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal \
    && . "$HOME/.cargo/env" \
    && git clone --depth 1 --branch v3.1.0 https://github.com/ReFirmLabs/binwalk.git /tmp/binwalk3-src \
    && cd /tmp/binwalk3-src \
    && cargo build --release \
    && cp target/release/binwalk /usr/local/bin/binwalk3 \
    && chmod +x /usr/local/bin/binwalk3 \
    && rm -rf /tmp/binwalk3-src "$HOME/.cargo" "$HOME/.rustup" /var/lib/apt/lists/* \
    && binwalk3 --version \
    || echo "WARN: binwalk3 Rust build failed — will fall back to unblob"

RUN pip3 install --no-cache-dir --break-system-packages \
    binwalk3 \
    jefferson \
    ubi_reader \
    && pip3 install --no-cache-dir --break-system-packages \
       git+https://github.com/devttys0/yaffshiv.git 2>/dev/null \
    || echo "WARN: yaffshiv install failed — YAFFS extraction won't work"

# Install unblob — universal firmware extractor (78+ formats including Rockchip,
# MediaTek, Qualcomm, and many proprietary container formats). Used as fallback
# when binwalk times out or can't handle the container format.
RUN pip3 install --no-cache-dir --break-system-packages unblob \
    || echo "WARN: unblob install failed — fallback extraction won't work"

# Download YARA Forge community rules (~5000 detections, zero cost)
# Distributed as a zip containing packages/core/yara-rules-core.yar
# Graceful fallback if GitHub is unreachable during build
RUN mkdir -p /data/yara-forge \
    && curl -fsSL --max-time 60 -o /tmp/yara-forge.zip \
       "$(curl -s https://api.github.com/repos/YARAHQ/yara-forge/releases/latest \
          | grep -o 'https://[^"]*yara-forge-rules-core.zip' | head -1)" \
    && unzip -o /tmp/yara-forge.zip -d /tmp/yara-forge-extract \
    && mv /tmp/yara-forge-extract/packages/core/yara-rules-core.yar /data/yara-forge/ \
    && rm -rf /tmp/yara-forge.zip /tmp/yara-forge-extract \
    || echo "WARN: YARA Forge download failed — use update_yara_rules tool to retry"

# Install sasquatch for non-standard SquashFS (vendor-modified firmware).
# Uses the onekey-sec fork (maintained by the unblob team) which handles
# vendor-modified SquashFS variants from Rockchip, Broadcom, etc.
# Also provides sasquatch-v4be for big-endian SquashFS v4 images.
RUN git clone --depth 1 https://github.com/onekey-sec/sasquatch.git /tmp/sasquatch \
    && cd /tmp/sasquatch/squashfs-tools \
    && make -j$(nproc) \
    && make install \
    && ln -sf /usr/local/bin/sasquatch /usr/local/bin/sasquatch-v4be \
    && rm -rf /tmp/sasquatch \
    && sasquatch -version 2>&1 | head -1

# Build jtang613/qnx_dumpers/ifsdump for QNX IFS extraction (Phase 2 handler 5).
# Pinned to jtang613/qnx_dumpers@c621029e3495f3881407d6487735d44155c75f98 per
# Rule #19 evidence-first license check (MIT per source-file headers; see
# .planning/knowledge/qnx-ifs-extraction-research-2026-05-07.md). Other QNX
# extractors (askac/dumpifs, ttepatti/dumpifs-linux, ReverseEngDotDev/dump_hbcifs)
# carry the proprietary $QNXLicenseC$ header verbatim and CANNOT be bundled in
# a public container image. build-essential + zlib1g-dev + liblzo2-dev are
# already installed in the base apt block above; only libucl-dev is added here.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libucl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && git clone https://github.com/jtang613/qnx_dumpers.git /tmp/qnx_dumpers \
    && cd /tmp/qnx_dumpers \
    && git checkout c621029e3495f3881407d6487735d44155c75f98 \
    && make ifsdump \
    && install -D -m 755 ifsdump /usr/local/bin/ifsdump \
    && rm -rf /tmp/qnx_dumpers \
    && /usr/local/bin/ifsdump -h 2>&1 | head -1 \
    || echo "WARN: ifsdump build failed — QNX IFS extraction handler will soft-fail to no_handler"

# Install OpenJDK 21 for Ghidra + Android firmware extraction tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk-headless \
    android-sdk-libsparse-utils \
    erofs-utils \
    python3-protobuf \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra
ARG GHIDRA_VERSION=11.3.1
ARG GHIDRA_DATE=20250219
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
        -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm /tmp/ghidra.zip

# On ARM64: build native decompiler from Ghidra source (official release
# only ships linux_x86_64 natives — no linux_arm_64). The decompiler is a
# C++ binary invoked by the Java frontend for decompilation.
# On x86_64: skip (pre-built binaries are included in the release ZIP).
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        echo "ARM64 detected — building Ghidra native decompiler from source..." && \
        apt-get update && apt-get install -y --no-install-recommends bison flex binutils-dev && \
        git clone --depth 1 --branch Ghidra_${GHIDRA_VERSION}_build \
            https://github.com/NationalSecurityAgency/ghidra /tmp/ghidra-src && \
        cd /tmp/ghidra-src/Ghidra/Features/Decompiler/src/decompile/cpp && \
        sed -i 's/-m32//g' Makefile && \
        make decomp_opt -j$(nproc) ARCH_FLAGS= && \
        mkdir -p /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64 && \
        cp decomp_opt /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/decompile && \
        chmod +x /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/decompile && \
        cd /tmp/ghidra-src/Ghidra/Features/Decompiler/src/decompile/cpp && \
        make sleigh_opt -j$(nproc) ARCH_FLAGS= && \
        cp sleigh_opt /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/sleighc && \
        chmod +x /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/sleighc && \
        rm -rf /tmp/ghidra-src && \
        apt-get purge -y bison flex && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* && \
        echo "Ghidra ARM64 natives built successfully"; \
    else \
        echo "x86_64 detected — using pre-built Ghidra natives"; \
    fi

# Install JADX for Android APK/DEX decompilation (uses JDK 21 installed above)
ARG JADX_VERSION=1.5.1
RUN curl -sSfL "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
        -o /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && chmod +x /opt/jadx/bin/jadx /opt/jadx/bin/jadx-gui \
    && rm /tmp/jadx.zip \
    && /opt/jadx/bin/jadx --version

# Install Grype for local vulnerability scanning (multi-arch)
ARG GRYPE_VERSION=0.87.0
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then GOARCH=amd64; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then GOARCH=arm64; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    curl -sSfL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${GOARCH}.tar.gz" \
        | tar xz -C /usr/local/bin grype && \
    chmod +x /usr/local/bin/grype

# Install Syft for SBOM generation (multi-arch)
ARG SYFT_VERSION=1.41.2
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then GOARCH=amd64; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then GOARCH=arm64; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    curl -sSfL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${GOARCH}.tar.gz" \
        | tar xz -C /usr/local/bin syft && \
    chmod +x /usr/local/bin/syft

# Install TruffleHog for deep secrets scanning (optional, enhances security audit)
ARG TRUFFLEHOG_VERSION=3.94.2
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then GOARCH=amd64; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then GOARCH=arm64; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    curl -sSfL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${GOARCH}.tar.gz" \
        | tar xz -C /usr/local/bin trufflehog && \
    chmod +x /usr/local/bin/trufflehog || echo "WARN: trufflehog install failed"

# Install Nosey Parker for high-performance secrets scanning (optional, enhances security audit)
ARG NOSEYPARKER_VERSION=0.24.0
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then NPARCH=x86_64; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then NPARCH=aarch64; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    curl -sSfL "https://github.com/praetorian-inc/noseyparker/releases/download/v${NOSEYPARKER_VERSION}/noseyparker-v${NOSEYPARKER_VERSION}-${NPARCH}-unknown-linux-gnu.tar.gz" \
        | tar xz -C /usr/local ./bin/noseyparker && \
    chmod +x /usr/local/bin/noseyparker || echo "WARN: noseyparker install failed"

# Copy pre-built UEFIExtract + UEFIFind from builder stage (no cmake/qt6 in final image)
COPY --from=uefi-builder /out-uefiextract /usr/local/bin/UEFIExtract
COPY --from=uefi-builder /out-uefifind /usr/local/bin/UEFIFind

# Install payload-dumper-go for A/B OTA extraction (multi-arch)
ARG PAYLOAD_DUMPER_VERSION=1.3.0
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then GOARCH=amd64; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then GOARCH=arm64; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    curl -sSfL "https://github.com/ssut/payload-dumper-go/releases/download/${PAYLOAD_DUMPER_VERSION}/payload-dumper-go_${PAYLOAD_DUMPER_VERSION}_linux_${GOARCH}.tar.gz" \
        | tar xz -C /usr/local/bin payload-dumper-go && \
    chmod +x /usr/local/bin/payload-dumper-go || echo "WARN: payload-dumper-go install failed"

# Install flare-capa for binary capability detection (crypto, network, anti-analysis, etc.)
# Installed separately from app dependencies because capa has a large dependency tree.
RUN pip3 install --no-cache-dir --break-system-packages flare-capa \
    || echo "WARN: flare-capa install failed — detect_capabilities tool won't work"

# Install cpu_rec for raw binary architecture detection (Airbus tool, 70+ architectures).
# cpu_rec is a standalone script + corpus — not on PyPI, installed from GitHub.
RUN git clone --depth 1 https://github.com/airbus-seclab/cpu_rec.git /opt/cpu_rec \
    && cd /opt/cpu_rec \
    && for f in cpu_rec_corpus/*.xz; do unxz "$f" 2>/dev/null || true; done \
    && rm -rf /opt/cpu_rec/.git \
    && echo "cpu_rec installed at /opt/cpu_rec" \
    || echo "WARN: cpu_rec install failed — raw binary architecture detection won't work"

# Install Qiling Framework rootfs templates for PE/Mach-O emulation.
# Qiling is a Python binary emulation framework that can run Windows PE and macOS
# Mach-O binaries without QEMU. The rootfs provides minimal OS file structures.
# NOTE: Windows DLLs are NOT included due to licensing — users must provide their own
# by mounting a volume at /opt/qiling-rootfs/x86_windows/Windows/System32/ etc.
RUN git clone --depth 1 https://github.com/qilingframework/rootfs.git /opt/qiling-rootfs \
    && rm -rf /opt/qiling-rootfs/.git \
    && echo "Qiling rootfs installed at /opt/qiling-rootfs" \
    || echo "WARN: Qiling rootfs download failed — PE/Mach-O emulation won't work"

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Create non-root user and add to docker group for emulation container management.
# The docker socket GID from the host is passed via build arg (default 999).
ARG DOCKER_GID=999
RUN groupadd -g ${DOCKER_GID} docker || true \
    && useradd -m -s /bin/bash wairz \
    && usermod -aG docker wairz

# Set up working directory
WORKDIR /app

# Copy dependency files first for caching
COPY pyproject.toml uv.lock* ./

# Force venv to use Python 3.12 from the base image — NOT the system
# python3.13 from Debian packages (needed for Qiling C extension compat).
ARG VENV_CACHE_BUST=2
RUN rm -rf .venv \
    && uv venv --python /usr/local/bin/python3.12 .venv \
    && uv sync --no-dev --no-editable 2>/dev/null \
    || uv sync --no-editable
# Install setuptools<70 into venv for pkg_resources (needed by semgrep's
# opentelemetry dependency chain). uv venvs don't include setuptools by
# default. Must use <70 because setuptools 70+ removed pkg_resources as
# a bundled module.
RUN .venv/bin/python -m ensurepip --default-pip 2>/dev/null; \
    .venv/bin/python -m pip install --no-cache-dir "setuptools<70" 2>/dev/null \
    || echo "WARN: setuptools install failed — SAST scanning may not work"

# Install Qiling system-wide (separate from uv venv to avoid dep conflicts).
# keystone-engine needs source build on ARM64. Qiling runs via subprocess
# using system Python, so no conflict with the venv's packages.
RUN pip3 install --no-cache-dir --break-system-packages \
        --no-binary :all: keystone-engine \
    && pip3 install --no-cache-dir --break-system-packages qiling \
    || echo "WARN: Qiling install failed — PE/Mach-O emulation won't work"

# Copy application code
COPY . .

# Bake in default emulation kernels so they're available out of the box.
# The docker-compose bind mount (./emulation/kernels:/opt/kernels) overlays
# on top at runtime, allowing users to add custom kernels.
COPY --from=kernels . /opt/kernels/

# Create data and Ghidra project directories
RUN mkdir -p /data/firmware /tmp/ghidra_projects \
    && chown -R wairz:wairz /data /app /tmp/ghidra_projects /opt/ghidra /opt/jadx /opt/kernels \
    && ([ -d /opt/qiling-rootfs ] && chown -R wairz:wairz /opt/qiling-rootfs || true) \
    && ([ -d /opt/cpu_rec ] && chown -R wairz:wairz /opt/cpu_rec || true)

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

EXPOSE 8000

# Trade-off: no `USER wairz` directive at image level. PID 1 (entrypoint.sh) runs
# as root for ONE specific reason — `groupmod -g <host-sock-gid> docker` +
# `usermod -aG docker wairz` to align the in-container `docker` group with the
# host's Docker socket GID, which is unknown at build time and varies across
# hosts. Both calls require CAP_CHOWN/CAP_FOWNER and root-owned /etc/group, so
# they cannot be performed as the `wairz` user.
#
# After the GID fix-up the entrypoint does `exec su -s /bin/sh wairz -c '...'`,
# REPLACING PID 1 with the unprivileged python uvicorn process — no shell
# remains as root once exec returns. See entrypoint.sh:1-22 for the full flow,
# and audit-2026-05-04 finding F-H-01 for the threat-model analysis.
#
# Possible future paths (out of scope for the audit-quick-wins close-out):
#   1. Move the GID fix-up to a separate one-shot privileged init container
#      (analogous to migrator) that chowns the docker.sock to a known UID and
#      exits, leaving backend+worker to run as wairz from the start.
#   2. Pin DOCKER_GID at compose time and rebuild on host change — already the
#      build-arg path, but the runtime fix-up exists for hosts where rebuild
#      isn't ergonomic (CI image used on multiple devs' boxes).
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
