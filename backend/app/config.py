from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"), env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "postgresql+asyncpg://wairz:wairz@localhost:5432/wairz"
    redis_url: str = "redis://localhost:6379/0"
    storage_root: str = "/data/firmware"
    max_upload_size_mb: int = 2048
    max_tool_output_kb: int = 30
    max_tool_iterations: int = 25
    ghidra_path: str = "/opt/ghidra"
    ghidra_scripts_path: str = "/opt/ghidra_scripts"
    # Persistent Ghidra project store. A binary is imported + auto-analyzed once
    # into <ghidra_project_root>/<ghidra_version>/<sha256>/ and kept; subsequent
    # scripts reuse it via -process (no re-analysis), so analysis done once is
    # shared across sessions/agents/users. Back this with a durable volume.
    ghidra_project_root: str = "/data/ghidra_projects"
    # Project-store GC: evict least-recently-used projects once the store
    # exceeds this many projects (0 disables GC). Keyed by access time.
    ghidra_project_cache_max: int = 200
    ghidra_timeout: int = 300
    # Persistent Ghidra project store for GZF process-mode (run_ghidra_headless
    # use_saved_project=True).  Projects are keyed by GZF content SHA256 so the
    # same archive always maps to the same directory.  Defaults to /var/wairz
    # inside the container; override to a host bind-mount for persistence across
    # container restarts.
    ghidra_projects_dir: str = "/var/wairz/ghidra_projects"
    ghidra_background_analysis_timeout: int = 3600
    ghidra_background_decompile_timeout: int = 1800
    jadx_path: str = "/opt/jadx/bin/jadx"
    jadx_timeout: int = 300
    jadx_max_memory: str = "4g"
    jadx_threads: int = 4
    nvd_api_key: str = ""
    emulation_timeout_minutes: int = 30
    emulation_max_sessions: int = 3
    emulation_memory_limit_mb: int = 1024
    emulation_cpu_limit: float = 1.0
    emulation_image: str = "wairz-emulation"
    emulation_kernel_dir: str = "/opt/kernels"
    emulation_network: str = "wairz_emulation_net"
    fuzzing_image: str = "wairz-fuzzing"
    fuzzing_timeout_minutes: int = 120
    fuzzing_max_campaigns: int = 1
    fuzzing_memory_limit_mb: int = 2048
    fuzzing_cpu_limit: float = 2.0
    fuzzing_data_dir: str = "/data/fuzzing"
    system_emulation_image: str = "wairz-system-emulation"
    system_emulation_pipeline_timeout: int = 1800  # 30 min (cross-arch on RPi is slow)
    system_emulation_idle_timeout: int = 1800  # 30 min
    system_emulation_ram_limit: str = "2g"
    system_emulation_cpu_limit: int = 2
    carving_image: str = "wairz-carving"
    carving_memory_limit_mb: int = 1024
    carving_cpu_limit: float = 1.0
    carving_default_timeout: int = 60
    carving_max_timeout: int = 600
    # Harness-build sandbox (cross-compiles fuzzing harnesses vs firmware .so).
    harness_build_image: str = "wairz-harness-build"
    harness_build_memory_limit_mb: int = 2048
    harness_build_cpu_limit: float = 2.0
    harness_build_timeout: int = 180
    uart_bridge_host: str = "host.docker.internal"
    uart_bridge_port: int = 9999
    uart_command_timeout: int = 30
    device_bridge_host: str = "host.docker.internal"
    device_bridge_port: int = 9998
    cors_origins: str = ""
    # Comma-separated extra hostnames (with optional port) to allow beyond the
    # built-in localhost/127.0.0.1 set.  Example: "daas-dev.lab:1234,wairz.internal"
    extra_allowed_hosts: str = ""
    syft_enabled: bool = True
    syft_timeout: int = 120
    vulnerability_backend: str = "grype"  # "grype" or "nvd"
    grype_db_cache_dir: str = "/data/grype-db"
    grype_timeout: int = 120
    kernel_vulns_git_url: str = "https://git.kernel.org/pub/scm/linux/security/vulns.git"
    kernel_vulns_cache_dir: str = "/data/kernel-vulns"
    kernel_vulns_sync_timeout: int = 600
    max_extraction_size_mb: int = 10240
    max_extraction_files: int = 500000
    max_compression_ratio: int = 200
    # Max firmware size for the "standalone binary" fallback path.  When all
    # extractors (unblob, binwalk3) fail to produce a filesystem root, firmware
    # at or under this size is COPIED into extraction_dir as a single-file
    # target so users can analyse it as a raw binary (bootloaders, bare-metal
    # medical / automotive / IoT images, ROM dumps).  Past this size, the
    # extraction fails cleanly with a readable error.  Tune up for
    # deployments that ingest large raw firmware; cost is ~input_size extra
    # disk per failed-extraction.  Original hardcoded limit was 10 MB, which
    # excluded most real-world bare-metal firmware.
    max_standalone_binary_mb: int = 512
    dependency_track_url: str = ""
    dependency_track_api_key: str = ""
    vulhunt_url: str = "http://vulhunt:8080"
    vulhunt_timeout: int = 300
    cwe_checker_image: str = "ghcr.io/fkie-cad/cwe_checker:stable"
    cwe_checker_timeout: int = 600
    cwe_checker_memory_limit: str = "4g"
    yara_forge_dir: str = "/data/yara-forge"
    docker_host: str = "tcp://docker-proxy:2375"
    clamav_host: str = "clamav"
    clamav_port: int = 3310
    clamav_enabled: bool = True
    virustotal_api_key: str = ""
    abusech_auth_key: str = ""
    api_key: str | None = None
    # Accept both ALLOW_NO_AUTH and WAIRZ_ALLOW_NO_AUTH (the documented name).
    # Default flipped from False → True 2026-05-21 per operator direction
    # (backlog `auth-gate-removal-2026-05-21`). The lifespan refuse-to-start
    # gate at app/main.py was redundant with the asgi_auth.py middleware's
    # "Auth is disabled entirely when settings.api_key is falsy" behaviour;
    # both removed/flipped together. Operators who want multi-user
    # enforcement set API_KEY (asgi_auth.py enforces); operators who don't
    # leave it unset (middleware no-ops). The env-var override still works
    # for backward compat but is no longer required for single-operator
    # deployments.
    allow_no_auth: bool = Field(
        default=True,
        validation_alias=AliasChoices("WAIRZ_ALLOW_NO_AUTH", "ALLOW_NO_AUTH", "allow_no_auth"),
    )
    log_level: str = "INFO"

    # --- Volume / backup knobs (infra-volumes-quotas-and-backup) ---
    # Firmware retention. ``None`` = keep forever (current default). When set
    # to an integer N, ``reconcile_firmware_storage`` (daily @05:00) will
    # include N-day-old rows in its log output. Auto-delete is DISABLED in
    # v1 — the cron logs counts only and treats the warning as operator-
    # actionable signal.
    firmware_retention_days: int | None = None
    # Host path bind-mounted into the ``pg-backup`` container. Relative to
    # the docker-compose working directory (typically the repo root).
    backup_dir: str = "./backups"

    # --- analysis_cache cleanup (backend-cache-module-extraction-and-ttl) ---
    # Rows in the ``analysis_cache`` table older than this many days are
    # deleted by the ``cleanup_analysis_cache`` arq cron job. Cached Ghidra
    # decompilations and JADX dumps can be multi-megabyte in the JSONB
    # ``result`` column; without a TTL, the table grows unboundedly.
    analysis_cache_retention_days: int = 30

    # --- Auth (OIDC / JWT bearer) ------------------------------------------
    # Enforce bearer-token auth on the HTTP API. Default off keeps the local
    # docker-compose deploy open and unauthenticated. When on, every request
    # (outside the allowlist) needs a valid OIDC access token; the SPA obtains
    # one via the Cognito hosted-UI login. IdP-agnostic: point oidc_issuer at
    # the deployment's Cognito pool, or any OIDC issuer.
    # Does not affect the MCP server (it calls services directly).
    auth_enabled: bool = False
    # e.g. https://cognito-idp.<region>.amazonaws.com/<user-pool-id>
    oidc_issuer: str = ""
    # App client id; matched against the token's `aud` or (Cognito) `client_id`.
    oidc_audience: str = ""
    # Defaults to "<oidc_issuer>/.well-known/jwks.json" when blank.
    oidc_jwks_url: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
