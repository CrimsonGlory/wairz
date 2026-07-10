from functools import lru_cache
from pathlib import Path
from typing import Literal

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
    max_upload_size_mb: int = 500
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
    ghidra_background_analysis_timeout: int = 3600
    ghidra_background_decompile_timeout: int = 1800
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
    log_level: str = "INFO"

    # Host/origin guard (app/main.py). Comma-separated extra entries. Empty =
    # the built-in localhost set plus any private-network (RFC1918/loopback/
    # link-local) address — so running Wairz on a LAN server and reaching it by
    # IP works out of the box. "*" disables the corresponding check entirely —
    # appropriate when the API sits behind an authenticating proxy
    # (ALB/CloudFront + Cognito) where Host varies.
    allowed_hosts: str = ""
    allowed_origins: str = ""
    # Auto-accept Host/Origin values whose host is a private-network IP
    # (RFC1918, loopback, link-local) without listing each one in allowed_*.
    # Default True restores the pre-hardening LAN-access behavior. Set False on
    # a public-facing single-host deploy to keep only the explicit allowlist
    # (tightest DNS-rebinding posture); a proxy deploy uses "*" instead.
    guard_trust_private_network: bool = True

    # --- Compute backend (enterprise cloud deploy) ---------------------------
    # Where heavy Ghidra jobs run. "local" (default) spawns detached worker
    # subprocesses on the backend host — the standard docker-compose behavior,
    # unchanged. "aws_batch" submits the same worker as an AWS Batch job
    # (enterprise/PLAN.md, Phase 2). Defaults keep the local deploy identical.
    compute_backend: Literal["local", "aws_batch"] = "local"
    aws_region: str = ""
    batch_job_queue: str = ""
    batch_job_definition: str = ""
    # Max in-flight Batch jobs per firmware (aws_batch mode). Shared-instance
    # fairness guardrail: bounds a runaway agent looping start_binary_analysis /
    # start_function_decompile so one analyst's firmware can't saturate the queue
    # under batch_max_vcpus. A firmware belongs to one project/analyst, so this is
    # the per-project/per-user cap realized on the one identity available at every
    # dispatch site (per-user proper needs the deferred ALB-Cognito identity). 0
    # disables the cap. No effect in local mode.
    batch_max_jobs_per_firmware: int = 8
    # TTL (seconds) for the distributed analysis lock used when compute_backend
    # != "local" (no shared filesystem for flock). Auto-renewed while held, so
    # this only bounds how long a crashed holder blocks others.
    redis_lock_ttl_seconds: int = 120
    # Idle timeout for the cloud "reuse worker" (C8). It stays warm while reuse
    # requests keep arriving and exits after this long with an empty queue.
    re_worker_idle_ttl_minutes: int = 20

    # --- Auth (OIDC / JWT bearer) ------------------------------------------
    # Enforce bearer-token auth on the HTTP API. Default off keeps the local
    # docker-compose deploy open and unauthenticated. When on, every request
    # (outside the allowlist) needs a valid OIDC access token; the SPA obtains
    # one via the Cognito hosted-UI login. IdP-agnostic: point oidc_issuer at
    # the deployment's Cognito pool, or any OIDC issuer — so an operator can
    # federate JumpCloud/Okta into Cognito (or use them directly) without a
    # code change. Does not affect the MCP server (it calls services directly).
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
