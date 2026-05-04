---
title: "Security: Install docker-socket-proxy to Narrow Host Access"
status: completed
priority: critical
target: docker-compose.yml, backend/app/services/, backend/app/ai/tools/
completed_at: 2026-04-19
completed_in: session 69f004fe phase 1
shipped_commits:
  - bac49ea  # feat(security): narrow Docker access via socket proxy (D.1)
closed_by: wave3-stream-gamma (Rule-19 status-bump)
---

## Problem

The Docker socket is bind-mounted read-write into the backend AND worker (`docker-compose.yml:76, 129`). Every service with `docker.from_env()` holds a full-privilege Docker API client:

- `backend/app/services/emulation_service.py:50`
- `backend/app/services/fuzzing_service.py:90`
- `backend/app/services/system_emulation_service.py:43`
- `backend/app/services/cwe_checker_service.py:97`
- `backend/app/services/sysroot_service.py:158`
- `backend/app/routers/terminal.py:55, 126, 365`
- `backend/app/routers/emulation.py:676`
- `backend/app/ai/tools/emulation.py:2196, 2335`
- `backend/app/ai/tools/fuzzing.py:954`

Any RCE in the backend — including downstream consequences of issues like `security-fuzzing-shell-injection` or any parser vulnerability in a third-party tool — becomes root on the host. This is the single largest blast-radius multiplier in the codebase.

Current code is disciplined (explicit `privileged=False`, `cap_add=["SYS_ADMIN"]`, resource limits) but nothing **architecturally** prevents a future handler from passing `privileged=True` or `volumes={"/": {"bind":"/host","mode":"rw"}}`.

## Approach

**Install `tecnativa/docker-socket-proxy` as a sidecar with a narrow allowlist.**

**Step 1 — Add the proxy service to `docker-compose.yml`.**

```yaml
  docker-proxy:
    image: ghcr.io/tecnativa/docker-socket-proxy:0.3.0
    restart: unless-stopped
    environment:
      CONTAINERS: 1        # GET /containers/*
      POST: 1              # POST endpoints (gated further below)
      IMAGES: 1            # GET /images/* (readonly)
      NETWORKS: 1
      VOLUMES: 1
      EXEC: 1              # exec in containers (for fuzzing/emulation)
      # Explicit denials (defaults, but clarity)
      BUILD: 0
      COMMIT: 0
      CONFIGS: 0
      DISTRIBUTION: 0
      PLUGINS: 0
      SECRETS: 0
      SERVICES: 0
      SESSION: 0
      SWARM: 0
      SYSTEM: 0
      TASKS: 0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - internal
    deploy:
      resources:
        limits:
          memory: 128M
```

**Step 2 — Un-mount the socket from backend and worker.**

Remove `/var/run/docker.sock:/var/run/docker.sock` from backend (`docker-compose.yml:76`) and worker (`docker-compose.yml:129`).

**Step 3 — Reconfigure Docker SDK clients to use the proxy.**

Add `DOCKER_HOST=tcp://docker-proxy:2375` to the backend and worker env. The `docker.from_env()` calls will pick this up automatically.

**Step 4 — Harden container creation validation.**

Create `backend/app/utils/docker_safety.py`:

```python
ALLOWED_IMAGES = {
    "wairz-emulation",
    "wairz-fuzzing",
    "wairz-system-emulation",
    "ghcr.io/tecnativa/docker-socket-proxy:0.3.0",
    "alpine:latest",  # terminal endpoints
    # ...
}

ALLOWED_BIND_PREFIXES = (
    "/data/firmware",
    "/data/fuzzing",
    "/data/emulation",
    "/tmp/wairz-",
)

def validate_container_config(image: str, host_config: dict) -> None:
    if image not in ALLOWED_IMAGES:
        raise ValueError(f"Image not allowed: {image}")
    if host_config.get("Privileged"):
        raise ValueError("Privileged containers not allowed")
    for bind in host_config.get("Binds", []):
        host_path = bind.split(":", 1)[0]
        if not any(host_path.startswith(p) for p in ALLOWED_BIND_PREFIXES):
            raise ValueError(f"Bind path not allowed: {host_path}")
```

Wrap every `client.containers.run(...)` / `client.containers.create(...)` call to validate before creation.

**Step 5 — Per-service Docker client factory.**

Create `backend/app/utils/docker_client.py`:

```python
def get_docker_client() -> docker.DockerClient:
    """Returns a docker client that routes through the socket proxy."""
    return docker.DockerClient(base_url=os.environ.get("DOCKER_HOST", "tcp://docker-proxy:2375"))
```

Replace all `docker.from_env()` calls with this factory.

## Files

- `docker-compose.yml` (add proxy service, remove socket mounts from backend + worker, add DOCKER_HOST env)
- `backend/app/utils/docker_client.py` (new)
- `backend/app/utils/docker_safety.py` (new)
- 10+ files listed in the problem statement — migrate to factory + validation

## Acceptance Criteria

- [ ] `docker-compose config` shows `/var/run/docker.sock` only mounted into `docker-proxy` service
- [ ] `docker-compose up -d` starts all services successfully
- [ ] Existing emulation / fuzzing / terminal flows work end-to-end (E2E test coverage)
- [ ] Attempting to pass `privileged=True` in a test raises `ValueError` before Docker is called
- [ ] Attempting to pass an image outside the allowlist raises `ValueError`
- [ ] Attempting to bind-mount `/etc` raises `ValueError`

## Risks

- This is a large change touching 10+ service files — break into sub-PRs: proxy + backend only first, then migrate one service at a time
- The `EXEC: 1` permission is required for fuzzing's `container.exec_run()` — can't narrow further via the proxy; rely on the validation wrapper
- `system-emulation` currently has `privileged: true` declared directly in compose (`docker-compose.yml:184`); this change doesn't affect compose-declared services, only runtime-spawned containers
- Version pinning the proxy: 0.3.0 was stable at time of writing; verify latest before merge

## References

- Security review C4 "Notes on threat model" — this is *the* structural risk
- Infrastructure review C5 (SYS_ADMIN), C3 (socket mounted RW)
