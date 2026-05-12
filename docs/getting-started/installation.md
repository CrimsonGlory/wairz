# Installation

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- [uv](https://docs.astral.sh/uv/getting-started/installation/) (for local development only)

## Docker (Recommended)

The simplest way to run Wairz is with Docker Compose:

```bash
git clone https://github.com/digitalandrew/wairz.git
cd wairz
cp .env.example .env
```

### Required `.env` edits before first boot

The backend container refuses to start unless **exactly one** of the
following is set in `.env`:

| Variable | When to use |
|---|---|
| `WAIRZ_ALLOW_NO_AUTH=true` | Local single-user development — disables REST/MCP auth for `localhost`. Recommended starting point. |
| `API_KEY=<strong-random-key>` | Production / multi-user / LAN-exposed deployments. Issue a key with `openssl rand -hex 32`. |

If neither is set, `docker compose ps` will show
`wairz-backend-1 Restarting (78)` and `docker compose logs backend`
will print:

```
ERROR: api_key is required. Set API_KEY in .env or
WAIRZ_ALLOW_NO_AUTH=true for local-only deployments.
```

Exit code 78 is `EX_CONFIG` from `/usr/include/sysexits.h` —
distinguishable from generic startup failures (exit 1).

Then start the stack:

```bash
docker compose up --build
```

This starts all services:

| Service | URL |
|---------|-----|
| Frontend | [http://localhost:3000](http://localhost:3000) |
| API docs | [http://localhost:8000/docs](http://localhost:8000/docs) |

!!! note
    The first build may take several minutes as it downloads and builds Ghidra, QEMU, and AFL++ containers.

## Local Development

For development with hot-reloading:

```bash
# Start PostgreSQL and Redis
docker compose up -d postgres redis

# Backend
cd backend
uv sync
uv run alembic upgrade head
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

Or use the helper script that starts both:

```bash
./launch.sh
```

## Updating

To update to the latest version:

```bash
git pull
docker compose up --build
```

Database migrations run automatically on container startup.

## Troubleshooting

### Port conflicts

If ports 3000 or 8000 are already in use, edit the port mappings in `docker-compose.yml`.

### Docker permissions

On Linux, you may need to add your user to the `docker` group:

```bash
sudo usermod -aG docker $USER
```

Then log out and back in.

### Build failures

If the build fails, try cleaning Docker's build cache:

```bash
docker compose down
docker system prune --filter "label=com.docker.compose.project=wairz"
docker compose up --build
```

### Backend container in restart loop

If `docker compose ps` shows `wairz-backend-1 Restarting` and the
restart count keeps climbing (`docker inspect wairz-backend-1
--format '{{.RestartCount}}'`), check the logs:

```bash
docker compose logs --tail 20 backend
```

The most common cause is the missing auth setting documented above
(exit code 78 / `EX_CONFIG`). Edit `.env` to add `WAIRZ_ALLOW_NO_AUTH=true`
or `API_KEY=<value>`, then:

```bash
docker compose up -d backend
```

The worker container does not run the same auth check and will keep
running healthy even while the backend restart-loops — so a "running"
worker is not evidence the backend is up. Always confirm backend
health with `docker compose ps` after a rebuild.
