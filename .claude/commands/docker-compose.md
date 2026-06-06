# Docker Compose — dev file discipline

Every `docker compose` command in this project **must** include both compose files:

```
docker compose -f docker-compose.yml -f docker-compose.dev.yml <subcommand>
```

## Why

`docker-compose.dev.yml` bind-mounts the source tree into running containers:

| Mount | Container |
|---|---|
| `./backend/app` → `/app/app` | backend, worker |
| `./frontend/src` → `/app/src` | frontend |

Without these mounts, code changes are invisible to the running process until
the image is fully rebuilt and the container recreated (minutes, not seconds).
Omitting `-f docker-compose.dev.yml` also means any newly created container
(e.g. after `up --build`) lacks the bind mounts entirely, so live editing stops
working silently.

## Examples

```bash
# Rebuild and recreate backend + worker + migrator
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build backend worker migrator

# Restart a service (picks up env-var changes without a rebuild)
docker compose -f docker-compose.yml -f docker-compose.dev.yml restart backend

# Tail logs
docker compose -f docker-compose.yml -f docker-compose.dev.yml logs -f backend

# Run a one-off command inside a container
docker compose -f docker-compose.yml -f docker-compose.dev.yml exec backend /app/.venv/bin/python -c "..."

# Bring everything down
docker compose -f docker-compose.yml -f docker-compose.dev.yml down
```

## Never do

```bash
# Missing -f flags — container recreated without bind mounts
docker compose up -d --build backend
docker compose restart backend
docker compose down
```
