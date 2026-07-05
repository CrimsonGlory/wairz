import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.database import Base
from app.models import *  # noqa: F401, F403 - ensure all models are imported

config = context.config
if config.config_file_name is not None:
    # disable_existing_loggers=False (fileConfig's default is True) — alembic
    # is invoked in-process by test_alembic_autogenerate_empty.py (via
    # alembic.command.check) inside the same pytest process as every other
    # test. fileConfig's default silently sets `.disabled = True` on every
    # logger that already exists but isn't named in alembic.ini's [loggers]
    # section (only root/sqlalchemy/alembic are listed) — permanently
    # muting every `app.*` logger for the rest of the process and breaking
    # every subsequent test's `caplog` assertions on app-level WARN/ERROR
    # logs. Harmless for the CLI-invoked case (migrator container running
    # `alembic upgrade head` in its own dedicated process).
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Override sqlalchemy.url from DATABASE_URL env var if set (e.g., in Docker).
# This avoids hardcoding the hostname in alembic.ini (localhost vs postgres).
db_url = os.environ.get("DATABASE_URL")
if db_url:
    config.set_main_option("sqlalchemy.url", db_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
