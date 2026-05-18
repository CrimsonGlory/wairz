from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings


class Base(DeclarativeBase):
    pass


engine = create_async_engine(
    get_settings().database_url,
    echo=False,
    # pool_size + max_overflow = 40 (raised from 30 on 2026-05-18).
    # Derivation: TIER_A_LIGHT_ACK at 30/hour permits a 30-scan burst within
    # any 1-hour rolling window. Each background scan (vuln-scan, SBOM
    # generate, authenticode chain) opens one AsyncSession via
    # async_session_factory(). If 30 acks land within the same minute, all
    # 30 sessions are in-flight simultaneously — at 30+0=30 pool capacity,
    # any concurrent GET /sbom/vulnerabilities/scan/status poll from the
    # frontend would queue at QueuePool and (eventually) timeout. Bumping
    # to 15+25=40 leaves 10 connections of headroom for polling endpoints
    # + frontend traffic during a worst-case burst. Postgres default
    # max_connections is 100; backend+worker+pg-backup together stay well
    # under that ceiling. Scout 2 (2026-05-18 audit of f6dbc7b) flagged
    # the prior 30-cap as the actual breaking point of the new tier.
    pool_size=15,
    max_overflow=25,
    pool_recycle=3600,
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
