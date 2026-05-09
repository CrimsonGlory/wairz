"""Server-Sent Events service backed by Redis pub/sub.

Provides publish/subscribe primitives for pushing real-time status
updates to frontend clients over SSE.

Channel naming convention:
    wairz:{project_id}:{event_type}

Example:
    wairz:550e8400-...:unpacking
    wairz:550e8400-...:emulation
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncGenerator

import redis.asyncio as aioredis

from app.config import get_settings

logger = logging.getLogger(__name__)


class EventService:
    """Singleton-style event bus backed by Redis pub/sub."""

    def __init__(self) -> None:
        self._redis: aioredis.Redis | None = None

    async def connect(self) -> None:
        """Create the async Redis connection from settings."""
        if self._redis is not None:
            return
        settings = get_settings()
        self._redis = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
        )
        # Verify connectivity
        await self._redis.ping()
        logger.info("EventService connected to Redis at %s", settings.redis_url)

    async def disconnect(self) -> None:
        """Close the Redis connection pool."""
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None
            logger.info("EventService disconnected from Redis")

    @property
    def redis(self) -> aioredis.Redis:
        if self._redis is None:
            raise RuntimeError("EventService not connected — call connect() first")
        return self._redis

    @staticmethod
    def channel_name(project_id: str, event_type: str) -> str:
        """Build a canonical Redis channel name."""
        return f"wairz:{project_id}:{event_type}"

    async def publish(self, channel: str, event: dict) -> int:
        """Publish a JSON event to a Redis channel.

        Returns the number of subscribers that received the message.
        """
        payload = json.dumps(event)
        count = await self.redis.publish(channel, payload)
        logger.debug("Published to %s (%d subscribers): %s", channel, count, payload[:200])
        return count

    async def publish_progress(
        self,
        project_id: str,
        event_type: str,
        *,
        status: str,
        progress: float | None = None,
        message: str = "",
        extra: dict | None = None,
    ) -> int:
        """Convenience helper for common progress-style events.

        Args:
            project_id: UUID of the project.
            event_type: One of unpacking, emulation, fuzzing, device, assessment.
            status: Current status string (e.g. "running", "completed", "error").
            progress: Optional 0.0-1.0 fraction.
            message: Human-readable status message.
            extra: Any additional fields to include.
        """
        channel = self.channel_name(project_id, event_type)
        event: dict = {
            "type": event_type,
            "status": status,
            "message": message,
        }
        if progress is not None:
            event["progress"] = progress
        if extra:
            event.update(extra)
        return await self.publish(channel, event)

    async def subscribe(
        self, *channels: str
    ) -> AsyncGenerator[dict, None]:
        """Subscribe to one or more Redis channels, yielding parsed events.

        This is an async generator that yields dicts until the caller
        breaks out of iteration (e.g. on client disconnect).
        """
        pubsub = self.redis.pubsub()
        try:
            await pubsub.subscribe(*channels)
            async for raw_message in pubsub.listen():
                if raw_message["type"] != "message":
                    continue
                try:
                    data = json.loads(raw_message["data"])
                    yield data
                except (json.JSONDecodeError, TypeError):
                    logger.warning(
                        "Non-JSON message on %s: %s",
                        raw_message.get("channel"),
                        raw_message.get("data", "")[:200],
                    )
        finally:
            await pubsub.unsubscribe(*channels)
            await pubsub.aclose()


# Module-level singleton
event_service = EventService()
