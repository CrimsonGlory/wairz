"""SSE endpoint for real-time project event streaming.

Clients connect to GET /api/v1/projects/{project_id}/events and receive
a text/event-stream of JSON-encoded status updates pushed via Redis pub/sub.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse

from app.rate_limit import limiter
from app.services.event_service import event_service

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/events",
    tags=["events"],
)

# Event types that clients can subscribe to
VALID_EVENT_TYPES = {"unpacking", "emulation", "fuzzing", "device", "assessment", "vulhunt"}

# Keepalive interval in seconds
KEEPALIVE_INTERVAL = 15


@router.get("")
@limiter.limit("10/minute")
async def stream_events(
    request: Request,
    project_id: uuid.UUID,
    types: str | None = Query(
        default=None,
        description="Comma-separated event types to subscribe to. "
        "Valid types: unpacking, emulation, fuzzing, device, assessment. "
        "Omit to subscribe to all.",
    ),
):
    """SSE endpoint streaming real-time project events.

    The response is a text/event-stream. Each event is formatted as:
        data: {"type": "...", "status": "...", ...}\\n\\n

    A keepalive comment `:ping\\n\\n` is sent every 15 seconds to prevent
    proxy/browser timeouts.
    """
    # Parse requested event types
    if types:
        requested = {t.strip() for t in types.split(",") if t.strip()}
        # Filter to valid types only
        event_types = requested & VALID_EVENT_TYPES
        if not event_types:
            event_types = VALID_EVENT_TYPES
    else:
        event_types = VALID_EVENT_TYPES

    # Build channel list
    project_str = str(project_id)
    channels = [
        event_service.channel_name(project_str, et)
        for et in sorted(event_types)
    ]

    async def event_generator():
        """Yield SSE-formatted events from Redis pub/sub with keepalive."""
        pubsub = event_service.redis.pubsub()
        try:
            await pubsub.subscribe(*channels)
            logger.info(
                "SSE client connected: project=%s types=%s",
                project_id,
                sorted(event_types),
            )

            while True:
                # Check if client disconnected
                if await request.is_disconnected():
                    break

                # Poll for a message with a timeout for keepalive
                raw_message = await asyncio.wait_for(
                    _get_message(pubsub),
                    timeout=KEEPALIVE_INTERVAL,
                )

                if raw_message is None:
                    # Timeout — send keepalive
                    yield ":ping\n\n"
                    continue

                if raw_message["type"] != "message":
                    continue

                try:
                    data = json.loads(raw_message["data"])
                    yield f"data: {json.dumps(data)}\n\n"
                except (json.JSONDecodeError, TypeError):
                    logger.warning(
                        "Non-JSON on %s: %s",
                        raw_message.get("channel"),
                        str(raw_message.get("data", ""))[:200],
                    )

        except asyncio.CancelledError:
            pass
        except Exception:
            logger.debug("SSE stream ended", exc_info=True)
        finally:
            await pubsub.unsubscribe(*channels)
            await pubsub.aclose()
            logger.info("SSE client disconnected: project=%s", project_id)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


async def _get_message(pubsub) -> dict | None:
    """Get a single message from pubsub, returning None on timeout.

    Wraps the async get_message with ignore_subscribe_messages so we
    only surface real data messages.
    """
    try:
        msg = await pubsub.get_message(
            ignore_subscribe_messages=True,
            timeout=KEEPALIVE_INTERVAL,
        )
        return msg
    except TimeoutError:
        return None
