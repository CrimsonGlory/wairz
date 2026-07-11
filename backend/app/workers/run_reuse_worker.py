"""Long-lived Ghidra "reuse worker" for the cloud (enterprise) deployment.

The small Fargate backend must not run Ghidra. Instead, query-script runs
(decompile / string-refs / stack & global layout / dataflow) are pushed onto a
Redis queue; this worker — a Batch job on an EFS-mounted instance — drains the
queue, runs each script against the shared persistent Ghidra project via
-process (no re-analysis), and returns the output on a per-request result list.

It stays warm while work keeps arriving (the blocking pop resets the idle clock)
and exits after --idle-ttl seconds with an empty queue, so it scales back to
zero. See enterprise/PLAN.md §3.2 (C8).

Invocation (submitted by BatchDispatcher.dispatch_reuse_worker):
    python -m app.workers.run_reuse_worker --idle-ttl 1200
"""

import argparse
import asyncio
import json
import logging
import sys
import time

from app.config import get_settings
from app.services.ghidra_service import (
    _REUSE_QUEUE,
    _REUSE_RESULT_PREFIX,
    _REUSE_RESULT_TTL,
    _REUSE_WORKER_HB,
    _run_ghidra_local,
)

logger = logging.getLogger(__name__)

# How long the heartbeat key lives, and how often we wake to refresh it / check
# idle. HB_TTL must exceed POP_TIMEOUT so the key never lapses while we work.
_POP_TIMEOUT = 10
_HB_TTL = 30


async def _run(idle_ttl: int) -> int:
    import redis.asyncio as aioredis

    # socket_timeout must exceed the BLPOP server-side timeout, or the client's
    # read times out while the (empty-queue) BLPOP is still legitimately blocking.
    client = aioredis.from_url(
        get_settings().redis_url,
        socket_timeout=_POP_TIMEOUT + 15,
        socket_keepalive=True,
    )
    logger.info("Reuse worker up (idle_ttl=%ds)", idle_ttl)
    last_work = time.time()
    try:
        while True:
            await client.set(_REUSE_WORKER_HB, "1", ex=_HB_TTL)
            popped = await client.blpop([_REUSE_QUEUE], timeout=_POP_TIMEOUT)
            if popped is None:
                if time.time() - last_work >= idle_ttl:
                    logger.info("Idle for %ds — exiting.", idle_ttl)
                    return 0
                continue

            last_work = time.time()
            _, raw = popped
            req = json.loads(raw)
            result_key = f"{_REUSE_RESULT_PREFIX}{req['id']}"
            try:
                output = await _run_ghidra_local(
                    req["binary_path"],
                    req["script_name"],
                    req.get("script_args"),
                    int(req["timeout"]),
                    req["binary_sha256"],
                )
                result = {"ok": True, "output": output}
            except Exception as exc:  # noqa: BLE001 — report any failure to caller
                logger.exception("Reuse run failed for %s", req.get("script_name"))
                result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

            # Hand the result back and let it expire if the caller gave up.
            await client.rpush(result_key, json.dumps(result))
            await client.expire(result_key, _REUSE_RESULT_TTL)
    finally:
        await client.delete(_REUSE_WORKER_HB)
        await client.aclose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--idle-ttl", type=int, default=1200)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    sys.exit(asyncio.run(_run(args.idle_ttl)))


if __name__ == "__main__":
    main()
