"""REST endpoint for the firmware component dependency graph."""

import asyncio

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.routers.deps import resolve_firmware as _resolve_firmware
from app.schemas.component_map import (
    ComponentEdgeResponse,
    ComponentGraphResponse,
    ComponentNodeResponse,
)
from app.services import _cache
from app.services.component_map_service import ComponentMapService

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/component-map",
    tags=["component-map"],
)


@router.get("", response_model=ComponentGraphResponse)
async def get_component_map(
    firmware=Depends(_resolve_firmware),
    db: AsyncSession = Depends(get_db),
):
    """Build and return the firmware component dependency graph.

    The result is cached per firmware — first call may take 10-25 seconds
    while subsequent calls return instantly.
    """
    # Check cache first (firmware-wide entry; binary_sha256 IS NULL)
    cached = await _cache.get_cached(
        db, firmware.id, "component_map",
    )

    if cached:
        return ComponentGraphResponse(
            nodes=[ComponentNodeResponse(**n) for n in cached["nodes"]],
            edges=[ComponentEdgeResponse(**e) for e in cached["edges"]],
            node_count=len(cached["nodes"]),
            edge_count=len(cached["edges"]),
            truncated=cached.get("truncated", False),
        )

    # Build graph (CPU-bound, run in thread) — Phase 3b: multi-root
    from app.services.firmware_paths import get_detection_roots

    roots = await get_detection_roots(firmware, db=db)
    extra = [r for r in roots if r and r != firmware.extracted_path]
    service = ComponentMapService(
        firmware.extracted_path, extra_roots=extra or None,
    )
    loop = asyncio.get_running_loop()
    try:
        graph = await loop.run_in_executor(None, service.build_graph)
    except Exception as e:
        raise HTTPException(500, f"Failed to build component map: {e}")

    # Serialize for cache and response
    nodes_data = [
        {"id": n.id, "label": n.label, "type": n.type, "path": n.path, "size": n.size, "metadata": n.metadata}
        for n in graph.nodes
    ]
    edges_data = [
        {"source": e.source, "target": e.target, "type": e.type, "details": e.details}
        for e in graph.edges
    ]

    # Store in cache (only if we found components — avoid caching empty results)
    if nodes_data:
        await _cache.store_cached(
            db,
            firmware.id,
            "component_map",
            {"nodes": nodes_data, "edges": edges_data, "truncated": graph.truncated},
        )

    return ComponentGraphResponse(
        nodes=[ComponentNodeResponse(**n) for n in nodes_data],
        edges=[ComponentEdgeResponse(**e) for e in edges_data],
        node_count=len(nodes_data),
        edge_count=len(edges_data),
        truncated=graph.truncated,
    )
