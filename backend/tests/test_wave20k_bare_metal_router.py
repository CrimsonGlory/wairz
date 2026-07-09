"""Wave 20k: bare_metal router full validation tree residual."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request


def _make_request() -> Request:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/v1/projects/x/firmware/y/bare-metal-hint",
        "raw_path": b"/api/v1/projects/x/firmware/y/bare-metal-hint",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 123),
        "server": ("test", 80),
    }
    return Request(scope)


@pytest.mark.asyncio
async def test_push_bare_metal_hint_all_branches():
    from app.routers import bare_metal as bm
    from app.services.hardware_firmware.chip_catalog import get_chip_catalog
    from starlette.responses import Response

    catalog = get_chip_catalog()
    family = "ti/tms320f28066"
    assert family in catalog
    domain = catalog[family].domains[0].name

    pid = uuid.uuid4()
    fid = uuid.uuid4()
    db = AsyncMock()
    request = _make_request()

    # Bypass slowapi rate limit decorator if present
    # Call underlying function if wrapped
    handler = bm.push_bare_metal_hint
    if hasattr(handler, "__wrapped__"):
        handler = handler.__wrapped__

    async def call(body, response=None, **extra):
        resp = response or Response()
        return await handler(
            request=request,
            response=resp,
            project_id=pid,
            firmware_id=fid,
            body=body,
            db=db,
            **extra,
        )

    # --- 404 project ---
    db.get = AsyncMock(return_value=None)
    body = bm.BareMetalHintRequest(chip_family_hint=family, domain_hint=domain)
    with pytest.raises(HTTPException) as ei:
        await call(body)
    assert ei.value.status_code == 404

    # --- 404 firmware wrong project ---
    proj = SimpleNamespace(id=pid)
    fw_wrong = SimpleNamespace(id=fid, project_id=uuid.uuid4())

    async def get1(model, id_):
        name = getattr(model, "__name__", "")
        if name == "Project":
            return proj
        return fw_wrong

    db.get = AsyncMock(side_effect=get1)
    with pytest.raises(HTTPException) as ei:
        await call(body)
    assert ei.value.status_code == 404

    # --- 422 unknown family ---
    fw_ok = SimpleNamespace(id=fid, project_id=pid)

    async def get2(model, id_):
        name = getattr(model, "__name__", "")
        if name == "Project":
            return proj
        return fw_ok

    db.get = AsyncMock(side_effect=get2)
    body_bad = bm.BareMetalHintRequest(chip_family_hint="zz/not_in_catalog")
    with pytest.raises(HTTPException) as ei:
        await call(body_bad)
    assert ei.value.status_code == 422

    # --- 422 bad domain ---
    body_bad_dom = bm.BareMetalHintRequest(
        chip_family_hint=family, domain_hint="no_such_domain"
    )
    with pytest.raises(HTTPException) as ei:
        await call(body_bad_dom)
    assert ei.value.status_code == 422

    # --- happy create (no prior rows) ---
    empty_scalars = MagicMock()
    empty_scalars.scalars = MagicMock(return_value=[])
    db.execute = AsyncMock(return_value=empty_scalars)
    db.add = MagicMock()
    db.commit = AsyncMock()

    async def refresh(obj):
        obj.id = uuid.uuid4()
        obj.received_at = datetime.now(timezone.utc)
        obj.descriptor_hash = getattr(obj, "descriptor_hash", "abc")

    db.refresh = AsyncMock(side_effect=refresh)
    body_ok = bm.BareMetalHintRequest(
        chip_family_hint=family,
        domain_hint=None,
        ingestor_id="test-ingestor",
        evidence={"note": "x"},
    )
    resp = Response()
    out = await call(body_ok, response=resp)
    assert out is not None
    assert db.add.called

    # --- idempotent replay (same hash) ---
    created = db.add.call_args[0][0]
    prior = SimpleNamespace(
        id=uuid.uuid4(),
        descriptor_hash=created.descriptor_hash,
        received_at=datetime.now(timezone.utc),
    )
    prior_scalars = MagicMock()
    prior_scalars.scalars = MagicMock(return_value=[prior])
    db.execute = AsyncMock(return_value=prior_scalars)
    resp2 = Response()
    out2 = await call(body_ok, response=resp2)
    assert resp2.status_code == 200
    assert out2.status == "idempotent_replay"

    # --- 409 conflict (different hash) ---
    conflict_prior = SimpleNamespace(
        id=uuid.uuid4(),
        descriptor_hash="different_hash_value_xxx",
        received_at=datetime.now(timezone.utc),
    )
    conflict_scalars = MagicMock()
    conflict_scalars.scalars = MagicMock(return_value=[conflict_prior])
    db.execute = AsyncMock(return_value=conflict_scalars)
    with pytest.raises(HTTPException) as ei:
        await call(body_ok, response=Response())
    assert ei.value.status_code == 409
