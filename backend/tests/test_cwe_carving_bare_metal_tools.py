"""MCP handler tests for cwe_checker, carving, bare_metal tools (wave3 coverage)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.bare_metal import (
    _handle_audit_bare_metal_firmware,
    _handle_list_chip_families,
    _handle_lookup_bare_metal_findings_across_firmwares,
    _handle_submit_bare_metal_descriptor,
    register_bare_metal_tools,
)
from app.ai.tools.carving import _cap, _handle_run_shell, register_carving_tools
from app.ai.tools.cwe_checker import (
    _format_result,
    _generate_findings,
    _handle_cwe_check_binary,
    _handle_cwe_check_firmware,
    _handle_cwe_check_status,
    register_cwe_checker_tools,
)
from app.models import Firmware, Project
from app.models.attack_surface import AttackSurfaceEntry
from tests._live_db import make_live_db


@dataclass
class _Ctx:
    db: object = None
    firmware_id: object = None
    project_id: object = None
    extracted_path: str | None = "/tmp/x"
    storage_path: str | None = None

    def __post_init__(self):
        self.firmware_id = self.firmware_id or uuid.uuid4()
        self.project_id = self.project_id or uuid.uuid4()
        if self.db is None:
            self.db = MagicMock()
            self.db.add = MagicMock()
            self.db.flush = AsyncMock()
            self.db.execute = AsyncMock()
            self.db.get = AsyncMock(return_value=None)

    def resolve_path(self, path: str) -> str:
        root = self.extracted_path or "/tmp/x"
        return f"{root.rstrip('/')}/{path.lstrip('/')}"


@pytest.fixture
async def live_db():
    async with make_live_db() as db:
        yield db


async def _seed(db: AsyncSession, extracted: str = "/tmp/x") -> tuple[Project, Firmware]:
    project = Project(id=uuid.uuid4(), name="cwe-carve", status="ready")
    db.add(project)
    await db.flush()
    fw = Firmware(
        id=uuid.uuid4(),
        project_id=project.id,
        sha256="b" * 64,
        extracted_path=extracted,
        extraction_dir=extracted,
        original_filename="fw.bin",
        bare_metal_audit_status="idle",
    )
    db.add(fw)
    await db.flush()
    return project, fw


def test_registers():
    for reg_fn, min_n in (
        (register_cwe_checker_tools, 3),
        (register_carving_tools, 1),
        (register_bare_metal_tools, 4),
    ):
        r = ToolRegistry()
        reg_fn(r)
        assert len(r._tools) >= min_n


def test_cap_helper():
    assert _cap("short", 100) == "short"
    long = "x" * 200
    out = _cap(long, 50)
    assert "truncated" in out
    assert len(out) < len(long)


def test_format_result_branches():
    warn = SimpleNamespace(
        cwe_id="CWE-119",
        name="Buffer Overflow",
        symbols=["main"],
        address="0x1000",
        description="overflow in foo " * 20,
    )
    res = SimpleNamespace(
        binary_name="httpd",
        binary_path="/bin/httpd",
        warnings=[warn, warn],
        error=None,
        from_cache=True,
        elapsed_seconds=1.5,
    )
    out = _format_result(res)
    assert "CWE-119" in out
    assert "cached" in out.lower() or "httpd" in out

    err = SimpleNamespace(
        binary_name="x", binary_path="/x", warnings=[], error="fail",
        from_cache=False, elapsed_seconds=0,
    )
    assert "Error" in _format_result(err)

    empty = SimpleNamespace(
        binary_name="y", binary_path="/y", warnings=[], error=None,
        from_cache=False, elapsed_seconds=0,
    )
    assert "No CWE" in _format_result(empty)


@pytest.mark.asyncio
async def test_cwe_status_and_binary(tmp_path, live_db):
    project, fw = await _seed(live_db, str(tmp_path))
    binary = tmp_path / "bin" / "httpd"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"\x7fELF fake")
    ctx = _Ctx(db=live_db, firmware_id=fw.id, project_id=project.id, extracted_path=str(tmp_path))

    with patch(
        "app.ai.tools.cwe_checker.check_image_available",
        new=AsyncMock(return_value=(True, "image:latest")),
    ):
        ok = await _handle_cwe_check_status({}, ctx)
        assert "available" in ok.lower()
    with patch(
        "app.ai.tools.cwe_checker.check_image_available",
        new=AsyncMock(return_value=(False, "missing image")),
    ):
        bad = await _handle_cwe_check_status({}, ctx)
        assert "NOT available" in bad

    assert "required" in await _handle_cwe_check_binary({}, ctx)
    assert "not found" in (await _handle_cwe_check_binary({"path": "/nope"}, ctx)).lower()

    warn = SimpleNamespace(
        cwe_id="CWE-416",
        name="Use After Free",
        symbols=["free_me"],
        address="0x2000",
        description="UAF",
    )
    result = SimpleNamespace(
        binary_name="httpd",
        binary_path="/bin/httpd",
        warnings=[warn],
        error=None,
        from_cache=False,
        elapsed_seconds=2.0,
    )
    with patch(
        "app.ai.tools.cwe_checker.run_cwe_checker",
        new=AsyncMock(return_value=result),
    ):
        out = await _handle_cwe_check_binary({"path": "/bin/httpd"}, ctx)
        assert "CWE-416" in out or "httpd" in out
        await live_db.flush()


@pytest.mark.asyncio
async def test_cwe_check_firmware(tmp_path, live_db):
    project, fw = await _seed(live_db, str(tmp_path))
    binary = tmp_path / "usr" / "sbin" / "httpd"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"\x7fELF")
    ctx = _Ctx(db=live_db, firmware_id=fw.id, project_id=project.id, extracted_path=str(tmp_path))

    # no attack surface rows
    out = await _handle_cwe_check_firmware({}, ctx)
    assert "No attack surface" in out or "detect_input_vectors" in out

    entry = AttackSurfaceEntry(
        id=uuid.uuid4(),
        project_id=project.id,
        firmware_id=fw.id,
        binary_path="/usr/sbin/httpd",
        binary_name="httpd",
        attack_surface_score=90,
    )
    live_db.add(entry)
    await live_db.flush()

    warn = SimpleNamespace(
        cwe_id="CWE-78", name="OS Command Injection", symbols=["system"],
        address="0x1", description="cmdi",
    )
    res = SimpleNamespace(
        binary_name="httpd", binary_path="/usr/sbin/httpd",
        warnings=[warn], error=None, from_cache=False, elapsed_seconds=1.0,
    )
    with patch(
        "app.ai.tools.cwe_checker.run_cwe_checker_batch",
        new=AsyncMock(return_value=[res]),
    ):
        out = await _handle_cwe_check_firmware({"top_n": 5}, ctx)
        assert "Summary" in out or "CWE" in out or "httpd" in out


@pytest.mark.asyncio
async def test_generate_findings_empty_and_flush():
    ctx = _Ctx()
    res = SimpleNamespace(warnings=[], binary_name="x", binary_path="/x")
    await _generate_findings(res, ctx)
    assert ctx.db.add.call_count == 0

    warn = SimpleNamespace(
        cwe_id="CWE-119", name="BOF", symbols=[], address="0x0", description="d",
    )
    res2 = SimpleNamespace(
        warnings=[warn], binary_name="b", binary_path="/b",
    )
    await _generate_findings(res2, ctx)
    assert ctx.db.add.called
    assert ctx.db.flush.await_count >= 1


@pytest.mark.asyncio
async def test_carving_run_shell_all_branches():
    ctx = _Ctx()
    assert "required" in await _handle_run_shell({}, ctx)
    assert "integer" in await _handle_run_shell({"command": "echo", "timeout": "nope"}, ctx)

    from app.services.carving_service import CarvingError

    with patch("app.ai.tools.carving.CarvingService") as CS:
        inst = CS.return_value
        inst.run_command = AsyncMock(
            return_value=SimpleNamespace(
                timed_out=False, exit_code=0, stdout="hello", stderr="",
            )
        )
        out = await _handle_run_shell({"command": "echo hi", "timeout": 5}, ctx)
        assert "exit_code" in out and "hello" in out

        inst.run_command = AsyncMock(
            return_value=SimpleNamespace(
                timed_out=True, exit_code=-1, stdout="", stderr="err " * 5000,
            )
        )
        out2 = await _handle_run_shell({"command": "slow"}, ctx)
        assert "timed out" in out2.lower()
        assert "stderr" in out2

        inst.run_command = AsyncMock(side_effect=CarvingError("sandbox down"))
        assert "sandbox down" in await _handle_run_shell({"command": "x"}, ctx)

        inst.run_command = AsyncMock(side_effect=RuntimeError("boom"))
        assert "unexpected" in (await _handle_run_shell({"command": "x"}, ctx)).lower()


@pytest.mark.asyncio
async def test_bare_metal_list_and_audit(live_db, tmp_path):
    project, fw = await _seed(live_db, str(tmp_path))
    ctx = _Ctx(db=live_db, firmware_id=fw.id, project_id=project.id, extracted_path=str(tmp_path))

    fake_domain = SimpleNamespace(
        name="cpu",
        arch="c28x",
        endianness="little",
        instruction_word_bits=16,
        data_word_bits=16,
        packing="none",
        address_regions=[SimpleNamespace(name="flash", policy=[1, 2])],
    )
    fake_manifest = SimpleNamespace(
        display_name="TMS320F28066",
        vendor="ti",
        domains=[fake_domain],
        source_path="data/chip_families/ti/tms320f28066.yaml",
    )
    with patch(
        "app.ai.tools.bare_metal.get_chip_catalog",
        return_value={"ti/tms320f28066": fake_manifest},
    ):
        out = await _handle_list_chip_families({}, ctx)
        assert "ti/tms320f28066" in out
        out_v = await _handle_list_chip_families({"vendor": "ti"}, ctx)
        assert "tms320" in out_v.lower() or "ti/" in out_v
        out_empty = await _handle_list_chip_families({"vendor": "nope"}, ctx)
        assert '"total": 0' in out_empty or "total" in out_empty

    # audit — invalid uuid
    bad = await _handle_audit_bare_metal_firmware({"firmware_id": "not-uuid"}, ctx)
    assert "invalid" in bad.lower()

    # audit — missing firmware
    miss = await _handle_audit_bare_metal_firmware(
        {"firmware_id": str(uuid.uuid4())}, ctx,
    )
    assert "not found" in miss.lower()

    with patch(
        "app.ai.tools.bare_metal.run_bare_metal_audit_background",
        new=AsyncMock(),
    ):
        with patch("asyncio.create_task") as ct:
            ct.side_effect = lambda coro: (coro.close() if hasattr(coro, "close") else None) or MagicMock()
            ok = await _handle_audit_bare_metal_firmware({}, ctx)
            assert "queued" in ok

    # already in flight
    fw.bare_metal_audit_status = "running"
    await live_db.flush()
    inflight = await _handle_audit_bare_metal_firmware({}, ctx)
    assert "already_in_flight" in inflight


@pytest.mark.asyncio
async def test_bare_metal_submit_and_lookup(live_db, tmp_path):
    project, fw = await _seed(live_db, str(tmp_path))
    ctx = _Ctx(db=live_db, firmware_id=fw.id, project_id=project.id, extracted_path=str(tmp_path))

    assert "required" in await _handle_submit_bare_metal_descriptor({}, ctx)
    assert "invalid" in await _handle_submit_bare_metal_descriptor(
        {"firmware_id": "bad", "chip_family_hint": "ti/x"}, ctx,
    )
    assert "chip_family_hint" in await _handle_submit_bare_metal_descriptor(
        {"chip_family_hint": "bad"}, ctx,
    )

    fake_domain = SimpleNamespace(name="cpu")
    fake_manifest = SimpleNamespace(domains=[fake_domain])
    with patch(
        "app.ai.tools.bare_metal.get_chip_catalog",
        return_value={"ti/tms320f28066": fake_manifest},
    ):
        with patch(
            "app.ai.tools.bare_metal._stamp_bare_metal_descriptor_payload",
            side_effect=lambda d: {**d, "schema_version": 1},
        ):
            created = await _handle_submit_bare_metal_descriptor(
                {"chip_family_hint": "ti/tms320f28066"}, ctx,
            )
            assert "created" in created or "descriptor_id" in created
            # idempotent replay
            replay = await _handle_submit_bare_metal_descriptor(
                {"chip_family_hint": "ti/tms320f28066"}, ctx,
            )
            assert "idempotent" in replay or "created" in replay or "descriptor" in replay

        unknown = await _handle_submit_bare_metal_descriptor(
            {"chip_family_hint": "vendor/missing"}, ctx,
        )
        assert "not in catalog" in unknown

    # lookup
    assert "required" in await _handle_lookup_bare_metal_findings_across_firmwares({}, ctx)
    empty = await _handle_lookup_bare_metal_findings_across_firmwares(
        {"finding_source": "c28x_unsecure_csm"}, ctx,
    )
    assert "matches" in empty or "total_firmwares" in empty
