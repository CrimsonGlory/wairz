"""Tests for MCP server firmware selection logic.

Covers the `_select_firmware` helper, which is responsible for picking the
active firmware from a project's firmware list. The helper is pulled out of
the DB-bound `_load_project` wrapper so it can be tested without a database.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import pytest

from app.mcp_server import _select_firmware


@dataclass
class _FakeFirmware:
    """Minimal stand-in for the SQLAlchemy Firmware model.

    `_select_firmware` only reads .id, .extracted_path, and .created_at, so a
    dataclass avoids pulling in the async ORM stack just for these tests.
    """
    id: uuid.UUID
    extracted_path: str | None
    created_at: datetime


def _fw(idx: int, *, extracted: bool = True, offset_seconds: int = 0) -> _FakeFirmware:
    """Build a fake firmware with a deterministic UUID and created_at ordering."""
    return _FakeFirmware(
        id=uuid.UUID(int=idx),
        extracted_path=f"/data/fw{idx}" if extracted else None,
        created_at=datetime(2026, 1, 1) + timedelta(seconds=offset_seconds),
    )


class TestSelectFirmware:
    def test_empty_list_raises(self):
        with pytest.raises(ValueError, match="no firmware uploaded"):
            _select_firmware([])

    def test_single_firmware_returned(self):
        fw = _fw(1)
        assert _select_firmware([fw]) is fw

    def test_multiple_picks_earliest_unpacked(self):
        """With multiple unpacked firmwares, the earliest-created one wins."""
        fw_old = _fw(1, offset_seconds=0)
        fw_mid = _fw(2, offset_seconds=100)
        fw_new = _fw(3, offset_seconds=200)
        # Pass in reverse order to prove we're not relying on input order.
        assert _select_firmware([fw_new, fw_mid, fw_old]) is fw_old

    def test_unpacked_required_when_no_id_specified(self):
        """Non-unpacked firmwares are skipped even if they were uploaded first."""
        fw_pending = _fw(1, extracted=False, offset_seconds=0)
        fw_ready = _fw(2, extracted=True, offset_seconds=100)
        assert _select_firmware([fw_pending, fw_ready]) is fw_ready

    def test_no_unpacked_raises(self):
        firmwares = [_fw(i, extracted=False, offset_seconds=i) for i in range(1, 4)]
        with pytest.raises(ValueError, match="has been unpacked"):
            _select_firmware(firmwares)

    def test_explicit_id_returns_that_firmware(self):
        firmwares = [_fw(i, offset_seconds=i) for i in range(1, 4)]
        target = firmwares[1]  # not the earliest
        assert _select_firmware(firmwares, firmware_id=target.id) is target

    def test_explicit_id_not_found_raises(self):
        firmwares = [_fw(i) for i in range(1, 4)]
        missing = uuid.UUID(int=999)
        with pytest.raises(ValueError, match="not found in this project"):
            _select_firmware(firmwares, firmware_id=missing)

    def test_explicit_id_must_be_unpacked(self):
        """When targeting a specific firmware, require it to be unpacked.

        Without this check, the MCP server would start against a firmware that
        has no extracted_path and fail confusingly on the first tool call.
        """
        fw = _fw(1, extracted=False)
        with pytest.raises(ValueError, match="has not been unpacked"):
            _select_firmware([fw], firmware_id=fw.id)
