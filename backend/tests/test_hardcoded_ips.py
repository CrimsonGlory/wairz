"""Tests for the hardcoded IP detection tool (S20).

Requires lief (installed in Docker but may not be available locally).
"""

from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

# ToolContext import triggers the full tool registry which needs lief
try:
    from app.ai.tool_registry import ToolContext
    from app.ai.tools.strings import _handle_find_hardcoded_ips
    HAS_LIEF = True
except (ImportError, ModuleNotFoundError):
    HAS_LIEF = False

pytestmark = pytest.mark.skipif(not HAS_LIEF, reason="lief not installed (run in Docker)")


@pytest.fixture
def ip_firmware(tmp_path: Path) -> Path:
    """Firmware with hardcoded IPs in config files."""
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "network.conf").write_text(
        "# Network config\n"
        "SERVER_IP=203.0.113.50\n"
        "DNS_PRIMARY=8.8.8.8\n"
        "DNS_SECONDARY=8.8.4.4\n"
        "GATEWAY=192.168.1.1\n"
    )
    (tmp_path / "etc" / "hosts").write_text(
        "127.0.0.1 localhost\n"
        "10.0.0.5 update-server\n"
    )
    return tmp_path


@pytest.fixture
def clean_ip_firmware(tmp_path: Path) -> Path:
    """Firmware with no hardcoded IPs."""
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "hostname").write_text("device\n")
    return tmp_path


@pytest.fixture
def version_string_firmware(tmp_path: Path) -> Path:
    """Firmware with version strings that look like IPs (false positives)."""
    (tmp_path / "usr" / "lib").mkdir(parents=True)
    (tmp_path / "usr" / "lib" / "libcrypto.so.1.1.1").write_bytes(b"")
    (tmp_path / "etc").mkdir(exist_ok=True)
    (tmp_path / "etc" / "version").write_text("Firmware v3.2.1.0\n")
    return tmp_path


class TestHardcodedIPs:
    @pytest.mark.asyncio
    async def test_finds_public_ips(self, ip_firmware: Path):
        context = ToolContext(
            project_id=uuid4(),
            firmware_id=uuid4(),
            extracted_path=str(ip_firmware),
            db=MagicMock(),
        )
        result = await _handle_find_hardcoded_ips({}, context)
        assert "203.0.113.50" in result

    @pytest.mark.asyncio
    async def test_finds_well_known_dns(self, ip_firmware: Path):
        context = ToolContext(
            project_id=uuid4(),
            firmware_id=uuid4(),
            extracted_path=str(ip_firmware),
            db=MagicMock(),
        )
        result = await _handle_find_hardcoded_ips({}, context)
        assert "8.8.8.8" in result

    @pytest.mark.asyncio
    async def test_clean_firmware(self, clean_ip_firmware: Path):
        context = ToolContext(
            project_id=uuid4(),
            firmware_id=uuid4(),
            extracted_path=str(clean_ip_firmware),
            db=MagicMock(),
        )
        result = await _handle_find_hardcoded_ips({}, context)
        assert "No hardcoded" in result or "0 unique" in result or "found: 0" in result.lower()
