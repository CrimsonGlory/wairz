"""MCP handler tests for ``app.ai.tools.network`` (was ~15% / 106 miss)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.network import (
    _handle_analyze_network_traffic,
    _handle_get_dns_queries,
    _handle_get_network_conversations,
    _handle_get_protocol_breakdown,
    _handle_identify_insecure_protocols,
    register_network_tools,
)


@dataclass
class _StubContext:
    db: object = None
    firmware_id: object = None
    project_id: object = None
    extracted_path: str | None = "/tmp/extract"

    def __post_init__(self):
        self.firmware_id = self.firmware_id or uuid.uuid4()
        self.project_id = self.project_id or uuid.uuid4()


def _analysis(**kw):
    defaults = dict(
        total_packets=100,
        protocol_breakdown={"TCP": 60, "UDP": 30, "DNS": 10},
        insecure_findings=[
            SimpleNamespace(
                severity="High", protocol="Telnet", port=23,
                description="cleartext", evidence="banner", packet_count=5,
            ),
            SimpleNamespace(
                severity="Medium", protocol="HTTP", port=80,
                description="no tls", evidence="GET", packet_count=10,
            ),
        ],
        dns_queries=[
            SimpleNamespace(domain="evil.example", query_type="A", resolved_ips=["1.2.3.4"]),
            SimpleNamespace(domain="ok.example", query_type="AAAA", resolved_ips=[]),
        ],
        conversations=[
            SimpleNamespace(
                src="10.0.0.1", src_port=1234, dst="10.0.0.2", dst_port=80,
                protocol="TCP", packet_count=12, byte_count=900,
            ),
        ],
        tls_info=[
            SimpleNamespace(server="api.example", port=443, version="TLS1.2", cipher_suites=["AES"]),
        ],
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def test_register_network_tools():
    reg = ToolRegistry()
    register_network_tools(reg)
    assert len(reg._tools) >= 5


@pytest.mark.asyncio
async def test_network_handlers_error_and_full():
    ctx = _StubContext()
    with patch(
        "app.ai.tools.network._load_pcap_analysis",
        new=AsyncMock(return_value=(None, "Error: no pcap")),
    ):
        assert "Error" in await _handle_analyze_network_traffic({}, ctx)
        assert "Error" in await _handle_get_protocol_breakdown({}, ctx)

    a = _analysis()
    with patch(
        "app.ai.tools.network._load_pcap_analysis",
        new=AsyncMock(return_value=(a, None)),
    ):
        full = await _handle_analyze_network_traffic({}, ctx)
        assert "Protocol Breakdown" in full
        assert "Telnet" in full
        assert "evil.example" in full
        assert "TLS" in full

        proto = await _handle_get_protocol_breakdown({}, ctx)
        assert "TCP" in proto and "#" in proto

        insecure = await _handle_identify_insecure_protocols({}, ctx)
        assert "Insecure Protocol" in insecure and "Summary" in insecure

        dns = await _handle_get_dns_queries({}, ctx)
        assert "evil.example" in dns and "unresolved" in dns

        conv = await _handle_get_network_conversations({}, ctx)
        assert "10.0.0.1" in conv and "Conversations" in conv

    empty = _analysis(
        insecure_findings=[], dns_queries=[], conversations=[], tls_info=[],
    )
    with patch(
        "app.ai.tools.network._load_pcap_analysis",
        new=AsyncMock(return_value=(empty, None)),
    ):
        assert "None found" in await _handle_analyze_network_traffic({}, ctx)
        assert "No insecure" in await _handle_identify_insecure_protocols({}, ctx)
        assert "No DNS" in await _handle_get_dns_queries({}, ctx)
        assert "No TCP/UDP" in await _handle_get_network_conversations({}, ctx)
