"""Service-layer tests for ``app.services.pcap_analysis_service``.

Phase 2 Wave 6 file 2 of 5 — backfills service-layer tests for the
PcapAnalysisService scapy wrapper (594 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

This service is the **inverse Rule #30 case**: every scapy symbol
(``PcapReader``, ``IP``, ``TCP``, ``UDP``, ``ICMP``, ``ARP``, ``DNS``,
``DNSQR``, ``DNSRR``, ``Raw``) is imported at MODULE scope (line 15 —
``from scapy.all import ...``). Per the campaign Decision Log "inverse
Rule #30" entry, patching the SOURCE modules (``scapy.all.PcapReader``)
would silently no-op because the consumer already holds local references.
Patches MUST hit the CONSUMER module:
``patch("app.services.pcap_analysis_service.PcapReader", ...)``.

In practice the live canary doesn't need patches at all — scapy is
installed, so we build real packets with ``IP() / TCP() / DNS()`` and
write them to a real pcap with ``wrpcap``, then call ``analyze_pcap()``
through the full PcapReader pipeline. This is BOTH cheaper than mocking
the packet object graph AND a stronger value-flow contract: the
"PcapAnalysis fields round-trip from real packets" canary catches the
F-A-06-shape regression that ``mock_reader.assert_called`` cannot.

Coverage targets:

* ``analyze_pcap`` missing-file branch — FileNotFoundError raised.
* ``_classify_protocol`` — DNS / TCP+well-known port / TCP+unknown /
  UDP+well-known / UDP+unknown / ICMP / ARP / fallback-to-lastlayer.
* ``_extract_protocol_breakdown`` — Counter accumulates and sorts.
* ``_extract_conversations`` — direction normalisation; top-50 cap; sorted
  by byte_count desc.
* ``_detect_insecure_protocols`` — Telnet (Critical), FTP (High), HTTP
  payload (Medium), DNS (Low), TFTP (Critical), SNMP (High); empty-pcap
  produces empty findings list.
* ``_extract_dns_queries`` — query+response → resolved IPs.
* ``_extract_tls_metadata`` — HAS_TLS=False short-circuits to empty list
  (the no-TLS-build branch).
* **Rule #35b live canary** — real pcap on disk via ``wrpcap``, full
  pipeline through ``analyze_pcap``, every PcapAnalysis field asserted
  against the bytes that went in.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.services.pcap_analysis_service import (
    Conversation,
    DnsQuery,
    InsecureProtocolFinding,
    PcapAnalysis,
    PcapAnalysisService,
    TlsInfo,
)


# ===========================================================================
# Helpers — real scapy packet builders (used by both unit tests + live canary)
# ===========================================================================


def _build_telnet_packets(*, count: int = 3) -> list:
    """Build ``count`` real scapy TCP packets to port 23 with payload."""
    from scapy.all import IP, TCP, Raw
    pkts = []
    for i in range(count):
        pkt = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(
            sport=40000 + i, dport=23, flags="PA",
        ) / Raw(load=b"login: admin\r\n")
        pkts.append(pkt)
    return pkts


def _build_http_packets(*, count: int = 2) -> list:
    """HTTP packets (port 80, with payload) — Medium severity finding."""
    from scapy.all import IP, TCP, Raw
    pkts = []
    for i in range(count):
        pkt = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(
            sport=50000 + i, dport=80, flags="PA",
        ) / Raw(load=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        pkts.append(pkt)
    return pkts


def _build_dns_query_response() -> list:
    """Build a DNS query + response pair (port 53)."""
    from scapy.all import IP, UDP, DNS, DNSQR, DNSRR
    query = IP(src="10.0.0.5", dst="10.0.0.1") / UDP(
        sport=33000, dport=53,
    ) / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    response = IP(src="10.0.0.1", dst="10.0.0.5") / UDP(
        sport=53, dport=33000,
    ) / DNS(
        qr=1, ra=1,
        qd=DNSQR(qname="example.com", qtype="A"),
        an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34"),
    )
    return [query, response]


def _build_arp_packets(*, count: int = 1) -> list:
    """ARP packets — a packet type that exercises the ARP branch of
    _classify_protocol."""
    from scapy.all import ARP
    return [ARP(op=1, pdst="10.0.0.1", hwsrc="00:11:22:33:44:55")
            for _ in range(count)]


def _build_icmp_packets(*, count: int = 1) -> list:
    """ICMP echo packets — exercises ICMP branch of _classify_protocol."""
    from scapy.all import IP, ICMP
    return [IP(src="10.0.0.5", dst="10.0.0.1") / ICMP(type=8)
            for _ in range(count)]


# ===========================================================================
# analyze_pcap — file-existence guard
# ===========================================================================


class TestAnalyzePcap:
    def test_missing_file_raises_file_not_found(self, tmp_path: Path):
        svc = PcapAnalysisService()
        with pytest.raises(FileNotFoundError, match="Pcap file not found"):
            svc.analyze_pcap(str(tmp_path / "nope.pcap"))


# ===========================================================================
# _classify_protocol — packet → protocol-name dispatch
# ===========================================================================


class TestClassifyProtocol:
    def setup_method(self):
        self.svc = PcapAnalysisService()

    def test_dns_packet_classified_as_dns(self):
        pkts = _build_dns_query_response()
        # DNS layer present → "DNS" wins regardless of port.
        assert self.svc._classify_protocol(pkts[0]) == "DNS"

    def test_tcp_well_known_port_returns_protocol_name(self):
        from scapy.all import IP, TCP
        # Port 80 → HTTP per _PORT_PROTOCOL_MAP.
        pkt = IP() / TCP(sport=12345, dport=80)
        assert self.svc._classify_protocol(pkt) == "HTTP"

    def test_tcp_well_known_source_port_also_matches(self):
        from scapy.all import IP, TCP
        # Reply direction: source port is the well-known one.
        pkt = IP() / TCP(sport=80, dport=54321)
        assert self.svc._classify_protocol(pkt) == "HTTP"

    def test_tcp_unknown_port_falls_back_to_tcp(self):
        from scapy.all import IP, TCP
        pkt = IP() / TCP(sport=40000, dport=40001)  # neither in port map
        assert self.svc._classify_protocol(pkt) == "TCP"

    def test_udp_well_known_port_returns_protocol_name(self):
        from scapy.all import IP, UDP
        pkt = IP() / UDP(sport=33000, dport=123)  # 123 = NTP
        assert self.svc._classify_protocol(pkt) == "NTP"

    def test_udp_unknown_port_falls_back_to_udp(self):
        from scapy.all import IP, UDP
        pkt = IP() / UDP(sport=40000, dport=40001)
        assert self.svc._classify_protocol(pkt) == "UDP"

    def test_icmp_packet_classified_as_icmp(self):
        pkt = _build_icmp_packets(count=1)[0]
        assert self.svc._classify_protocol(pkt) == "ICMP"

    def test_arp_packet_classified_as_arp(self):
        pkt = _build_arp_packets(count=1)[0]
        assert self.svc._classify_protocol(pkt) == "ARP"


# ===========================================================================
# _extract_protocol_breakdown — Counter accumulation + sort
# ===========================================================================


class TestExtractProtocolBreakdown:
    def setup_method(self):
        self.svc = PcapAnalysisService()

    def test_empty_packet_list_returns_empty_dict(self):
        assert self.svc._extract_protocol_breakdown([]) == {}

    def test_counts_each_protocol(self):
        # 3 telnet TCP + 2 HTTP TCP + 1 DNS UDP + 1 ICMP = 7 packets, 4 protos.
        pkts = (
            _build_telnet_packets(count=3)
            + _build_http_packets(count=2)
            + _build_dns_query_response()[:1]  # Just the query, not response
            + _build_icmp_packets(count=1)
        )
        breakdown = self.svc._extract_protocol_breakdown(pkts)

        # Telnet → TCP+port-23 → "Telnet" via _PORT_PROTOCOL_MAP.
        assert breakdown.get("Telnet") == 3
        # HTTP → TCP+port-80.
        assert breakdown.get("HTTP") == 2
        # DNS query → DNS layer matches.
        assert breakdown.get("DNS") == 1
        assert breakdown.get("ICMP") == 1
        # Result is sorted desc by count (Counter.most_common() ordering).
        counts = list(breakdown.values())
        assert counts == sorted(counts, reverse=True)


# ===========================================================================
# _extract_conversations — direction normalisation + top-50 cap
# ===========================================================================


class TestExtractConversations:
    def setup_method(self):
        self.svc = PcapAnalysisService()

    def test_aggregates_packets_into_conversation(self):
        pkts = _build_telnet_packets(count=3)
        # All 3 packets share the same (src, sport, dst, dport) tuple per
        # _build_telnet_packets — though sport differs across i.
        # Build packets with identical sport too:
        from scapy.all import IP, TCP, Raw
        pkts = [
            IP(src="10.0.0.5", dst="10.0.0.1") / TCP(
                sport=40000, dport=23, flags="PA",
            ) / Raw(load=b"x")
            for _ in range(3)
        ]
        convs = self.svc._extract_conversations(pkts)
        # Same src/dst/sport/dport → 1 conversation, packet_count=3.
        assert len(convs) == 1
        assert convs[0].packet_count == 3
        assert convs[0].byte_count > 0
        assert convs[0].protocol == "TCP"

    def test_direction_normalisation_collapses_replies(self):
        """Forward packets and reply packets should be aggregated into a
        single conversation via the (smaller IP:port → src) normalisation."""
        from scapy.all import IP, TCP, Raw
        # Forward packet: 10.0.0.5:40000 → 10.0.0.1:23
        forward = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(
            sport=40000, dport=23,
        ) / Raw(load=b"x")
        # Reply: 10.0.0.1:23 → 10.0.0.5:40000
        reply = IP(src="10.0.0.1", dst="10.0.0.5") / TCP(
            sport=23, dport=40000,
        ) / Raw(load=b"y")
        convs = self.svc._extract_conversations([forward, reply])
        # ONE conversation for both directions.
        assert len(convs) == 1
        assert convs[0].packet_count == 2

    def test_non_ip_packets_skipped(self):
        # ARP packets aren't IP/IPv6 → skipped by the conversation extractor.
        pkts = _build_arp_packets(count=2)
        convs = self.svc._extract_conversations(pkts)
        assert len(convs) == 0

    def test_top_50_cap(self):
        """When more than 50 conversations exist, only the top 50 by
        byte_count are returned."""
        from scapy.all import IP, TCP, Raw
        pkts = []
        # Build 60 distinct conversations (60 different dst IPs).
        for i in range(60):
            pkts.append(
                IP(src="10.0.0.5", dst=f"10.0.0.{i + 10}") / TCP(
                    sport=40000, dport=80,
                ) / Raw(load=b"x" * (10 + i)),  # increasing size for ranking
            )
        convs = self.svc._extract_conversations(pkts)
        assert len(convs) == 50
        # Sorted desc by byte_count → the top should be the largest packets.
        byte_counts = [c.byte_count for c in convs]
        assert byte_counts == sorted(byte_counts, reverse=True)


# ===========================================================================
# _detect_insecure_protocols — 13 detection rules
# ===========================================================================


class TestDetectInsecureProtocols:
    def setup_method(self):
        self.svc = PcapAnalysisService()

    def test_empty_pcap_yields_empty_findings(self):
        assert self.svc._detect_insecure_protocols([]) == []

    def test_telnet_packets_yield_critical_finding(self):
        findings = self.svc._detect_insecure_protocols(
            _build_telnet_packets(count=3),
        )
        telnet = next(f for f in findings if f.protocol == "Telnet")
        assert telnet.severity == "Critical"
        assert telnet.port == 23
        assert telnet.packet_count == 3
        assert "3 " in telnet.evidence  # "3 packets to/from port 23..."

    def test_http_packets_yield_medium_finding(self):
        findings = self.svc._detect_insecure_protocols(
            _build_http_packets(count=2),
        )
        http = next(f for f in findings if f.protocol == "HTTP (no TLS)")
        assert http.severity == "Medium"
        assert http.port == 80
        assert http.packet_count == 2

    def test_dns_packets_yield_low_finding(self):
        # DNS query (UDP port 53) → "DNS (no DoT/DoH)" Low.
        pkts = _build_dns_query_response()
        findings = self.svc._detect_insecure_protocols(pkts)
        dns = next(f for f in findings if f.protocol == "DNS (no DoT/DoH)")
        assert dns.severity == "Low"
        assert dns.port == 53

    def test_tftp_packets_yield_critical_finding(self):
        from scapy.all import IP, UDP
        # TFTP UDP port 69.
        pkts = [
            IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=33000, dport=69)
            for _ in range(2)
        ]
        findings = self.svc._detect_insecure_protocols(pkts)
        tftp = next(f for f in findings if f.protocol == "TFTP")
        assert tftp.severity == "Critical"
        assert tftp.port == 69

    def test_snmp_v1_v2c_yields_high_finding(self):
        from scapy.all import IP, UDP
        pkts = [
            IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=33000, dport=161)
            for _ in range(2)
        ]
        findings = self.svc._detect_insecure_protocols(pkts)
        snmp = next(f for f in findings if f.protocol == "SNMPv1/v2c")
        assert snmp.severity == "High"

    def test_clean_https_traffic_produces_no_critical_findings(self):
        from scapy.all import IP, TCP, Raw
        # Port 443 is HTTPS — not in the insecure-port set.
        pkts = [
            IP(src="10.0.0.5", dst="10.0.0.1") / TCP(
                sport=50000, dport=443,
            ) / Raw(load=b"\x16\x03\x01")
            for _ in range(3)
        ]
        findings = self.svc._detect_insecure_protocols(pkts)
        critical = [f for f in findings if f.severity == "Critical"]
        assert critical == []


# ===========================================================================
# _extract_dns_queries — query+response → resolved IPs
# ===========================================================================


class TestExtractDnsQueries:
    def setup_method(self):
        self.svc = PcapAnalysisService()

    def test_query_alone_returns_empty_resolved(self):
        from scapy.all import IP, UDP, DNS, DNSQR
        query = IP(src="10.0.0.5", dst="10.0.0.1") / UDP(
            sport=33000, dport=53,
        ) / DNS(rd=1, qd=DNSQR(qname="alone.example.com", qtype="A"))
        queries = self.svc._extract_dns_queries([query])
        assert len(queries) == 1
        assert queries[0].domain == "alone.example.com"
        assert queries[0].query_type == "A"
        assert queries[0].resolved_ips == []

    def test_query_response_pair_persists_domain_and_type(self):
        """In-memory query+response pair is parsed into a DnsQuery row.

        The response→resolved_ips edge depends on PcapReader's
        on-disk serialization (scapy's PacketListField is realised
        differently when read from a real pcap vs constructed in-memory),
        so the resolved-IPs assertion lives in the
        TestAnalyzePcapLiveCanary canary which round-trips through
        wrpcap+PcapReader. Here we just check the query side persists.
        """
        pkts = _build_dns_query_response()
        queries = self.svc._extract_dns_queries(pkts)
        assert len(queries) == 1
        q = queries[0]
        assert q.domain == "example.com"
        assert q.query_type == "A"

    def test_non_dns_packets_ignored(self):
        pkts = _build_telnet_packets(count=2)
        assert self.svc._extract_dns_queries(pkts) == []


# ===========================================================================
# _extract_tls_metadata — HAS_TLS=False short-circuit
# ===========================================================================


class TestExtractTlsMetadata:
    def setup_method(self):
        self.svc = PcapAnalysisService()

    def test_returns_empty_when_tls_unavailable(self):
        # Patch the consumer module's HAS_TLS flag to False — covers the
        # "scapy build without TLS support" branch (line 516).
        with patch(
            "app.services.pcap_analysis_service.HAS_TLS",
            new=False,
        ):
            assert self.svc._extract_tls_metadata([]) == []

    def test_returns_empty_for_non_tls_packets(self):
        # Even with HAS_TLS available, non-TLS packets produce no metadata.
        pkts = _build_telnet_packets(count=2)
        # TestExtractTlsMetadata: real packets with no TLSClientHello layer.
        assert self.svc._extract_tls_metadata(pkts) == []


# ===========================================================================
# Rule #35b live canary — real pcap on disk → analyze_pcap → assert fields
# ===========================================================================


class TestAnalyzePcapLiveCanary:
    """Rule #35b live canary: real pcap on disk + real PcapReader pipeline +
    SELECT-equivalent assertion of every PcapAnalysis field.

    Mirrors test_androguard_service.py's ``analyze_apk`` happy-path canary —
    every field the wrapper explicitly populates round-trips through the
    PcapReader pipeline into the returned dataclass with the expected key
    names. Mock-only tests that assert ``mock_reader.assert_called`` cannot
    fail on a constructor that types ``severity`` as ``None`` or drops
    ``packet_count``; this can.
    """

    def test_full_pipeline_value_flow(self, tmp_path: Path):
        from scapy.all import wrpcap
        # Mix of telnet (Critical), HTTP (Medium), DNS (Low + DnsQuery),
        # ICMP (no insecure finding, just counted).
        pkts = (
            _build_telnet_packets(count=3)
            + _build_http_packets(count=2)
            + _build_dns_query_response()
            + _build_icmp_packets(count=1)
        )
        pcap_path = tmp_path / "canary.pcap"
        wrpcap(str(pcap_path), pkts)

        # Sanity: pcap is on disk and non-empty.
        assert pcap_path.exists()
        assert pcap_path.stat().st_size > 0

        svc = PcapAnalysisService()
        result = svc.analyze_pcap(str(pcap_path))

        # Type contract.
        assert isinstance(result, PcapAnalysis)
        assert isinstance(result.protocol_breakdown, dict)
        assert isinstance(result.conversations, list)
        assert isinstance(result.insecure_findings, list)
        assert isinstance(result.dns_queries, list)
        assert isinstance(result.tls_info, list)

        # total_packets matches what we wrote (Rule #35b — exact value flow).
        assert result.total_packets == len(pkts)

        # Protocol breakdown counts.
        assert result.protocol_breakdown.get("Telnet") == 3
        assert result.protocol_breakdown.get("HTTP") == 2
        assert result.protocol_breakdown.get("DNS") == 2  # query + response
        assert result.protocol_breakdown.get("ICMP") == 1

        # Insecure findings — Telnet (Critical), HTTP (Medium), DNS (Low).
        findings_by_proto = {f.protocol: f for f in result.insecure_findings}
        assert "Telnet" in findings_by_proto
        assert findings_by_proto["Telnet"].severity == "Critical"
        assert findings_by_proto["Telnet"].packet_count == 3
        assert findings_by_proto["Telnet"].port == 23
        assert "3 " in findings_by_proto["Telnet"].evidence

        assert "HTTP (no TLS)" in findings_by_proto
        assert findings_by_proto["HTTP (no TLS)"].severity == "Medium"
        assert findings_by_proto["HTTP (no TLS)"].port == 80

        assert "DNS (no DoT/DoH)" in findings_by_proto
        assert findings_by_proto["DNS (no DoT/DoH)"].severity == "Low"

        # DNS query → response.
        assert len(result.dns_queries) == 1
        dns_q = result.dns_queries[0]
        assert dns_q.domain == "example.com"
        assert dns_q.query_type == "A"
        assert "93.184.216.34" in dns_q.resolved_ips

        # Conversations: at least one TCP conversation aggregating telnet
        # packets, one HTTP conversation, and DNS UDP conversation.
        assert len(result.conversations) >= 2
        # All conversations have the dataclass shape.
        for c in result.conversations:
            assert isinstance(c, Conversation)
            assert c.packet_count >= 1
            assert c.byte_count > 0
            assert c.protocol in ("TCP", "UDP")

    def test_max_packets_cap(self, tmp_path: Path):
        """``MAX_PACKETS`` (10000) caps reading. Verify with a smaller cap
        via monkeypatch so the test is fast."""
        from scapy.all import wrpcap
        pkts = _build_telnet_packets(count=20)
        pcap_path = tmp_path / "many.pcap"
        wrpcap(str(pcap_path), pkts)

        with patch.object(PcapAnalysisService, "MAX_PACKETS", new=5):
            svc = PcapAnalysisService()
            result = svc.analyze_pcap(str(pcap_path))
        # Cap honoured: only 5 packets read despite 20 in the file.
        assert result.total_packets == 5

    def test_pcap_reader_failure_propagates(self, tmp_path: Path):
        """Non-pcap garbage on disk → PcapReader raises → analyze_pcap
        propagates (the inner ``except Exception: ... raise`` re-raises
        after logging)."""
        garbage = tmp_path / "junk.pcap"
        garbage.write_bytes(b"this is not a pcap")
        svc = PcapAnalysisService()
        with pytest.raises(Exception):  # noqa: B017 — propagated from scapy
            svc.analyze_pcap(str(garbage))


# ===========================================================================
# Rule #30 inverse-case canary — patching CONSUMER module
# ===========================================================================


class TestRule30InverseConsumerPatch:
    """Documents the inverse-Rule #30 case that this service exemplifies.
    Patching ``app.services.pcap_analysis_service.PcapReader`` IS the
    correct target because the symbol is bound at module scope (line 15);
    patching ``scapy.all.PcapReader`` would leave the consumer's local
    reference unchanged.
    """

    def test_consumer_module_patch_intercepts_pcap_reader(self, tmp_path: Path):
        # Build a fake reader context manager that yields nothing.
        fake_reader = MagicMock()
        fake_reader.__enter__ = MagicMock(return_value=iter([]))
        fake_reader.__exit__ = MagicMock(return_value=None)

        pcap_path = tmp_path / "any.pcap"
        pcap_path.write_bytes(b"placeholder")  # file must exist

        with patch(
            "app.services.pcap_analysis_service.PcapReader",
            return_value=fake_reader,
        ) as mock_reader:
            svc = PcapAnalysisService()
            result = svc.analyze_pcap(str(pcap_path))

        # The patched-in reader was actually called — proving the
        # consumer-module target is correct.
        mock_reader.assert_called_once_with(str(pcap_path))
        # And the empty-iter result flows through to total_packets=0.
        assert result.total_packets == 0
        assert result.protocol_breakdown == {}
        assert result.conversations == []
        assert result.insecure_findings == []
