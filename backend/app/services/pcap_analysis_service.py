"""Pcap analysis service using Scapy for protocol dissection.

This service analyzes binary pcap files captured during emulation sessions.
It runs synchronously (CPU-bound) -- callers should use loop.run_in_executor().
Memory-safe: uses PcapReader iterator, not rdpcap. Capped at MAX_PACKETS.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from dataclasses import dataclass, field

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, IPv6, PcapReader, Raw

# TLS layers may not be available depending on scapy build/version
try:
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.tls.record import TLS
    HAS_TLS = True
except ImportError:
    HAS_TLS = False

logger = logging.getLogger(__name__)

# Port-to-protocol mapping for well-known services
_PORT_PROTOCOL_MAP: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    443: "HTTPS",
    514: "Syslog",
    993: "IMAPS",
    995: "POP3S",
    1883: "MQTT",
    1900: "UPnP/SSDP",
    5353: "mDNS",
    5683: "CoAP",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8883: "MQTT-TLS",
}

# DNS query type codes to names
_DNS_QTYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


@dataclass
class Conversation:
    """A network conversation between two endpoints."""

    src: str
    src_port: int
    dst: str
    dst_port: int
    protocol: str
    packet_count: int = 0
    byte_count: int = 0


@dataclass
class InsecureProtocolFinding:
    """An insecure protocol detected in the capture."""

    protocol: str
    port: int
    severity: str  # Critical, High, Medium, Low, Info
    description: str
    evidence: str  # e.g. "3 packets to port 23"
    packet_count: int = 0


@dataclass
class DnsQuery:
    """A DNS query observed in the capture."""

    domain: str
    query_type: str
    resolved_ips: list[str] = field(default_factory=list)


@dataclass
class TlsInfo:
    """TLS handshake metadata extracted from a ClientHello."""

    server: str
    port: int
    version: str
    cipher_suites: list[str] = field(default_factory=list)


@dataclass
class PcapAnalysis:
    """Complete analysis result for a pcap file."""

    total_packets: int
    protocol_breakdown: dict[str, int]  # protocol_name -> packet_count
    conversations: list[Conversation]
    insecure_findings: list[InsecureProtocolFinding]
    dns_queries: list[DnsQuery]
    tls_info: list[TlsInfo]


class PcapAnalysisService:
    """Analyzes pcap files using Scapy.

    All public methods are synchronous (CPU-bound). Callers should invoke
    them via ``loop.run_in_executor()`` to avoid blocking the event loop.
    """

    MAX_PACKETS = 10_000  # Safety cap to prevent memory exhaustion

    # ── public API ──────────────────────────────────────────────────

    def analyze_pcap(self, pcap_path: str) -> PcapAnalysis:
        """Full analysis pipeline. Runs synchronously -- call from executor."""
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"Pcap file not found: {pcap_path}")

        packets = self._read_packets(pcap_path)

        return PcapAnalysis(
            total_packets=len(packets),
            protocol_breakdown=self._extract_protocol_breakdown(packets),
            conversations=self._extract_conversations(packets),
            insecure_findings=self._detect_insecure_protocols(packets),
            dns_queries=self._extract_dns_queries(packets),
            tls_info=self._extract_tls_metadata(packets),
        )

    # ── packet reading ──────────────────────────────────────────────

    def _read_packets(self, pcap_path: str) -> list:
        """Read packets using PcapReader iterator (memory-safe).

        Uses PcapReader instead of rdpcap to avoid loading the entire file
        into memory. Caps at MAX_PACKETS.
        """
        packets: list = []
        try:
            with PcapReader(pcap_path) as reader:
                for pkt in reader:
                    packets.append(pkt)
                    if len(packets) >= self.MAX_PACKETS:
                        logger.warning(
                            "Reached packet cap (%d) for %s, truncating",
                            self.MAX_PACKETS,
                            pcap_path,
                        )
                        break
        except Exception as exc:
            logger.error("Failed to read pcap %s: %s", pcap_path, exc)
            raise
        return packets

    # ── protocol breakdown ──────────────────────────────────────────

    def _classify_protocol(self, pkt) -> str:
        """Classify a packet into a human-readable protocol name."""
        # Check for specific application-layer protocols first
        if pkt.haslayer(DNS):
            return "DNS"

        if HAS_TLS and pkt.haslayer(TLS):
            return "TLS"

        # Try IoT protocols via contrib (lazy import)
        try:
            from scapy.contrib.mqtt import MQTT
            if pkt.haslayer(MQTT):
                return "MQTT"
        except ImportError:
            pass

        try:
            from scapy.contrib.coap import CoAP
            if pkt.haslayer(CoAP):
                return "CoAP"
        except ImportError:
            pass

        # TCP/UDP with well-known port mapping
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            # Check destination port first, then source (reply)
            for port in (dport, sport):
                if port in _PORT_PROTOCOL_MAP:
                    return _PORT_PROTOCOL_MAP[port]
            return "TCP"

        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            for port in (dport, sport):
                if port in _PORT_PROTOCOL_MAP:
                    return _PORT_PROTOCOL_MAP[port]
            return "UDP"

        if pkt.haslayer(ICMP):
            return "ICMP"

        if pkt.haslayer(ARP):
            return "ARP"

        # Fallback: use Scapy's last layer name
        return pkt.lastlayer().name

    def _extract_protocol_breakdown(self, packets: list) -> dict[str, int]:
        """Count packets by protocol, returning a protocol->count mapping."""
        counter: Counter[str] = Counter()
        for pkt in packets:
            proto = self._classify_protocol(pkt)
            counter[proto] += 1
        # Sort by count descending
        return dict(counter.most_common())

    # ── conversations ───────────────────────────────────────────────

    def _extract_conversations(self, packets: list) -> list[Conversation]:
        """Group packets into conversations (top 50 by byte count)."""
        conv_map: dict[tuple, dict] = {}

        for pkt in packets:
            if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
                continue

            ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)

            if pkt.haslayer(TCP):
                transport = pkt[TCP]
                proto = "TCP"
            elif pkt.haslayer(UDP):
                transport = pkt[UDP]
                proto = "UDP"
            else:
                continue  # Skip non-TCP/UDP for conversation tracking

            sport = transport.sport
            dport = transport.dport

            # Normalize direction: smaller IP:port is always "src"
            if (src_ip, sport) > (dst_ip, dport):
                key = (dst_ip, dport, src_ip, sport, proto)
            else:
                key = (src_ip, sport, dst_ip, dport, proto)

            if key not in conv_map:
                conv_map[key] = {"packet_count": 0, "byte_count": 0}

            conv_map[key]["packet_count"] += 1
            conv_map[key]["byte_count"] += len(pkt)

        # Build conversation objects, sort by byte_count descending
        conversations = [
            Conversation(
                src=k[0],
                src_port=k[1],
                dst=k[2],
                dst_port=k[3],
                protocol=k[4],
                packet_count=v["packet_count"],
                byte_count=v["byte_count"],
            )
            for k, v in conv_map.items()
        ]
        conversations.sort(key=lambda c: c.byte_count, reverse=True)
        return conversations[:50]

    # ── insecure protocol detection ─────────────────────────────────

    def _detect_insecure_protocols(self, packets: list) -> list[InsecureProtocolFinding]:
        """Detect insecure protocols based on 13 rules."""
        findings: list[InsecureProtocolFinding] = []

        # Counters for each rule
        telnet_count = 0
        tftp_count = 0
        ftp_count = 0
        mqtt_plain_count = 0
        snmp_count = 0
        http_plain_count = 0
        coap_plain_count = 0
        upnp_count = 0
        syslog_count = 0
        tls_old_count = 0
        dns_plain_count = 0
        ntp_count = 0
        mdns_count = 0

        for pkt in packets:
            # TCP-based detections
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                sport, dport = tcp.sport, tcp.dport
                has_payload = pkt.haslayer(Raw) and len(pkt[Raw].load) > 0

                # Telnet (port 23, with payload)
                if (dport == 23 or sport == 23) and has_payload:
                    telnet_count += 1

                # FTP (port 21, with payload)
                if (dport == 21 or sport == 21) and has_payload:
                    ftp_count += 1

                # MQTT plaintext (port 1883)
                if dport == 1883 or sport == 1883:
                    mqtt_plain_count += 1

                # HTTP plaintext (port 80, with payload)
                if (dport == 80 or sport == 80) and has_payload:
                    http_plain_count += 1

                # TLS 1.0/1.1 detection
                if HAS_TLS and pkt.haslayer(TLS):
                    try:
                        if pkt.haslayer(TLSClientHello):
                            hello = pkt[TLSClientHello]
                            # TLS versions: 0x0301 = TLS 1.0, 0x0302 = TLS 1.1
                            version = getattr(hello, "version", None)
                            if version is not None and version <= 0x0302:
                                tls_old_count += 1
                    except Exception:
                        pass

            # UDP-based detections
            if pkt.haslayer(UDP):
                udp = pkt[UDP]
                sport, dport = udp.sport, udp.dport

                # TFTP (port 69)
                if dport == 69 or sport == 69:
                    tftp_count += 1

                # SNMP v1/v2c (port 161)
                if dport == 161 or sport == 161:
                    snmp_count += 1

                # CoAP plaintext (port 5683)
                if dport == 5683 or sport == 5683:
                    coap_plain_count += 1

                # UPnP/SSDP (multicast to 239.255.255.250:1900)
                if pkt.haslayer(IP):
                    dst_ip = str(pkt[IP].dst)
                    if dst_ip == "239.255.255.250" and dport == 1900:
                        upnp_count += 1

                # Syslog (port 514)
                if dport == 514 or sport == 514:
                    syslog_count += 1

                # DNS plaintext (port 53)
                if dport == 53 or sport == 53:
                    dns_plain_count += 1

                # NTP (port 123)
                if dport == 123 or sport == 123:
                    ntp_count += 1

                # mDNS (multicast to 224.0.0.251:5353)
                if pkt.haslayer(IP):
                    dst_ip = str(pkt[IP].dst)
                    if dst_ip == "224.0.0.251" and dport == 5353:
                        mdns_count += 1

            # Also check TCP port 53 for DNS
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                if tcp.dport == 53 or tcp.sport == 53:
                    dns_plain_count += 1

        # Build findings from counts
        rules = [
            (telnet_count, "Telnet", 23, "Critical",
             "Telnet transmits credentials and commands in cleartext",
             "packets to/from port 23 with payload"),
            (tftp_count, "TFTP", 69, "Critical",
             "TFTP has no authentication or encryption; firmware images may be exfiltrated",
             "packets to/from port 69"),
            (ftp_count, "FTP", 21, "High",
             "FTP transmits credentials in cleartext; use SFTP or SCP instead",
             "packets to/from port 21 with payload"),
            (mqtt_plain_count, "MQTT (no TLS)", 1883, "High",
             "MQTT without TLS exposes IoT commands and telemetry in cleartext",
             "packets to/from port 1883"),
            (snmp_count, "SNMPv1/v2c", 161, "High",
             "SNMP v1/v2c uses community strings in cleartext; use SNMPv3",
             "packets to/from port 161"),
            (http_plain_count, "HTTP (no TLS)", 80, "Medium",
             "Plaintext HTTP exposes request/response data; use HTTPS",
             "packets to/from port 80 with payload"),
            (coap_plain_count, "CoAP (no DTLS)", 5683, "Medium",
             "CoAP without DTLS exposes IoT messages in cleartext",
             "packets to/from port 5683"),
            (upnp_count, "UPnP/SSDP", 1900, "Medium",
             "UPnP/SSDP can expose device capabilities and allow unauthorized control",
             "packets to 239.255.255.250:1900"),
            (syslog_count, "Syslog (UDP)", 514, "Medium",
             "UDP syslog transmits log data in cleartext; may leak sensitive info",
             "packets to/from port 514"),
            (tls_old_count, "TLS 1.0/1.1", 0, "Medium",
             "TLS 1.0/1.1 have known vulnerabilities (POODLE, BEAST); use TLS 1.2+",
             "ClientHello packets with version <= TLS 1.1"),
            (dns_plain_count, "DNS (no DoT/DoH)", 53, "Low",
             "Plaintext DNS exposes queried domains; consider DNS-over-TLS or DNS-over-HTTPS",
             "packets to/from port 53"),
            (ntp_count, "NTP (unauthenticated)", 123, "Low",
             "Unauthenticated NTP is susceptible to time-based attacks",
             "packets to/from port 123"),
            (mdns_count, "mDNS", 5353, "Info",
             "mDNS broadcasts device information on the local network",
             "packets to 224.0.0.251:5353"),
        ]

        for count, protocol, port, severity, description, evidence_suffix in rules:
            if count > 0:
                findings.append(InsecureProtocolFinding(
                    protocol=protocol,
                    port=port,
                    severity=severity,
                    description=description,
                    evidence=f"{count} {evidence_suffix}",
                    packet_count=count,
                ))

        return findings

    # ── DNS queries ─────────────────────────────────────────────────

    def _extract_dns_queries(self, packets: list) -> list[DnsQuery]:
        """Extract DNS queries and match responses to get resolved IPs."""
        # Map domain -> {query_type, resolved_ips}
        queries: dict[str, dict] = {}

        for pkt in packets:
            if not pkt.haslayer(DNS):
                continue

            dns = pkt[DNS]

            # Extract query info
            if pkt.haslayer(DNSQR):
                qr = pkt[DNSQR]
                domain = qr.qname.decode("utf-8", errors="replace").rstrip(".")
                qtype = _DNS_QTYPES.get(qr.qtype, str(qr.qtype))

                if domain not in queries:
                    queries[domain] = {
                        "query_type": qtype,
                        "resolved_ips": [],
                    }

            # Extract answers (responses)
            if dns.ancount and dns.ancount > 0:
                try:
                    # Walk the answer RRs
                    ans = dns.an
                    while ans:
                        if hasattr(ans, "rrname") and hasattr(ans, "rdata"):
                            resp_domain = ans.rrname.decode("utf-8", errors="replace").rstrip(".")
                            rdata = ans.rdata
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode("utf-8", errors="replace")
                            rdata = str(rdata)
                            if resp_domain in queries:
                                if rdata not in queries[resp_domain]["resolved_ips"]:
                                    queries[resp_domain]["resolved_ips"].append(rdata)
                        # Move to next RR in the chain
                        ans = ans.payload if hasattr(ans, "payload") and ans.payload and type(ans.payload) is not type(pkt.payload.__class__) else None
                        # Scapy chains RRs; use the underlayer pattern
                        if ans is not None and not hasattr(ans, "rrname"):
                            break
                except Exception:
                    # DNS answer parsing can be fragile; skip malformed
                    pass

        return [
            DnsQuery(
                domain=domain,
                query_type=info["query_type"],
                resolved_ips=info["resolved_ips"],
            )
            for domain, info in queries.items()
        ]

    # ── TLS metadata ────────────────────────────────────────────────

    def _extract_tls_metadata(self, packets: list) -> list[TlsInfo]:
        """Extract TLS ClientHello metadata (SNI, version, ciphers)."""
        if not HAS_TLS:
            logger.debug("Scapy TLS layer not available, skipping TLS metadata extraction")
            return []

        tls_sessions: list[TlsInfo] = []
        seen: set[tuple] = set()  # Deduplicate by (server, port, version)

        # TLS version number -> human-readable name
        version_names = {
            0x0300: "SSL 3.0",
            0x0301: "TLS 1.0",
            0x0302: "TLS 1.1",
            0x0303: "TLS 1.2",
            0x0304: "TLS 1.3",
        }

        for pkt in packets:
            try:
                if not pkt.haslayer(TLSClientHello):
                    continue

                hello = pkt[TLSClientHello]

                # Extract server name from SNI extension
                server_name = ""
                try:
                    # SNI is in the extensions list
                    if hasattr(hello, "ext") and hello.ext:
                        for ext in hello.ext:
                            # ServerName extension type = 0
                            if hasattr(ext, "type") and ext.type == 0:
                                if hasattr(ext, "servernames"):
                                    for sn in ext.servernames:
                                        if hasattr(sn, "servername"):
                                            name = sn.servername
                                            if isinstance(name, bytes):
                                                name = name.decode("utf-8", errors="replace")
                                            server_name = str(name)
                                            break
                except Exception:
                    pass

                # Extract TLS version
                version_num = getattr(hello, "version", 0x0303)
                version_str = version_names.get(version_num, f"0x{version_num:04x}")

                # Extract destination port
                dst_port = 443
                if pkt.haslayer(TCP):
                    dst_port = pkt[TCP].dport

                # Extract cipher suites
                cipher_list: list[str] = []
                try:
                    ciphers = getattr(hello, "ciphers", [])
                    if ciphers:
                        for c in ciphers:
                            cipher_list.append(f"0x{c:04x}" if isinstance(c, int) else str(c))
                except Exception:
                    pass

                # Deduplicate
                dedup_key = (server_name, dst_port, version_str)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                tls_sessions.append(TlsInfo(
                    server=server_name or f"(unknown:{dst_port})",
                    port=dst_port,
                    version=version_str,
                    cipher_suites=cipher_list[:20],  # Cap at 20 for readability
                ))

            except Exception as exc:
                logger.debug("Error parsing TLS packet: %s", exc)
                continue

        return tls_sessions
