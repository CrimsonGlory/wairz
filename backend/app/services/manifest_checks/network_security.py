"""Network-related manifest security checks.

MANIFEST-003 (usesCleartextTraffic) and MANIFEST-011 (Network Security
Configuration analysis, including trust anchors and certificate
pinning).  All network-related findings live here so that changes to
NSC parsing rules stay in one place.

The ``NetworkSecurityChecks`` class is composed by ``ManifestChecker``
and takes a reference to the outer scanner via ``__init__``.  NSC
helpers (``_extract_network_security_config_xml``,
``_analyse_nsc_base_config``, ``_analyse_nsc_domain_configs``,
``_analyse_nsc_debug_overrides``, ``_check_trust_anchors``,
``_check_pin_set``) are kept as methods on the same class for cohesion
with ``_check_network_security_config`` which drives them.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from app.services.manifest_checks._base import (
    ManifestFinding,
    _get_manifest_attr,
    _is_true,
)


class NetworkSecurityChecks:
    """Topic module for cleartext / NSC / trust-anchor / pinning checks."""

    def __init__(self, scanner: Any) -> None:
        self.scanner = scanner

    def _check_cleartext_traffic(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-003: android:usesCleartextTraffic=true check.

        MobSF base severity: **high** (CWE-319).
        """
        val = _get_manifest_attr(
            apk_obj, "application", "usesCleartextTraffic"
        )

        # Default is true for targetSdk < 28, false for >= 28
        target_sdk_str = apk_obj.get_target_sdk_version()
        try:
            target_sdk = int(target_sdk_str) if target_sdk_str else 0
        except (ValueError, TypeError):
            target_sdk = 0

        explicitly_true = _is_true(val)
        default_true = val is None and target_sdk < 28

        if not explicitly_true and not default_true:
            return []

        evidence_detail = (
            f"android:usesCleartextTraffic={val}"
            if val is not None
            else f"android:usesCleartextTraffic not set (defaults to true for targetSdk={target_sdk})"
        )

        # Confidence: high when explicitly set, medium when relying on default
        confidence = "high" if explicitly_true else "medium"

        return [
            ManifestFinding(
                check_id="MANIFEST-003",
                title="Application permits cleartext HTTP traffic",
                severity="high",
                description=(
                    "The application allows cleartext (non-TLS) network "
                    "traffic. This exposes data in transit to eavesdropping "
                    "and man-in-the-middle attacks. Applications should "
                    "enforce HTTPS for all network communication."
                ),
                evidence=evidence_detail,
                cwe_ids=["CWE-319"],
                confidence=confidence,
            )
        ]

    def _check_network_security_config(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-011: Network Security Configuration analysis.

        Parses the ``network_security_config.xml`` resource (if present)
        and flags:
        - Cleartext traffic allowed globally or per-domain
        - User-installed CA certificates trusted (enables MITM)
        - Missing or weak certificate pinning configuration
        - Overly permissive domain configurations
        - Pin expiration issues

        Reference:
        https://developer.android.com/training/articles/security-config
        """
        findings: list[ManifestFinding] = []

        # 1) Check if a network security config is referenced
        nsc_ref = _get_manifest_attr(
            apk_obj, "application", "networkSecurityConfig"
        )

        if nsc_ref is None:
            # No custom NSC — behaviour governed by usesCleartextTraffic
            # and targetSdk defaults. Absence is not a finding by itself
            # (covered by MANIFEST-003).
            return []

        # 2) Resolve and parse the XML resource
        nsc_xml = self._extract_network_security_config_xml(apk_obj, nsc_ref)
        if nsc_xml is None:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-011",
                    title="Network security config referenced but not found",
                    severity="info",
                    description=(
                        "The manifest declares android:networkSecurityConfig "
                        f"pointing to '{nsc_ref}', but the resource could not "
                        "be extracted from the APK. The runtime will use "
                        "default network security settings."
                    ),
                    evidence=f"android:networkSecurityConfig=\"{nsc_ref}\"",
                    cwe_ids=["CWE-295"],
                    confidence="medium",
                )
            )
            return findings

        try:
            root = ET.fromstring(nsc_xml)
        except ET.ParseError as exc:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-011",
                    title="Malformed network security config XML",
                    severity="low",
                    description=(
                        f"Failed to parse network_security_config: {exc}. "
                        "The runtime may ignore this config entirely, "
                        "falling back to default (less secure) behaviour."
                    ),
                    evidence=f"Parse error: {exc}",
                    cwe_ids=["CWE-436"],
                    confidence="medium",
                )
            )
            return findings

        # 3) Analyse <base-config>
        findings.extend(self._analyse_nsc_base_config(root))

        # 4) Analyse <domain-config> entries
        findings.extend(self._analyse_nsc_domain_configs(root))

        # 5) Analyse <debug-overrides>
        findings.extend(self._analyse_nsc_debug_overrides(root))

        return findings

    # -- NSC XML extraction -------------------------------------------------

    @staticmethod
    def _extract_network_security_config_xml(
        apk_obj: Any, nsc_ref: str
    ) -> str | None:
        """Attempt to extract the network security config XML content.

        The ``nsc_ref`` value is typically ``@xml/network_security_config``
        or a direct resource reference.  We try multiple strategies to
        locate the actual XML within the APK.
        """
        # Derive the likely filename from the resource reference
        # e.g. "@xml/network_security_config" → "res/xml/network_security_config.xml"
        if nsc_ref.startswith("@xml/"):
            res_name = nsc_ref[5:]  # strip "@xml/"
        elif nsc_ref.startswith("@"):
            # Could be @xml/foo or other resource type
            parts = nsc_ref.lstrip("@").split("/", 1)
            res_name = parts[-1] if len(parts) == 2 else nsc_ref
        else:
            # Could be a raw hex resource ID
            res_name = "network_security_config"

        candidate_paths = [
            f"res/xml/{res_name}.xml",
            f"r/x/{res_name}.xml",  # obfuscated resource paths
            "res/xml/network_security_config.xml",  # fallback common name
        ]

        # Try to get the file from the APK
        for path in candidate_paths:
            try:
                data = apk_obj.get_file(path)
                if data:
                    # Androguard may return bytes or string
                    if isinstance(data, bytes):
                        return data.decode("utf-8", errors="replace")
                    return str(data)
            except Exception:
                continue

        # Try via Androguard's AXML parser for compiled XML
        try:
            from androguard.core.axml import AXMLPrinter

            for path in candidate_paths:
                try:
                    data = apk_obj.get_file(path)
                    if data:
                        axml = AXMLPrinter(data)
                        xml_str = axml.get_xml()
                        if isinstance(xml_str, bytes):
                            return xml_str.decode("utf-8", errors="replace")
                        return str(xml_str)
                except Exception:
                    continue
        except ImportError:
            pass

        return None

    # -- NSC base-config analysis -------------------------------------------

    def _analyse_nsc_base_config(
        self, root: ET.Element
    ) -> list[ManifestFinding]:
        """Analyse the <base-config> element of a network security config."""
        findings: list[ManifestFinding] = []

        base_config = root.find("base-config")
        if base_config is None:
            return findings

        # Check cleartextTrafficPermitted on base-config
        cleartext = base_config.get("cleartextTrafficPermitted", "").lower()
        if cleartext == "true":
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-011",
                    title="Network security config allows cleartext traffic globally",
                    severity="high",
                    description=(
                        "The <base-config> element explicitly permits "
                        "cleartext (HTTP) traffic for all domains. This "
                        "exposes all network communication to eavesdropping "
                        "and modification. Even when individual domain "
                        "configs override this, the broad default is risky "
                        "as new domains added to the app will inherit "
                        "cleartext permission."
                    ),
                    evidence='<base-config cleartextTrafficPermitted="true">',
                    cwe_ids=["CWE-319"],
                )
            )

        # Check trust-anchors in base-config
        findings.extend(
            self._check_trust_anchors(base_config, context="base-config")
        )

        return findings

    # -- NSC domain-config analysis -----------------------------------------

    def _analyse_nsc_domain_configs(
        self, root: ET.Element
    ) -> list[ManifestFinding]:
        """Analyse all <domain-config> elements."""
        findings: list[ManifestFinding] = []

        for domain_config in root.findall("domain-config"):
            domains = [
                d.text.strip() if d.text else "*"
                for d in domain_config.findall("domain")
            ]
            domain_str = ", ".join(domains) if domains else "(no domains)"
            include_subdomains = any(
                d.get("includeSubdomains", "").lower() == "true"
                for d in domain_config.findall("domain")
            )
            subdomain_note = " (including subdomains)" if include_subdomains else ""

            # a) Cleartext traffic per-domain
            cleartext = domain_config.get(
                "cleartextTrafficPermitted", ""
            ).lower()
            if cleartext == "true":
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-011",
                        title="Cleartext traffic permitted for specific domains",
                        severity="medium",
                        description=(
                            f"The network security config allows cleartext "
                            f"HTTP traffic for: {domain_str}{subdomain_note}. "
                            f"This may be intentional for local development "
                            f"or legacy services, but exposes communication "
                            f"with these domains to interception."
                        ),
                        evidence=(
                            f'<domain-config cleartextTrafficPermitted="true"> '
                            f"domains: {domain_str}"
                        ),
                        cwe_ids=["CWE-319"],
                        confidence="high",
                    )
                )

            # Wildcard / overly broad domains
            for d in domain_config.findall("domain"):
                dtext = (d.text or "").strip()
                inc_sub = d.get("includeSubdomains", "").lower() == "true"
                # Flag very broad domains like bare TLDs with includeSubdomains
                if inc_sub and dtext.count(".") == 0 and dtext:
                    findings.append(
                        ManifestFinding(
                            check_id="MANIFEST-011",
                            title="Overly broad domain in network security config",
                            severity="high",
                            description=(
                                f"The domain '{dtext}' with "
                                f"includeSubdomains=\"true\" matches an "
                                f"extremely broad set of hostnames. This "
                                f"likely captures unintended traffic."
                            ),
                            evidence=f'<domain includeSubdomains="true">{dtext}</domain>',
                            cwe_ids=["CWE-183"],
                            confidence="medium",
                        )
                    )

            # b) Trust anchors per-domain
            findings.extend(
                self._check_trust_anchors(
                    domain_config, context=f"domain-config ({domain_str})"
                )
            )

            # c) Pin-set analysis per-domain
            findings.extend(
                self._check_pin_set(domain_config, domain_str)
            )

        return findings

    # -- NSC debug-overrides analysis ---------------------------------------

    def _analyse_nsc_debug_overrides(
        self, root: ET.Element
    ) -> list[ManifestFinding]:
        """Analyse the <debug-overrides> element."""
        findings: list[ManifestFinding] = []

        debug_overrides = root.find("debug-overrides")
        if debug_overrides is None:
            return findings

        # debug-overrides only activate when android:debuggable=true,
        # but their presence is still worth noting

        trust_anchors = debug_overrides.find("trust-anchors")
        if trust_anchors is not None:
            user_certs = [
                c for c in trust_anchors.findall("certificates")
                if c.get("src", "").lower() == "user"
            ]
            if user_certs:
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-011",
                        title="Debug overrides trust user-installed certificates",
                        severity="info",
                        description=(
                            "The <debug-overrides> section trusts "
                            "user-installed CA certificates. This is common "
                            "for development/debugging with proxy tools "
                            "(Burp Suite, mitmproxy) and only activates in "
                            "debuggable builds. Verify that release builds "
                            "do NOT set android:debuggable=true."
                        ),
                        evidence='<debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides>',
                        cwe_ids=["CWE-295"],
                        confidence="low",
                    )
                )

        return findings

    # -- NSC shared helpers -------------------------------------------------

    @staticmethod
    def _check_trust_anchors(
        config_element: ET.Element, *, context: str
    ) -> list[ManifestFinding]:
        """Check <trust-anchors> within a config element for user cert trust."""
        findings: list[ManifestFinding] = []

        trust_anchors = config_element.find("trust-anchors")
        if trust_anchors is None:
            return findings

        for cert_elem in trust_anchors.findall("certificates"):
            src = cert_elem.get("src", "").lower()

            if src == "user":
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-011",
                        title=f"User-installed CA certificates trusted ({context})",
                        severity="high",
                        description=(
                            f"The {context} trusts user-installed CA "
                            f"certificates. This allows any CA certificate "
                            f"installed by the user (or MDM) to intercept "
                            f"TLS traffic. An attacker with physical device "
                            f"access or MDM control can perform MitM attacks. "
                            f"Production apps should only trust system CAs "
                            f"unless there is a specific enterprise requirement."
                        ),
                        evidence=(
                            f"<trust-anchors><certificates src=\"user\"/> "
                            f"in {context}"
                        ),
                        cwe_ids=["CWE-295"],
                        confidence="high",
                    )
                )

            elif src not in ("system", ""):
                # Custom CA file — note it but don't flag as high
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-011",
                        title=f"Custom CA certificate bundled ({context})",
                        severity="info",
                        description=(
                            f"The {context} includes a custom CA certificate "
                            f"file (src=\"{cert_elem.get('src')}\"). This is "
                            f"used for certificate pinning or connecting to "
                            f"servers with private CAs. Ensure the bundled "
                            f"certificate corresponds to a legitimate CA and "
                            f"has not been compromised."
                        ),
                        evidence=(
                            f"<certificates src=\"{cert_elem.get('src')}\"/> "
                            f"in {context}"
                        ),
                        cwe_ids=["CWE-295"],
                        confidence="low",
                    )
                )

            overridePins = cert_elem.get("overridePins", "").lower()
            if overridePins == "true":
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-011",
                        title=f"Certificate pinning bypass enabled ({context})",
                        severity="high",
                        description=(
                            f"The {context} sets overridePins=\"true\" on a "
                            f"trust anchor. This means the trusted CA can "
                            f"bypass certificate pinning, effectively "
                            f"defeating the protection pinning provides. "
                            f"An attacker who compromises this CA (or installs "
                            f"their own CA when src=\"user\") can intercept "
                            f"pinned connections."
                        ),
                        evidence=(
                            f"<certificates overridePins=\"true\"/> in {context}"
                        ),
                        cwe_ids=["CWE-295"],
                        confidence="high",
                    )
                )

        return findings

    @staticmethod
    def _check_pin_set(
        domain_config: ET.Element, domain_str: str
    ) -> list[ManifestFinding]:
        """Analyse <pin-set> within a domain-config element."""
        findings: list[ManifestFinding] = []

        pin_set = domain_config.find("pin-set")
        if pin_set is None:
            # No pinning configured — not a finding by itself (many apps
            # don't pin), but absence is notable for high-security contexts
            return findings

        pins = pin_set.findall("pin")
        expiration = pin_set.get("expiration", "")

        if not pins:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-011",
                    title=f"Empty pin-set for {domain_str}",
                    severity="medium",
                    description=(
                        f"A <pin-set> is declared for {domain_str} but "
                        f"contains no <pin> entries. This is effectively a "
                        f"no-op — the app declares intent to pin but has no "
                        f"actual pins, providing no additional security."
                    ),
                    evidence=f"<pin-set> with 0 pins for {domain_str}",
                    cwe_ids=["CWE-295"],
                    confidence="high",
                )
            )
            return findings

        # Check pin algorithms
        weak_pins = []
        for pin in pins:
            digest = pin.get("digest", "").upper()
            if digest and digest != "SHA-256":
                weak_pins.append(digest)

        if weak_pins:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-011",
                    title=f"Weak pin digest algorithm for {domain_str}",
                    severity="medium",
                    description=(
                        f"Certificate pins for {domain_str} use digest "
                        f"algorithm(s): {', '.join(set(weak_pins))}. "
                        f"SHA-256 is the recommended minimum. Weaker "
                        f"algorithms may be vulnerable to collision attacks."
                    ),
                    evidence=(
                        f"Pin digests: {', '.join(set(weak_pins))} "
                        f"for {domain_str}"
                    ),
                    cwe_ids=["CWE-328"],
                    confidence="high",
                )
            )

        # Only one pin — no backup pin
        if len(pins) < 2:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-011",
                    title=f"Single certificate pin without backup for {domain_str}",
                    severity="medium",
                    description=(
                        f"Only one certificate pin is configured for "
                        f"{domain_str}. Google recommends at least one "
                        f"backup pin to avoid bricking the app if the "
                        f"primary pinned certificate is rotated. Without "
                        f"a backup pin, a certificate rotation will cause "
                        f"complete connection failure."
                    ),
                    evidence=f"1 pin configured for {domain_str}",
                    cwe_ids=["CWE-295"],
                    confidence="medium",
                )
            )

        # Check expiration
        if expiration:
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-011",
                    title=f"Certificate pin expiration set for {domain_str}",
                    severity="info",
                    description=(
                        f"The pin-set for {domain_str} has an expiration "
                        f"date of {expiration}. After this date, pinning "
                        f"is disabled and the app falls back to normal "
                        f"certificate validation. Verify the expiration "
                        f"date is intentional and that pins will be "
                        f"refreshed before expiry via app updates."
                    ),
                    evidence=(
                        f'<pin-set expiration="{expiration}"> '
                        f"for {domain_str}"
                    ),
                    cwe_ids=["CWE-298"],
                    confidence="low",
                )
            )

        return findings
