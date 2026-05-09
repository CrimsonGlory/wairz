"""Component-level manifest security checks.

Covers component exposure, task-stack hijacking, and intent-scheme
issues.  Individual checks:

- MANIFEST-006 _check_exported_components: exported components without
  permission protection.
- MANIFEST-008 _check_strandhogg_v1: StrandHogg 1.0 task-affinity
  hijacking.
- MANIFEST-009 _check_strandhogg_v2: StrandHogg 2.0 launchMode-based
  overlay attacks.
- MANIFEST-010 _check_app_links: unverified http/https and custom URL
  scheme deep links.
- MANIFEST-012 _check_allow_task_reparenting: activity reparenting
  hijack enabler.
- MANIFEST-013 _check_implicit_intent_hijacking: exported services /
  receivers with intent filters but no permission.
- MANIFEST-017 _check_intent_scheme_hijacking: insecure
  file://content://javascript://data: URI schemes on exported
  components.
"""

from __future__ import annotations

import logging
from typing import Any

from app.services.manifest_checks._base import (
    _NS_ANDROID,
    ManifestFinding,
)

logger = logging.getLogger(__name__)


class ComponentChecks:
    """Topic module for component / task / intent-filter manifest checks."""

    # Component tags scanned by _check_exported_components (MANIFEST-006).
    _COMPONENT_TAGS: list[tuple[str, str]] = [
        ("activity", "Activity"),
        ("activity-alias", "Activity-alias"),
        ("service", "Service"),
        ("receiver", "Broadcast Receiver"),
        ("provider", "Content Provider"),
    ]

    # launchMode values that enable StrandHogg 1.0/2.0 when combined with
    # enabling conditions.  Shared between _check_strandhogg_v1 and
    # _check_strandhogg_v2.
    _STRANDHOGG_V1_LAUNCH_MODES: set[str] = {
        "singletask",
        "singleinstance",
    }

    # Schemes that are security-sensitive in intent filters (MANIFEST-017).
    _SENSITIVE_SCHEMES: dict[str, tuple[str, str]] = {
        "file": (
            "File URI scheme allows access to local files",
            "CWE-94",
        ),
        "content": (
            "Content URI scheme may expose content provider data",
            "CWE-200",
        ),
        "javascript": (
            "JavaScript URI scheme enables code injection in WebViews",
            "CWE-94",
        ),
        "data": (
            "Data URI scheme may enable content injection",
            "CWE-94",
        ),
        "intent": (
            "Intent URI scheme enables intent-scheme hijacking where "
            "a crafted URL can redirect the user to an attacker-chosen "
            "activity with arbitrary parameters",
            "CWE-926",
        ),
    }

    def __init__(self, scanner: Any) -> None:
        self.scanner = scanner

    # ------------------------------------------------------------------
    # MANIFEST-006: Exported components
    # ------------------------------------------------------------------

    def _check_exported_components(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-006: Exported components without permission protection.

        MobSF base severity: **high** for ≥5 components, **medium** for 2–4,
        **low** for 1.

        An exported component that declares no ``android:permission`` can be
        invoked by any app on the device, potentially leaking data or
        triggering privileged behaviour.

        Export is explicit (``android:exported="true"``) or implicit when
        the component has an ``<intent-filter>`` *and* targetSdk < 31
        (in targetSdk >= 31, exported must be explicit).
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception as exc:
            logger.warning("Failed to parse manifest XML: %s", exc)
            return findings

        if manifest_xml is None:
            return findings

        # Determine targetSdk to know default export behaviour
        target_sdk_str = apk_obj.get_target_sdk_version()
        try:
            target_sdk = int(target_sdk_str) if target_sdk_str else 0
        except (ValueError, TypeError):
            target_sdk = 0

        ns = _NS_ANDROID
        main_activity = apk_obj.get_main_activity()
        exported_unprotected: list[dict[str, str]] = []

        for tag_name, component_type in self._COMPONENT_TAGS:
            elements = manifest_xml.findall(f".//{tag_name}")
            for elem in elements:
                comp_name = (
                    elem.get(f"{{{ns}}}name")
                    or elem.get("name")
                    or "unknown"
                )

                # Determine if exported
                exported_attr = elem.get(f"{{{ns}}}exported") or elem.get("exported")
                has_intent_filter = len(elem.findall("intent-filter")) > 0

                if exported_attr is not None:
                    is_exported = exported_attr.lower() in ("true", "0xffffffff", "-1")
                else:
                    # Implicit export: components with intent-filters are
                    # exported by default when targetSdk < 31
                    if has_intent_filter and target_sdk < 31:
                        is_exported = True
                    elif tag_name == "provider":
                        # Content providers are exported by default when
                        # targetSdk < 17 (API 17 changed the default)
                        is_exported = target_sdk < 17
                    else:
                        is_exported = False

                if not is_exported:
                    continue

                # Check for permission protection on the component
                perm = elem.get(f"{{{ns}}}permission") or elem.get("permission")

                # For providers, also check readPermission / writePermission
                if tag_name == "provider":
                    read_perm = (
                        elem.get(f"{{{ns}}}readPermission")
                        or elem.get("readPermission")
                    )
                    write_perm = (
                        elem.get(f"{{{ns}}}writePermission")
                        or elem.get("writePermission")
                    )
                    if perm or (read_perm and write_perm):
                        continue
                elif perm:
                    continue

                # Skip the main launcher activity — it must be exported
                # and is inherently user-facing (not a meaningful finding)
                if comp_name == main_activity:
                    continue

                exported_unprotected.append({
                    "component": comp_name,
                    "type": component_type,
                    "has_intent_filter": str(has_intent_filter),
                    "explicit_export": str(exported_attr is not None),
                })

        if not exported_unprotected:
            return findings

        # Build evidence string
        evidence_lines = []
        for comp in exported_unprotected:
            export_note = (
                "explicitly exported"
                if comp["explicit_export"] == "True"
                else "implicitly exported (has intent-filter)"
            )
            evidence_lines.append(
                f"  {comp['type']}: {comp['component']} ({export_note})"
            )
        evidence = (
            f"{len(exported_unprotected)} exported component(s) without "
            f"permission:\n" + "\n".join(evidence_lines)
        )

        # Severity scales with exposed component count (MobSF baseline).
        # Firmware context bump (+1) is applied uniformly in
        # scan_manifest_security() for priv-app / platform-signed APKs.
        if len(exported_unprotected) >= 5:
            severity = "high"
        elif len(exported_unprotected) >= 2:
            severity = "medium"
        else:
            severity = "low"

        # Confidence: high when all components are explicitly exported,
        # medium when any are implicitly exported via intent-filter default
        all_explicit = all(
            c["explicit_export"] == "True" for c in exported_unprotected
        )
        confidence = "high" if all_explicit else "medium"

        findings.append(
            ManifestFinding(
                check_id="MANIFEST-006",
                title="Exported components without permission protection",
                severity=severity,
                description=(
                    "The application exports components that are accessible "
                    "to any other app on the device without requiring a "
                    "permission. Exported activities can be launched, exported "
                    "services can be bound to, exported receivers can receive "
                    "broadcasts, and exported providers can be queried — all "
                    "by third-party apps. This may allow unauthorized access "
                    "to sensitive functionality or data."
                ),
                evidence=evidence,
                cwe_ids=["CWE-926"],
                confidence=confidence,
            )
        )

        return findings

    # ------------------------------------------------------------------
    # MANIFEST-008: StrandHogg 1.0
    # ------------------------------------------------------------------

    def _check_strandhogg_v1(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-008: StrandHogg 1.0 task hijacking via taskAffinity.

        MobSF base severity: **high** (CWE-1021).

        StrandHogg 1.0 (CVE-2020-0096) exploits the Android task/activity
        stack by combining a non-default ``taskAffinity`` with either
        ``allowTaskReparenting=true`` or a ``launchMode`` of
        ``singleTask``/``singleInstance``.  A malicious app can inject its
        activity into the victim app's task stack, presenting a phishing
        UI while the user believes they are interacting with the
        legitimate application.

        An empty ``taskAffinity=""`` is also suspicious: it opts the
        activity out of the default task grouping, which may be intentional
        but is a prerequisite for reparenting attacks.
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception as exc:
            logger.warning("Failed to parse manifest XML: %s", exc)
            return findings

        if manifest_xml is None:
            return findings

        ns = _NS_ANDROID
        package = apk_obj.get_package() or ""
        vulnerable_activities: list[dict[str, str]] = []

        for elem in manifest_xml.findall(".//activity"):
            activity_name = (
                elem.get(f"{{{ns}}}name") or elem.get("name") or "unknown"
            )

            # --- taskAffinity ---
            task_affinity = (
                elem.get(f"{{{ns}}}taskAffinity")
                or elem.get("taskAffinity")
            )
            # Default taskAffinity equals the package name; only flag
            # activities that deviate from the default.
            if task_affinity is None:
                continue  # uses default (package name) — not vulnerable
            # Empty string or a different package's affinity are suspicious
            affinity_is_empty = task_affinity.strip() == ""
            affinity_is_foreign = (
                not affinity_is_empty and task_affinity != package
            )
            if not affinity_is_empty and not affinity_is_foreign:
                continue  # matches own package — safe

            # --- Check for enabling conditions ---
            allow_reparenting = elem.get(
                f"{{{ns}}}allowTaskReparenting"
            ) or elem.get("allowTaskReparenting")
            reparenting_enabled = (
                allow_reparenting is not None
                and allow_reparenting.lower() in ("true", "0xffffffff", "-1")
            )

            launch_mode = (
                elem.get(f"{{{ns}}}launchMode") or elem.get("launchMode")
            )
            risky_launch_mode = (
                launch_mode is not None
                and launch_mode.strip().lower() in self._STRANDHOGG_V1_LAUNCH_MODES
            )

            if not reparenting_enabled and not risky_launch_mode:
                # Non-default affinity alone is informational — only flag
                # when combined with an enabling condition.
                continue

            reasons: list[str] = []
            if affinity_is_empty:
                reasons.append('taskAffinity=""')
            else:
                reasons.append(f'taskAffinity="{task_affinity}"')
            if reparenting_enabled:
                reasons.append("allowTaskReparenting=true")
            if risky_launch_mode:
                reasons.append(f"launchMode={launch_mode}")

            vulnerable_activities.append({
                "activity": activity_name,
                "detail": ", ".join(reasons),
            })

        if not vulnerable_activities:
            return findings

        evidence_lines = [
            f"  {va['activity']}: {va['detail']}"
            for va in vulnerable_activities
        ]
        evidence = (
            f"{len(vulnerable_activities)} activity(ies) vulnerable to "
            f"StrandHogg 1.0 task hijacking:\n"
            + "\n".join(evidence_lines)
        )

        findings.append(
            ManifestFinding(
                check_id="MANIFEST-008",
                title="StrandHogg 1.0 task hijacking vulnerability",
                severity="high",
                description=(
                    "One or more activities declare a non-default "
                    "taskAffinity combined with allowTaskReparenting=true "
                    "or a launchMode of singleTask/singleInstance. This "
                    "configuration allows a malicious app to hijack the "
                    "application's task stack by inserting its own activity, "
                    "enabling phishing attacks that impersonate the "
                    "legitimate app's UI (StrandHogg 1.0 / CVE-2020-0096). "
                    "Users believe they are interacting with the real app "
                    "while providing credentials or sensitive data to the "
                    "attacker."
                ),
                evidence=evidence,
                cwe_ids=["CWE-1021"],
                confidence="medium",
            )
        )

        return findings

    # ------------------------------------------------------------------
    # MANIFEST-009: StrandHogg 2.0
    # ------------------------------------------------------------------

    def _check_strandhogg_v2(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-009: StrandHogg 2.0 task hijacking via launchMode.

        MobSF base severity: **high** (CWE-1021), reduced to **low** when
        ``minSdk >= 29`` (OS-level mitigation present).

        StrandHogg 2.0 (CVE-2020-0096) is a privilege-escalation variant
        that does *not* require a specific taskAffinity.  Activities with
        ``launchMode="singleInstance"`` or ``"singleTask"`` create a
        separate task back-stack entry.  On Android < 10 (API 29) the
        system does not verify the calling app's identity, allowing any
        app to invoke these activities and position a malicious overlay
        on top.

        This check flags activities that use these launch modes and are
        also exported (reachable by other apps), especially when the
        app's minSdk is below 29 (where the OS-level fix was applied).
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception as exc:
            logger.warning("Failed to parse manifest XML: %s", exc)
            return findings

        if manifest_xml is None:
            return findings

        ns = _NS_ANDROID

        # Check minSdk — Android 10 (API 29) patched the OS-level vuln
        min_sdk_str = apk_obj.get_min_sdk_version()
        try:
            min_sdk = int(min_sdk_str) if min_sdk_str else 0
        except (ValueError, TypeError):
            min_sdk = 0

        target_sdk_str = apk_obj.get_target_sdk_version()
        try:
            target_sdk = int(target_sdk_str) if target_sdk_str else 0
        except (ValueError, TypeError):
            target_sdk = 0

        main_activity = apk_obj.get_main_activity()
        risky_activities: list[dict[str, str]] = []

        for elem in manifest_xml.findall(".//activity"):
            activity_name = (
                elem.get(f"{{{ns}}}name") or elem.get("name") or "unknown"
            )

            launch_mode = (
                elem.get(f"{{{ns}}}launchMode") or elem.get("launchMode")
            )
            if (
                launch_mode is None
                or launch_mode.strip().lower()
                not in self._STRANDHOGG_V1_LAUNCH_MODES  # same risky set
            ):
                continue

            # Check if the activity is exported
            exported_attr = (
                elem.get(f"{{{ns}}}exported") or elem.get("exported")
            )
            has_intent_filter = len(elem.findall("intent-filter")) > 0

            if exported_attr is not None:
                is_exported = exported_attr.lower() in (
                    "true", "0xffffffff", "-1"
                )
            else:
                # Implicit export via intent-filter for targetSdk < 31
                is_exported = has_intent_filter and target_sdk < 31

            if not is_exported:
                continue

            # Skip main activity — it must be exported and is always
            # singleTask in many apps for a good reason
            if activity_name == main_activity:
                continue

            risky_activities.append({
                "activity": activity_name,
                "launchMode": launch_mode.strip(),
                "exported": "explicit" if exported_attr else "implicit",
            })

        if not risky_activities:
            return findings

        evidence_lines = [
            f"  {ra['activity']}: launchMode={ra['launchMode']}, "
            f"exported ({ra['exported']})"
            for ra in risky_activities
        ]
        evidence = (
            f"{len(risky_activities)} exported activity(ies) with risky "
            f"launchMode:\n" + "\n".join(evidence_lines)
        )

        # Severity depends on whether the OS-level fix applies.
        # Firmware context bump (+1) is applied uniformly in
        # scan_manifest_security() for priv-app / platform-signed APKs.
        if min_sdk >= 29:
            # OS patched at API 29 — lower risk
            severity = "low"
            confidence = "low"  # OS-level mitigation makes exploitation unlikely
            evidence += (
                f"\nNote: minSdk={min_sdk} (>= 29) — OS-level mitigation "
                "present, but app-level risk remains for overlay attacks."
            )
        else:
            severity = "high"
            confidence = "medium"  # Pattern match; exploitability depends on context

        findings.append(
            ManifestFinding(
                check_id="MANIFEST-009",
                title="StrandHogg 2.0 task hijacking risk",
                severity=severity,
                description=(
                    "Exported activities with launchMode singleTask or "
                    "singleInstance create separate task back-stack entries "
                    "that can be exploited by malicious apps to overlay "
                    "phishing UIs (StrandHogg 2.0 / CVE-2020-0096). On "
                    "Android < 10 (API 29) the OS does not verify the "
                    "calling app's identity, enabling seamless UI hijacking. "
                    "Even on patched OS versions, exported activities with "
                    "these launch modes present a broader attack surface."
                ),
                evidence=evidence,
                cwe_ids=["CWE-1021"],
                confidence=confidence,
            )
        )

        return findings

    # ------------------------------------------------------------------
    # MANIFEST-010: App Links / Browsable intent validation
    # ------------------------------------------------------------------

    def _check_app_links(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-010: Browsable activities and Android App Links validation.

        Activities with ``<intent-filter>`` containing
        ``<category android:name="android.intent.category.BROWSABLE"/>``
        and a ``<data>`` element with ``android:scheme="http"`` or
        ``"https"`` handle web URLs.  Without ``android:autoVerify="true"``
        on the intent-filter, the system shows a disambiguation dialog
        instead of sending the URL directly to the app, and any app can
        register the same scheme+host, enabling phishing via intent
        interception.

        This check flags:
        1. Browsable activities handling http/https without autoVerify
        2. Browsable activities using custom schemes (potential deep link
           hijacking since custom schemes have no ownership verification)
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception as exc:
            logger.warning("Failed to parse manifest XML: %s", exc)
            return findings

        if manifest_xml is None:
            return findings

        ns = _NS_ANDROID
        unverified_http_links: list[dict[str, str]] = []
        custom_scheme_links: list[dict[str, str]] = []

        _WEB_SCHEMES = {"http", "https"}

        for elem in manifest_xml.findall(".//activity"):
            activity_name = (
                elem.get(f"{{{ns}}}name") or elem.get("name") or "unknown"
            )

            for intent_filter in elem.findall("intent-filter"):
                # Check for BROWSABLE category
                categories = intent_filter.findall("category")
                is_browsable = any(
                    (
                        cat.get(f"{{{ns}}}name") or cat.get("name") or ""
                    ) == "android.intent.category.BROWSABLE"
                    for cat in categories
                )
                if not is_browsable:
                    continue

                # Check for VIEW action (required for app links)
                actions = intent_filter.findall("action")
                has_view_action = any(
                    (
                        act.get(f"{{{ns}}}name") or act.get("name") or ""
                    ) == "android.intent.action.VIEW"
                    for act in actions
                )

                # Check autoVerify on the intent-filter
                auto_verify = (
                    intent_filter.get(f"{{{ns}}}autoVerify")
                    or intent_filter.get("autoVerify")
                )
                is_auto_verified = (
                    auto_verify is not None
                    and auto_verify.lower() in ("true", "0xffffffff", "-1")
                )

                # Examine <data> elements for schemes and hosts
                data_elements = intent_filter.findall("data")
                schemes: set[str] = set()
                hosts: set[str] = set()

                for data_elem in data_elements:
                    scheme = (
                        data_elem.get(f"{{{ns}}}scheme")
                        or data_elem.get("scheme")
                    )
                    host = (
                        data_elem.get(f"{{{ns}}}host")
                        or data_elem.get("host")
                    )
                    if scheme:
                        schemes.add(scheme.lower())
                    if host:
                        hosts.add(host)

                web_schemes = schemes & _WEB_SCHEMES
                custom_schemes = schemes - _WEB_SCHEMES - {"", "content", "file"}

                # Flag 1: http/https without autoVerify
                if web_schemes and has_view_action and not is_auto_verified:
                    host_str = ", ".join(sorted(hosts)) if hosts else "(any host)"
                    unverified_http_links.append({
                        "activity": activity_name,
                        "schemes": ", ".join(sorted(web_schemes)),
                        "hosts": host_str,
                    })

                # Flag 2: Custom schemes (no verification mechanism exists)
                if custom_schemes and has_view_action:
                    custom_scheme_links.append({
                        "activity": activity_name,
                        "schemes": ", ".join(sorted(custom_schemes)),
                        "hosts": ", ".join(sorted(hosts)) if hosts else "(any)",
                    })

        # Build findings for unverified HTTP/HTTPS app links
        if unverified_http_links:
            evidence_lines = [
                f"  {link['activity']}: {link['schemes']}://{link['hosts']}"
                for link in unverified_http_links
            ]
            evidence = (
                f"{len(unverified_http_links)} browsable activity(ies) "
                f"handling web URLs without autoVerify:\n"
                + "\n".join(evidence_lines)
            )

            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-010",
                    title="Unverified App Links (http/https without autoVerify)",
                    severity="medium",
                    description=(
                        "Activities handle http/https URLs via browsable "
                        "intent filters but do not set autoVerify=\"true\". "
                        "Without Digital Asset Links verification, any app "
                        "can register the same URL patterns and intercept "
                        "links intended for this application. This enables "
                        "phishing attacks where a malicious app captures "
                        "login URLs, OAuth callbacks, or password reset "
                        "links. The system will show a disambiguation dialog "
                        "instead of routing directly to this app, degrading "
                        "user experience and security."
                    ),
                    evidence=evidence,
                    cwe_ids=["CWE-939"],
                    confidence="medium",
                )
            )

        # Build findings for custom scheme deep links
        if custom_scheme_links:
            evidence_lines = [
                f"  {link['activity']}: {link['schemes']}:// "
                f"(hosts: {link['hosts']})"
                for link in custom_scheme_links
            ]
            evidence = (
                f"{len(custom_scheme_links)} activity(ies) using custom "
                f"URL schemes:\n" + "\n".join(evidence_lines)
            )

            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-010",
                    title="Custom URL scheme deep links (no verification possible)",
                    severity="low",
                    description=(
                        "Activities register custom URL schemes for deep "
                        "linking. Unlike http/https App Links, custom "
                        "schemes (e.g. myapp://) have no ownership "
                        "verification mechanism — any app can register the "
                        "same scheme. If the app uses custom scheme deep "
                        "links for sensitive operations (OAuth callbacks, "
                        "payment confirmations, etc.), a malicious app could "
                        "register the same scheme and intercept these intents."
                    ),
                    evidence=evidence,
                    cwe_ids=["CWE-939"],
                    confidence="low",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # MANIFEST-012: allowTaskReparenting
    # ------------------------------------------------------------------

    def _check_allow_task_reparenting(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-012: allowTaskReparenting=true enables task hijacking.

        When ``android:allowTaskReparenting="true"`` is set on an activity,
        Android may move that activity from the task that started it into
        the task of the app whose affinity it shares when that app next
        comes to the foreground.  A malicious app can exploit this to
        steal sensitive activities into its own task stack, enabling UI
        spoofing or data theft (CWE-926).
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception:
            return findings

        if manifest_xml is None:
            return findings

        ns = _NS_ANDROID

        # Check application-level default
        app_elem = manifest_xml.find(".//application")
        app_level_reparenting = False
        if app_elem is not None:
            val = app_elem.get(f"{{{ns}}}allowTaskReparenting") or app_elem.get(
                "allowTaskReparenting"
            )
            if val and val.lower() in ("true", "0xffffffff", "-1"):
                app_level_reparenting = True

        vulnerable_activities: list[str] = []

        for activity in manifest_xml.findall(".//activity"):
            name = (
                activity.get(f"{{{ns}}}name")
                or activity.get("name")
                or "unknown"
            )
            val = activity.get(f"{{{ns}}}allowTaskReparenting") or activity.get(
                "allowTaskReparenting"
            )
            # Activity inherits from application if not explicitly set
            if val is not None:
                activity_reparenting = val.lower() in ("true", "0xffffffff", "-1")
            else:
                activity_reparenting = app_level_reparenting

            if activity_reparenting:
                vulnerable_activities.append(name)

        if app_level_reparenting and not vulnerable_activities:
            # Application-level flag but no activities found — still flag it
            findings.append(
                ManifestFinding(
                    check_id="MANIFEST-012",
                    title="Application-level allowTaskReparenting enabled",
                    severity="medium",
                    description=(
                        "The <application> element sets "
                        "android:allowTaskReparenting=\"true\", which allows "
                        "all activities to be moved between task stacks. "
                        "A malicious app can hijack activities into its own "
                        "task by matching task affinity, enabling UI spoofing "
                        "or data interception."
                    ),
                    evidence='android:allowTaskReparenting="true" on <application>',
                    cwe_ids=["CWE-926"],
                    confidence="high",
                )
            )
        elif vulnerable_activities:
            for name in vulnerable_activities[:20]:
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-012",
                        title=f"Activity allows task reparenting: {name}",
                        severity="medium",
                        description=(
                            f"Activity {name} has "
                            f"android:allowTaskReparenting=\"true\" (directly "
                            f"or inherited from <application>). This allows "
                            f"the activity to be moved to a different task "
                            f"stack at runtime, which a malicious app can "
                            f"exploit for UI spoofing or data theft."
                        ),
                        evidence=f'allowTaskReparenting="true" on {name}',
                        cwe_ids=["CWE-926"],
                        confidence="high",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # MANIFEST-013: Implicit intent hijacking
    # ------------------------------------------------------------------

    def _check_implicit_intent_hijacking(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-013: Exported components with intent filters vulnerable to hijacking.

        When a component declares an ``<intent-filter>``, Android
        implicitly marks it as exported (pre-API 31).  If such a component
        handles sensitive actions without requiring a permission, any app
        on the device can send intents to it, potentially intercepting or
        injecting data (CWE-927).

        This check focuses on **services** and **broadcast receivers**
        with intent filters but no permission protection — activities are
        already covered by MANIFEST-006 (exported components).
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception:
            return findings

        if manifest_xml is None:
            return findings

        ns = _NS_ANDROID

        for tag in ("service", "receiver"):
            for elem in manifest_xml.findall(f".//{tag}"):
                intent_filters = elem.findall("intent-filter")
                if not intent_filters:
                    continue

                name = (
                    elem.get(f"{{{ns}}}name")
                    or elem.get("name")
                    or "unknown"
                )

                # Check explicit exported status
                exported = elem.get(f"{{{ns}}}exported") or elem.get("exported")
                if exported and exported.lower() in ("false", "0x0", "0"):
                    continue  # Explicitly not exported

                # Check for permission protection
                perm = elem.get(f"{{{ns}}}permission") or elem.get("permission")
                if perm:
                    continue  # Protected by a permission

                # Collect action names for evidence
                actions: list[str] = []
                for intent_filter in intent_filters:
                    for action_elem in intent_filter.findall("action"):
                        action_name = (
                            action_elem.get(f"{{{ns}}}name")
                            or action_elem.get("name")
                        )
                        if action_name:
                            actions.append(action_name)

                component_type = tag.capitalize()
                findings.append(
                    ManifestFinding(
                        check_id="MANIFEST-013",
                        title=(
                            f"{component_type} with implicit intent: {name}"
                        ),
                        severity="medium",
                        description=(
                            f"{component_type} {name} declares intent filters "
                            f"without requiring a permission. Any app can send "
                            f"intents matching these filters, potentially "
                            f"triggering unintended behaviour or intercepting "
                            f"sensitive data. Consider adding "
                            f"android:permission or setting "
                            f'android:exported="false".'
                        ),
                        evidence=(
                            f"Intent actions: {', '.join(actions[:5])}"
                            if actions
                            else f"<intent-filter> on {tag} {name}"
                        ),
                        cwe_ids=["CWE-927"],
                        confidence="high" if actions else "medium",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # MANIFEST-017: Intent scheme hijacking
    # ------------------------------------------------------------------

    def _check_intent_scheme_hijacking(
        self, apk_obj: Any
    ) -> list[ManifestFinding]:
        """MANIFEST-017: Insecure data URI schemes in intent filters.

        Intent filters that accept ``file://``, ``content://``,
        ``javascript://``, or ``data:`` URI schemes on exported
        components may enable local file access, content provider data
        leakage, or code injection through crafted intents (CWE-94,
        CWE-200).
        """
        findings: list[ManifestFinding] = []

        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
        except Exception:
            return findings

        if manifest_xml is None:
            return findings

        ns = _NS_ANDROID

        for tag in ("activity", "activity-alias", "service", "receiver"):
            for elem in manifest_xml.findall(f".//{tag}"):
                name = (
                    elem.get(f"{{{ns}}}name")
                    or elem.get("name")
                    or "unknown"
                )

                # Only check exported components (explicitly or implicitly)
                exported = elem.get(f"{{{ns}}}exported") or elem.get("exported")
                has_intent_filter = len(elem.findall("intent-filter")) > 0
                if exported and exported.lower() in ("false", "0x0", "0"):
                    continue
                if not exported and not has_intent_filter:
                    continue  # Not exported

                for intent_filter in elem.findall("intent-filter"):
                    for data_elem in intent_filter.findall("data"):
                        scheme = (
                            data_elem.get(f"{{{ns}}}scheme")
                            or data_elem.get("scheme")
                        )
                        if not scheme:
                            continue
                        scheme_lower = scheme.lower()

                        if scheme_lower in self._SENSITIVE_SCHEMES:
                            desc, cwe = self._SENSITIVE_SCHEMES[scheme_lower]
                            component_type = tag.replace("-", " ").title()

                            severity = "high"
                            if scheme_lower in ("javascript", "data"):
                                severity = "high"
                            elif scheme_lower == "file":
                                severity = "high"
                            else:
                                severity = "medium"

                            findings.append(
                                ManifestFinding(
                                    check_id="MANIFEST-017",
                                    title=(
                                        f"Insecure {scheme}:// scheme in "
                                        f"{component_type}: {name}"
                                    ),
                                    severity=severity,
                                    description=(
                                        f"{component_type} {name} accepts "
                                        f"intents with the {scheme}:// URI "
                                        f"scheme. {desc}. An attacker can "
                                        f"craft an intent with a malicious "
                                        f"{scheme}:// URI to exploit this "
                                        f"component."
                                    ),
                                    evidence=(
                                        f'<data android:scheme="{scheme}"> '
                                        f"in {tag} {name}"
                                    ),
                                    cwe_ids=[cwe],
                                    confidence="high",
                                )
                            )

        return findings
