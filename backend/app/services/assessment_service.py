"""Full firmware security assessment orchestrator.

Runs a multi-phase security assessment against an extracted firmware image,
calling existing services directly and persisting findings to the database.
Each phase is independent -- failures in one phase do not block others.
"""

import asyncio
import logging
import os
import time
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.binary import _scan_all_binary_protections
from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.sbom import SbomComponent
from app.schemas.finding import FindingCreate, Severity
from app.services.androguard_service import AndroguardService
from app.services.compliance_service import ETSIComplianceService
from app.services.event_service import event_service
from app.services.finding_service import FindingService
from app.services.firmware_paths import get_detection_roots
from app.services.sbom import SbomService
from app.services.security_audit import SecurityFinding, run_scan_subset
from app.services.selinux_service import SELinuxService
from app.services.vulnerability_service import VulnerabilityService
from app.services.yara_service import scan_firmware_multi

logger = logging.getLogger(__name__)

# Source tag for all assessment-generated findings
ASSESSMENT_SOURCE = "security_review"


#: Android partition-style directory pairs. Each entry is
#: ``"<partition>/<dir>"`` — rooted at every detection root, these are
#: scanned for APKs. Phase 3b expansion: previously only ``system/app``
#: and ``system/priv-app`` were checked, missing apps shipped in
#: ``product/app/`` (common on AOSP builds past Q) and the four-way
#: ``system/system_ext/vendor/odm`` partition split on newer devices.
ANDROID_APK_PARTITION_DIRS: tuple[str, ...] = (
    "system/app",
    "system/priv-app",
    "product/app",
    "product/priv-app",
    "vendor/app",
    "vendor/priv-app",
    "system_ext/app",
    "system_ext/priv-app",
    "odm/app",
    "odm/priv-app",
)


def _enumerate_android_apk_dirs(roots: list[str]) -> list[str]:
    """Return every existing Android APK-holding directory under ``roots``.

    Covers the 10 partition/directory pairs listed in
    ``ANDROID_APK_PARTITION_DIRS`` across each detection root. Exposed
    as a module-level helper so unit tests can exercise it in isolation.
    """
    out: list[str] = []
    seen: set[str] = set()
    for root in roots:
        if not root:
            continue
        for rel in ANDROID_APK_PARTITION_DIRS:
            candidate = os.path.join(root, rel)
            if not os.path.isdir(candidate):
                continue
            real = os.path.realpath(candidate)
            if real in seen:
                continue
            seen.add(real)
            out.append(candidate)
    return out


class AssessmentService:
    """Orchestrates a full firmware security assessment across multiple phases."""

    def __init__(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
        extracted_path: str,
        db: AsyncSession,
    ):
        self.project_id = project_id
        self.firmware_id = firmware_id
        self.extracted_path = os.path.realpath(extracted_path)
        self.db = db
        self.finding_svc = FindingService(db)
        # Phase 3b: every detection root surfaced by the helper — phases
        # iterate this list so scatter-zip partitions / raw-image dirs are
        # scanned alongside the primary rootfs. Populated lazily on first
        # access via ``_resolve_detection_roots`` so the constructor stays
        # synchronous and single-root tests keep working.
        self._detection_roots: list[str] | None = None

    async def _resolve_detection_roots(self) -> list[str]:
        """Return every detection root for this firmware, memoised.

        Falls back to ``[self.extracted_path]`` if the helper fails or
        returns nothing — callers can always iterate.
        """
        if self._detection_roots is not None:
            return self._detection_roots
        try:
            fw = await self.db.get(Firmware, self.firmware_id)
            if fw is not None:
                roots = await get_detection_roots(fw, db=self.db)
                if roots:
                    loop = asyncio.get_running_loop()
                    self._detection_roots = await loop.run_in_executor(
                        None,
                        lambda: [os.path.realpath(r) for r in roots],
                    )
                    return self._detection_roots
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "detection_roots resolution failed, using extracted_path only: %s",
                exc,
            )
        self._detection_roots = [self.extracted_path]
        return self._detection_roots

    async def run_full_assessment(
        self,
        skip_phases: list[str] | None = None,
    ) -> dict:
        """Execute all assessment phases and return a structured summary.

        Args:
            skip_phases: Optional list of phase names to skip.

        Returns:
            Dict with overall status and per-phase results.
        """
        skip = set(skip_phases or [])
        overall_start = time.monotonic()

        # SSE event publishing — best-effort, never blocks assessment
        try:
            await event_service.connect()
        except Exception:
            logger.debug("EventService connect failed, continuing without SSE")

        project_id_str = str(self.project_id)

        phases = [
            ("credential_crypto", self._phase_credential_crypto),
            ("sbom_vulnerability", self._phase_sbom_vulnerability),
            ("config_filesystem", self._phase_config_filesystem),
            ("malware_detection", self._phase_malware_detection),
            ("binary_protections", self._phase_binary_protections),
            ("android", self._phase_android),
            ("compliance", self._phase_compliance),
        ]

        results: list[dict] = []
        total_findings = 0

        total_phases = sum(1 for n, _ in phases if n not in skip)

        for phase_idx, (phase_name, phase_func) in enumerate(phases):
            if phase_name in skip:
                results.append({
                    "phase": phase_name,
                    "status": "skipped",
                    "findings_created": 0,
                    "duration_s": 0.0,
                    "errors": [],
                })
                continue

            try:
                await event_service.publish_progress(
                    project_id_str, "assessment", status="running",
                    progress=phase_idx / total_phases if total_phases else 0,
                    message=f"Running: {phase_name}",
                )
            except Exception:
                pass

            phase_start = time.monotonic()
            try:
                logger.info("Assessment phase '%s' starting", phase_name)
                findings_created = await phase_func()
                total_findings += findings_created
                results.append({
                    "phase": phase_name,
                    "status": "completed",
                    "findings_created": findings_created,
                    "duration_s": round(time.monotonic() - phase_start, 1),
                    "errors": [],
                })
                logger.info(
                    "Assessment phase '%s' completed: %d findings",
                    phase_name,
                    findings_created,
                )
            except Exception as e:
                logger.warning(
                    "Assessment phase '%s' failed: %s",
                    phase_name,
                    e,
                    exc_info=True,
                )
                results.append({
                    "phase": phase_name,
                    "status": "error",
                    "findings_created": 0,
                    "duration_s": round(time.monotonic() - phase_start, 1),
                    "errors": [str(e)],
                })
                try:
                    await event_service.publish_progress(
                        project_id_str, "assessment", status="running",
                        progress=(phase_idx + 1) / total_phases if total_phases else 0,
                        message=f"Phase {phase_name} failed: {e}",
                    )
                except Exception:
                    pass

        await self.db.flush()

        try:
            await event_service.publish_progress(
                project_id_str, "assessment", status="complete",
                progress=1.0,
                message=f"Assessment complete: {total_findings} findings",
            )
        except Exception:
            pass

        return {
            "status": "completed",
            "total_findings_created": total_findings,
            "total_duration_s": round(time.monotonic() - overall_start, 1),
            "phases": results,
        }

    # ------------------------------------------------------------------
    # Helper: create a finding
    # ------------------------------------------------------------------

    async def _create_finding(
        self,
        title: str,
        severity: str,
        description: str,
        evidence: str | None = None,
        file_path: str | None = None,
        line_number: int | None = None,
        cwe_ids: list[str] | None = None,
        cve_ids: list[str] | None = None,
    ) -> Finding:
        """Persist a single security finding."""
        data = FindingCreate(
            title=title,
            severity=Severity(severity),
            description=description,
            evidence=evidence,
            file_path=file_path,
            line_number=line_number,
            cwe_ids=cwe_ids,
            cve_ids=cve_ids,
            firmware_id=self.firmware_id,
            source=ASSESSMENT_SOURCE,
        )
        return await self.finding_svc.create(self.project_id, data)

    # ------------------------------------------------------------------
    # Phase 1: Credential & Crypto Scan
    # ------------------------------------------------------------------

    async def _phase_credential_crypto(self) -> int:
        """Scan for hardcoded credentials and crypto material."""
        findings: list[SecurityFinding] = []
        loop = asyncio.get_running_loop()

        # Phase 3b: iterate every detection root so scatter-zip siblings
        # and raw-image partitions get scanned in one pass.
        scanners = ["credentials", "shadow", "crypto_material"]
        roots = await self._resolve_detection_roots()
        for root in roots:
            await loop.run_in_executor(
                None, run_scan_subset, root, scanners, findings
            )

        created = 0
        for sf in findings:
            await self._create_finding(
                title=sf.title,
                severity=sf.severity,
                description=sf.description,
                evidence=sf.evidence,
                file_path=sf.file_path,
                line_number=sf.line_number,
                cwe_ids=sf.cwe_ids,
            )
            created += 1

        return created

    # ------------------------------------------------------------------
    # Phase 2: SBOM & Vulnerability
    # ------------------------------------------------------------------

    async def _phase_sbom_vulnerability(self) -> int:
        """Generate SBOM and scan for known vulnerabilities."""
        # Check if SBOM already exists
        existing_count = await self.db.scalar(
            select(func.count(SbomComponent.id)).where(
                SbomComponent.firmware_id == self.firmware_id
            )
        )

        if not existing_count:
            # Phase 3b: construct SbomService with the Firmware row so it
            # walks every detection root via the helper. Falls back to the
            # single-root constructor when the row is unavailable (tests).
            fw = await self.db.get(Firmware, self.firmware_id)
            if fw is not None:
                svc = SbomService(firmware=fw)
            else:
                svc = SbomService(self.extracted_path)
            loop = asyncio.get_running_loop()
            component_dicts = await loop.run_in_executor(
                None, svc.generate_sbom
            )

            # Persist components
            for comp_dict in component_dicts:
                db_comp = SbomComponent(
                    firmware_id=self.firmware_id,
                    name=comp_dict["name"],
                    version=comp_dict["version"],
                    type=comp_dict["type"],
                    cpe=comp_dict["cpe"],
                    purl=comp_dict["purl"],
                    supplier=comp_dict["supplier"],
                    detection_source=comp_dict["detection_source"],
                    detection_confidence=comp_dict["detection_confidence"],
                    file_paths=comp_dict["file_paths"],
                    metadata_=comp_dict["metadata"],
                )
                self.db.add(db_comp)
            await self.db.flush()

        # Run vulnerability scan -- VulnerabilityService auto-creates findings
        vuln_svc = VulnerabilityService(self.db)
        summary = await vuln_svc.scan_components(
            firmware_id=self.firmware_id,
            project_id=self.project_id,
        )

        return summary.get("findings_created", 0)

    # ------------------------------------------------------------------
    # Phase 3: Configuration & Filesystem
    # ------------------------------------------------------------------

    async def _phase_config_filesystem(self) -> int:
        """Check init scripts, setuid, world-writable files, filesystem perms."""
        findings: list[SecurityFinding] = []
        loop = asyncio.get_running_loop()

        # Phase 3b: scan every detection root.
        scanners = ["init_services", "setuid", "world_writable"]
        roots = await self._resolve_detection_roots()
        for root in roots:
            await loop.run_in_executor(
                None, run_scan_subset, root, scanners, findings
            )

        created = 0
        for sf in findings:
            await self._create_finding(
                title=sf.title,
                severity=sf.severity,
                description=sf.description,
                evidence=sf.evidence,
                file_path=sf.file_path,
                line_number=sf.line_number,
                cwe_ids=sf.cwe_ids,
            )
            created += 1

        return created

    # ------------------------------------------------------------------
    # Phase 4: Malware & Script Detection (YARA + Semgrep)
    # ------------------------------------------------------------------

    async def _phase_malware_detection(self) -> int:
        """Run YARA scan and optional Semgrep scan."""
        created = 0

        # YARA scan — Phase 3b: multi-root via scan_firmware_multi so
        # scatter-zip siblings / raw-image dirs are covered in one pass.
        try:
            roots = await self._resolve_detection_roots()
            loop = asyncio.get_running_loop()
            yara_result = await loop.run_in_executor(
                None, scan_firmware_multi, roots
            )

            for sf in yara_result.findings:
                await self._create_finding(
                    title=sf.title,
                    severity=sf.severity,
                    description=sf.description,
                    evidence=sf.evidence,
                    file_path=sf.file_path,
                    cwe_ids=sf.cwe_ids,
                )
                created += 1

            if yara_result.errors:
                logger.warning(
                    "YARA scan errors: %s", "; ".join(yara_result.errors)
                )
        except ImportError:
            logger.info("YARA not available, skipping malware scan")
        except Exception as e:
            logger.warning("YARA scan failed: %s", e)

        # Semgrep scan (optional, runs as subprocess)
        try:
            created += await self._run_semgrep()
        except Exception as e:
            logger.warning("Semgrep scan failed: %s", e)

        return created

    async def _run_semgrep(self) -> int:
        """Run Semgrep on script files if semgrep is installed."""
        import json
        import shutil

        if not shutil.which("semgrep"):
            logger.debug("Semgrep not installed, skipping")
            return 0

        # Phase 3b: collect script dirs across every detection root.
        # The isdir checks across N×5 candidate paths are routed through a
        # single executor hop (Rule #5).
        roots = await self._resolve_detection_roots()

        def _collect_semgrep_targets_sync(detection_roots: list[str]) -> list[str]:
            collected: list[str] = []
            for root_local in detection_roots:
                for d in ["etc", "usr/bin", "usr/sbin", "www", "opt"]:
                    path = os.path.join(root_local, d)
                    if os.path.isdir(path):
                        collected.append(path)
            return collected

        loop = asyncio.get_running_loop()
        targets = await loop.run_in_executor(
            None, _collect_semgrep_targets_sync, roots,
        )

        if not targets:
            return 0

        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "--json", "--config", "auto",
                "--timeout", "60",
                *targets,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            # Bumped outer wait_for 120 → 300 on 2026-05-22 (over-constraint
            # sweep). Inner `semgrep --timeout 60` is the PER-FILE limit;
            # `targets` can contain hundreds of files on a multi-GB firmware
            # PE catalog scan, so the OUTER wait_for must cover the aggregate.
            # 300s accommodates a ~5-file batch at the worst-case 60s/file.
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        except (TimeoutError, OSError) as e:
            logger.warning("Semgrep timed out or failed: %s", e)
            return 0

        if not stdout:
            return 0

        created = 0
        try:
            data = json.loads(stdout.decode("utf-8", errors="replace"))
            for result in data.get("results", [])[:50]:
                check_id = result.get("check_id", "unknown")
                message = result.get("extra", {}).get("message", check_id)
                severity = result.get("extra", {}).get("severity", "WARNING")
                sev_map = {
                    "ERROR": "high",
                    "WARNING": "medium",
                    "INFO": "low",
                }
                sev = sev_map.get(severity, "medium")

                file_path = result.get("path", "")
                # Phase 3b: normalise against any detection root so multi-root
                # Semgrep output shows firmware-relative paths for partitions
                # too, not just the primary rootfs.
                for _root in roots:
                    if file_path.startswith(_root):
                        file_path = "/" + os.path.relpath(file_path, _root)  # noqa: ASYNC240 — pure-string path op; no I/O
                        break

                await self._create_finding(
                    title=f"Semgrep: {check_id.split('.')[-1]}",
                    severity=sev,
                    description=message,
                    evidence=result.get("extra", {}).get("lines", "")[:500],
                    file_path=file_path,
                    line_number=result.get("start", {}).get("line"),
                )
                created += 1
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Failed to parse Semgrep output: %s", e)

        return created

    # ------------------------------------------------------------------
    # Phase 5: Binary Protection Audit
    # ------------------------------------------------------------------

    async def _phase_binary_protections(self) -> int:
        """Check all ELF binaries for security protections."""
        # Phase 3b: scan every detection root. Results from sibling
        # partitions are labelled with paths relative to their own root
        # (``_scan_all_binary_protections`` already takes a ``real_root``
        # argument), so findings never mix partition prefixes.
        roots = await self._resolve_detection_roots()
        loop = asyncio.get_running_loop()
        results: list[dict] = []
        for root in roots:
            part_results = await loop.run_in_executor(
                None,
                _scan_all_binary_protections,
                root,
                root,
            )
            if part_results:
                results.extend(part_results)

        if not results:
            return 0

        # Identify binaries with poor protections (score < 2 out of 5)
        poorly_protected = [r for r in results if r["score"] < 2.0]
        total = len(results)

        if not poorly_protected:
            return 0

        # Create a summary finding
        count = len(poorly_protected)
        pct = round(count / total * 100) if total else 0

        # Build evidence listing the worst offenders
        evidence_lines = [
            f"Scanned {total} ELF binaries. "
            f"{count} ({pct}%) have protection score < 2.0/5.0:",
            "",
        ]
        for r in sorted(poorly_protected, key=lambda x: x["score"])[:20]:
            flags = []
            if not r.get("nx"):
                flags.append("no-NX")
            if not r.get("canary"):
                flags.append("no-canary")
            if not r.get("pie"):
                flags.append("no-PIE")
            if r.get("relro") == "none":
                flags.append("no-RELRO")
            evidence_lines.append(
                f"  {r['path']} (score {r['score']:.1f}): {', '.join(flags)}"
            )
        if count > 20:
            evidence_lines.append(f"  ... and {count - 20} more")

        severity = "high" if pct > 50 else "medium"

        await self._create_finding(
            title=f"Weak binary protections: {count}/{total} binaries "
                  f"({pct}%) lack hardening",
            severity=severity,
            description=(
                f"Binary protection scan found {count} out of {total} ELF "
                f"binaries with protection score below 2.0 (out of 5.0). "
                f"Missing protections include NX, stack canaries, PIE, and "
                f"RELRO. This makes exploitation of memory corruption "
                f"vulnerabilities significantly easier."
            ),
            evidence="\n".join(evidence_lines),
            cwe_ids=["CWE-693"],
        )
        return 1

    # ------------------------------------------------------------------
    # Phase 6: Android-Specific
    # ------------------------------------------------------------------

    async def _phase_android(self) -> int:
        """Run Android-specific checks if firmware appears to be Android."""
        # Phase 3b: check every detection root for Android markers. Works
        # around single-root detection missing Android firmware where the
        # rootfs is a scatter-zip sibling instead of the primary path. The
        # marker probe across N roots × 4 markers each runs in a single
        # executor hop (Rule #5).
        roots = await self._resolve_detection_roots()

        def _find_android_root_sync(detection_roots: list[str]) -> str | None:
            for r in detection_roots:
                markers = [
                    os.path.join(r, "system", "app"),
                    os.path.join(r, "system", "build.prop"),
                    os.path.join(r, "system", "system", "build.prop"),
                    os.path.join(r, "build.prop"),
                ]
                if any(os.path.exists(m) for m in markers):
                    return r
            return None

        marker_loop = asyncio.get_running_loop()
        android_root: str | None = await marker_loop.run_in_executor(
            None, _find_android_root_sync, roots,
        )
        if android_root is None:
            return 0

        created = 0

        # SELinux analysis — uses the Android root so ``sepolicy``/``cil``
        # files in that partition resolve correctly.
        try:
            svc = SELinuxService(android_root)
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, svc.analyze_policy)

            if not result.get("has_selinux"):
                await self._create_finding(
                    title="SELinux not detected in Android firmware",
                    severity="high",
                    description=(
                        "No SELinux policy files found. Android devices "
                        "should enforce SELinux for mandatory access control."
                    ),
                    cwe_ids=["CWE-732"],
                )
                created += 1
            else:
                # Check for permissive domains
                permissive = result.get("permissive_domains", [])
                if permissive:
                    await self._create_finding(
                        title=f"SELinux: {len(permissive)} permissive domain(s)",
                        severity="medium",
                        description=(
                            f"Found {len(permissive)} SELinux domain(s) in "
                            f"permissive mode. Permissive domains bypass "
                            f"mandatory access control."
                        ),
                        evidence="\n".join(
                            f"  - {d}" for d in permissive[:30]
                        ),
                        cwe_ids=["CWE-732"],
                    )
                    created += 1

                enforcement = result.get("enforcement", {})
                if enforcement.get("mode") == "permissive":
                    await self._create_finding(
                        title="SELinux in global permissive mode",
                        severity="critical",
                        description=(
                            "SELinux is set to permissive mode globally. "
                            "This disables all mandatory access control "
                            "enforcement."
                        ),
                        cwe_ids=["CWE-732"],
                    )
                    created += 1
        except Exception as e:
            logger.warning("SELinux analysis failed: %s", e)

        # APK analysis (if androguard available)
        try:
            apk_svc = AndroguardService()
            loop = asyncio.get_running_loop()

            # Phase 3b: enumerate every partition/dir pair across every
            # detection root. Previously only ``system/app`` and
            # ``system/priv-app`` were checked, silently missing apps
            # shipped in ``product/app`` (common on AOSP Q+), the
            # four-way system/system_ext/vendor/odm split on newer
            # devices, and any scatter-zip sibling rootfs.
            apk_dirs = _enumerate_android_apk_dirs(roots)

            def _enumerate_unique_apks_sync(
                dirs: list[str], detection_roots: list[str],
            ) -> list[tuple[str, str]]:
                """Walk ``dirs`` once, dedup by realpath, compute rel_path.

                Offloaded so the async caller does N apk-analyses through a
                single deduplicated input set instead of stalling the loop
                per file via the per-call ``os.path.realpath`` / ``relpath``
                pair (Rule #5). Returns ``[(apk_path, rel_path)]``.
                """
                seen_local: set[str] = set()
                out_local: list[tuple[str, str]] = []
                for apk_dir_local in dirs:
                    for dirpath, _dirs, files in os.walk(apk_dir_local):
                        for name in files:
                            if not name.endswith(".apk"):
                                continue
                            apk_path_local = os.path.join(dirpath, name)
                            real_local = os.path.realpath(apk_path_local)
                            if real_local in seen_local:
                                continue
                            seen_local.add(real_local)
                            rel_local = apk_path_local
                            for r_local in detection_roots:
                                if apk_path_local.startswith(r_local + os.sep):
                                    rel_local = "/" + os.path.relpath(
                                        apk_path_local, r_local,
                                    )
                                    break
                            out_local.append((apk_path_local, rel_local))
                return out_local

            apk_entries = await loop.run_in_executor(
                None, _enumerate_unique_apks_sync, apk_dirs, roots,
            )
            dangerous_apks = 0
            for apk_path, _rel_path in apk_entries:
                try:
                    info = await loop.run_in_executor(
                        None, apk_svc.analyze_apk, apk_path
                    )
                    if info and info.get("dangerous_permissions"):
                        dangerous_apks += 1
                except Exception:
                    pass

            if dangerous_apks:
                await self._create_finding(
                    title=f"{dangerous_apks} APK(s) with dangerous permissions",
                    severity="medium",
                    description=(
                        f"Found {dangerous_apks} pre-installed APK(s) that "
                        f"request dangerous Android permissions."
                    ),
                )
                created += 1

        except ImportError:
            logger.debug("Androguard not available, skipping APK analysis")
        except Exception as e:
            logger.warning("APK analysis failed: %s", e)

        return created

    # ------------------------------------------------------------------
    # Phase 7: Compliance
    # ------------------------------------------------------------------

    async def _phase_compliance(self) -> int:
        """Run ETSI EN 303 645 compliance check.

        This does not create findings directly -- it generates a compliance
        report that maps existing findings to ETSI provisions. The report
        is returned as part of the phase result.
        """
        svc = ETSIComplianceService(self.db)
        report = await svc.generate_report(
            project_id=self.project_id,
            firmware_id=self.firmware_id,
        )

        # Create a summary finding if there are failed provisions
        summary = report.get("summary", {})
        fail_count = summary.get("fail", 0)
        partial_count = summary.get("partial", 0)

        if fail_count == 0 and partial_count == 0:
            return 0

        provisions = report.get("provisions", [])
        failed_names = [
            p["name"]
            for p in provisions
            if p.get("status") in ("fail", "partial")
        ]

        await self._create_finding(
            title=f"ETSI EN 303 645: {fail_count} failed, "
                  f"{partial_count} partial provisions",
            severity="medium" if fail_count == 0 else "high",
            description=(
                f"Compliance assessment against ETSI EN 303 645 found "
                f"{fail_count} failed and {partial_count} partially met "
                f"provisions out of 13 total. Failed/partial provisions:\n"
                + "\n".join(f"  - {n}" for n in failed_names)
            ),
            evidence=f"Full report: {summary}",
        )
        return 1
