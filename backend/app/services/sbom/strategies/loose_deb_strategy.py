"""Loose ``.deb`` archive detector for vendor BSP shipments.

Unlike :class:`DpkgStrategy` (which parses ``/var/lib/dpkg/status`` —
the INSTALLED-PACKAGE STATE on a running Debian system), this strategy
walks the extracted firmware tree for ``*.deb`` archives shipped as
files (NVIDIA Jetson L4T BSPs under ``nv_tegra/l4t_deb_packages/``,
similar vendor BSPs in Ubuntu Core / Yocto images, kernel module
``.deb`` bundles for embedded Linux distros). It opens each archive
directly via ``ar`` + ``tar``, parses the control file, and emits an
``IdentifiedComponent``.

The deb file format is an ``ar`` archive whose members are
``debian-binary``, ``control.tar.{gz,xz,zst}``, and ``data.tar.*``. We
read only the control tarball so we avoid the (potentially huge) data
payload.

Bounded per Rule #5: per-deb subprocess wall-clock ≤5 s; per-root file
scan ≤``_MAX_DEBS_PER_ROOT`` (truncation surfaces a synthetic
``cap_hit`` component per Scout-D-style sentinel discipline so an exact
1000 doesn't masquerade as a complete walk).

Originally added 2026-05-22 as follow-up #1 from
``postmortem-over-constraint-sweep-2026-05-22.md`` after Syft caught
loose debs on the L4T BSP but the curated strategy list had no
dedicated walker. Operator-facing component count should match the
on-disk ``find <root> -name '*.deb' | wc -l`` count exactly.
"""

from __future__ import annotations

import logging
import os
import subprocess

from app.services.sbom.constants import IdentifiedComponent
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext
from app.services.sbom.strategies.dpkg_strategy import parse_control_block

logger = logging.getLogger(__name__)

#: Hard cap on the number of ``.deb`` files processed per scan root.
#: A real L4T BSP ships ~21; a Yocto kernel-modules drop tops out around
#: 80; this cap is a runaway-defense against pathological firmware (e.g.
#: a vendor that ships every Ubuntu archive snapshot inside the tarball).
_MAX_DEBS_PER_ROOT = 1000

#: Per-subprocess timeout. ``ar t`` + ``ar p | tar`` against a small
#: control tarball is sub-second on typical hardware; 5 s is the runaway
#: defense against e.g. an LZMA bomb in the control segment.
_DEB_SUBPROCESS_TIMEOUT_S = 5

#: Known ``control.tar.*`` member extensions. Order matters: newer debs
#: prefer xz; older default to gz; zst appears in Ubuntu 22.04+.
_CONTROL_MEMBER_NAMES = (
    "control.tar.gz",
    "control.tar.xz",
    "control.tar.zst",
    "control.tar.bz2",
    "control.tar",
)


def _list_deb_members(deb_path: str) -> list[str] | None:
    """Return the member list of a ``.deb`` ``ar`` archive, or None on failure."""
    try:
        proc = subprocess.run(
            ["ar", "t", deb_path],
            capture_output=True,
            text=True,
            timeout=_DEB_SUBPROCESS_TIMEOUT_S,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("ar t timed out / failed for %s: %s", deb_path, exc)
        return None
    if proc.returncode != 0:
        return None
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _extract_control_file(deb_path: str, control_member: str) -> str | None:
    """Stream ``control.tar.*`` from the deb and return the ``control`` file body."""
    # ar p <deb> control.tar.<ext> | tar -O -xf - ./control
    # The control file inside the tarball is conventionally './control'
    # (older deb) or 'control' (newer); tar accepts either via -O.
    try:
        ar_proc = subprocess.Popen(
            ["ar", "p", deb_path, control_member],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        # Detect tar format from the member name and pass the right
        # decompression flag explicitly so tar doesn't auto-probe a
        # stream of unknown shape and stall.
        tar_args = ["tar", "-xO", "-f", "-", "./control"]
        if control_member.endswith(".gz"):
            tar_args.insert(1, "-z")
        elif control_member.endswith(".xz"):
            tar_args.insert(1, "-J")
        elif control_member.endswith(".bz2"):
            tar_args.insert(1, "-j")
        elif control_member.endswith(".zst"):
            tar_args.insert(1, "--zstd")
        # tar without compression flag handles uncompressed control.tar.

        try:
            tar_proc = subprocess.run(
                tar_args,
                stdin=ar_proc.stdout,
                capture_output=True,
                timeout=_DEB_SUBPROCESS_TIMEOUT_S,
                check=False,
            )
        finally:
            # Always reap the ar process so we don't leak file handles.
            if ar_proc.stdout is not None:
                ar_proc.stdout.close()
            ar_proc.wait(timeout=_DEB_SUBPROCESS_TIMEOUT_S)
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("ar p | tar pipeline failed for %s: %s", deb_path, exc)
        return None

    if tar_proc.returncode != 0 or not tar_proc.stdout:
        # Some debs name the file 'control' (no leading dot). Retry once.
        try:
            ar_proc2 = subprocess.Popen(
                ["ar", "p", deb_path, control_member],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            tar_args2 = list(tar_args)
            tar_args2[-1] = "control"
            try:
                tar_proc2 = subprocess.run(
                    tar_args2,
                    stdin=ar_proc2.stdout,
                    capture_output=True,
                    timeout=_DEB_SUBPROCESS_TIMEOUT_S,
                    check=False,
                )
            finally:
                if ar_proc2.stdout is not None:
                    ar_proc2.stdout.close()
                ar_proc2.wait(timeout=_DEB_SUBPROCESS_TIMEOUT_S)
        except (subprocess.TimeoutExpired, OSError):
            return None
        if tar_proc2.returncode != 0 or not tar_proc2.stdout:
            return None
        try:
            return tar_proc2.stdout.decode("utf-8", errors="replace")
        except (UnicodeDecodeError, AttributeError):
            return None

    try:
        return tar_proc.stdout.decode("utf-8", errors="replace")
    except (UnicodeDecodeError, AttributeError):
        return None


class LooseDebStrategy(SbomStrategy):
    """Detect loose ``*.deb`` archives shipped in vendor firmware trees.

    Complements :class:`DpkgStrategy` (which parses installed-package
    state from ``/var/lib/dpkg/status``). The two strategies share the
    same purl ``pkg:deb/...`` shape; ``ComponentStore.add`` dedupes on
    ``(normalized_name, normalized_version)``, so a package present in
    both a loose ``.deb`` AND ``/var/lib/dpkg/status`` lands once.

    ``detection_confidence='high'`` — we PARSED the control file
    directly (not a binary-strings heuristic).
    """

    name = "loose_deb"

    def run(self, ctx: StrategyContext) -> None:  # noqa: ASYNC240 — sync subprocess + bounded filesystem walk; called from executor
        deb_paths: list[str] = []
        try:
            for dirpath, _dirnames, filenames in os.walk(
                ctx.extracted_root, followlinks=False,
            ):
                for fn in filenames:
                    if fn.endswith(".deb"):
                        deb_paths.append(os.path.join(dirpath, fn))
                        if len(deb_paths) >= _MAX_DEBS_PER_ROOT:
                            break
                if len(deb_paths) >= _MAX_DEBS_PER_ROOT:
                    break
        except OSError as exc:
            logger.debug("os.walk failed for %s: %s", ctx.extracted_root, exc)
            return

        cap_hit = len(deb_paths) >= _MAX_DEBS_PER_ROOT
        for deb_path in deb_paths:
            self._process_deb(deb_path, ctx)

        if cap_hit:
            # Per Rule #5 / Scout-D sentinel: surface the truncation so
            # operators can distinguish "exactly N debs in the BSP" from
            # "we stopped at the cap; there might be more".
            sentinel = IdentifiedComponent(
                name="_loose_deb_scan_cap_hit",
                version=str(_MAX_DEBS_PER_ROOT),
                type="application",
                cpe=None,
                purl=None,
                supplier=None,
                detection_source="loose_deb",
                detection_confidence="high",
                file_paths=[],
                metadata={
                    "cap": _MAX_DEBS_PER_ROOT,
                    "note": (
                        "loose-deb walker stopped at the per-root cap; "
                        "additional .deb files in this scan root were "
                        "not processed. Re-run with a raised cap if the "
                        "BSP genuinely ships >cap packages."
                    ),
                },
            )
            ctx.store.add(sentinel)

    @staticmethod
    def _process_deb(deb_path: str, ctx: StrategyContext) -> None:
        members = _list_deb_members(deb_path)
        if not members:
            # Corrupt deb, non-deb ELF/zip with .deb extension, or ar
            # timed out — skip silently.
            return

        control_member = next(
            (m for m in members if m in _CONTROL_MEMBER_NAMES), None,
        )
        if control_member is None:
            return

        control_body = _extract_control_file(deb_path, control_member)
        if not control_body:
            return

        fields = parse_control_block(control_body)
        name = fields.get("package", "").strip()
        if not name:
            return
        version = fields.get("version", "").strip() or None
        arch = fields.get("architecture", "").strip() or None
        maintainer = fields.get("maintainer", "").strip() or None
        section = fields.get("section", "").strip() or None
        homepage = fields.get("homepage", "").strip() or None
        description = (fields.get("description", "") or "")[:200]

        # Build purl manually rather than via build_purl() so we can pin
        # the arch qualifier — packageurl-python's qualifier API can drop
        # malformed values silently, and arch is high-signal for CPE
        # narrowing (e.g. nvidia-l4t-core@32.3.1?arch=arm64).
        if version:
            purl = f"pkg:deb/{name}@{version}"
            if arch:
                purl += f"?arch={arch}"
        else:
            purl = None

        try:
            rel_path = os.path.relpath(deb_path, ctx.extracted_root)
        except ValueError:
            # Different mounts on Windows — fall back to the absolute path.
            rel_path = deb_path

        comp = IdentifiedComponent(
            name=name,
            version=version,
            type="application",
            cpe=None,  # Let post-processing enrich_cpes() resolve.
            purl=purl,
            supplier=maintainer,
            detection_source="loose_deb",
            detection_confidence="high",
            file_paths=[f"/{rel_path}"],
            metadata={
                "section": section,
                "homepage": homepage,
                "description": description,
                "arch": arch,
                "source": "loose_deb",
            },
        )
        ctx.store.add(comp)
