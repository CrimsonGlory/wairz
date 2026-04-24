"""ClamAV antivirus scanning service.

Connects to a clamd daemon running as a Docker sidecar via TCP.
All sync clamd library calls are wrapped in run_in_executor() for
async compatibility.
"""

import asyncio
import logging
import os
import stat
from dataclasses import dataclass

from app.config import get_settings

logger = logging.getLogger(__name__)

# Maximum file size to scan (100 MB)
MAX_SCAN_FILE_SIZE = 100 * 1024 * 1024


@dataclass
class ClamScanResult:
    """Result of scanning a single file with ClamAV."""
    file_path: str
    infected: bool
    signature: str | None = None
    error: str | None = None


async def check_available() -> bool:
    """Check whether the clamd daemon is reachable."""
    settings = get_settings()
    if not settings.clamav_enabled:
        return False

    loop = asyncio.get_running_loop()
    try:
        import clamd
        cd = clamd.ClamdNetworkSocket(host=settings.clamav_host, port=settings.clamav_port, timeout=5)
        result = await loop.run_in_executor(None, cd.ping)
        return result == "PONG"
    except Exception as e:
        logger.debug("ClamAV not available: %s", e)
        return False


def _get_clamd():
    """Create a clamd network socket client."""
    settings = get_settings()
    import clamd
    return clamd.ClamdNetworkSocket(
        host=settings.clamav_host,
        port=settings.clamav_port,
        timeout=120,
    )


async def scan_file(file_path: str) -> ClamScanResult:
    """Scan a single file with ClamAV.

    The file must be accessible from the ClamAV container (shared volume).
    """
    loop = asyncio.get_running_loop()

    def _scan():
        try:
            cd = _get_clamd()
            # Use MULTISCAN for single file via path (clamd reads the file directly)
            result = cd.scan(file_path)
            if result is None:
                return ClamScanResult(file_path=file_path, infected=False)
            # result format: {'/path/to/file': ('FOUND', 'Win.Trojan.Agent-123')}
            # or {'/path/to/file': ('OK', None)}
            status, signature = result.get(file_path, ("OK", None))
            if status == "FOUND":
                return ClamScanResult(
                    file_path=file_path, infected=True, signature=signature
                )
            return ClamScanResult(file_path=file_path, infected=False)
        except Exception as e:
            return ClamScanResult(
                file_path=file_path, infected=False, error=str(e)
            )

    return await loop.run_in_executor(None, _scan)


async def scan_directory(
    dir_path: str, max_files: int = 500
) -> list[ClamScanResult]:
    """Scan a directory with ClamAV, skipping non-regular and oversized files.

    Returns a list of ClamScanResult for each scanned file.
    """
    loop = asyncio.get_running_loop()

    def _collect_files():
        files: list[str] = []
        for dirpath, _dirs, filenames in os.walk(dir_path):
            for fname in filenames:
                if len(files) >= max_files:
                    return files
                fpath = os.path.join(dirpath, fname)
                try:
                    st = os.lstat(fpath)
                except OSError:
                    continue
                # Skip non-regular files (symlinks, devices, etc.)
                if not stat.S_ISREG(st.st_mode):
                    continue
                # Skip very large files
                if st.st_size > MAX_SCAN_FILE_SIZE:
                    continue
                files.append(fpath)
        return files

    files = await loop.run_in_executor(None, _collect_files)

    def _batch_scan():
        results: list[ClamScanResult] = []
        try:
            cd = _get_clamd()
            # Scan the directory in one call — clamd walks it
            scan_result = cd.multiscan(dir_path)
            if scan_result is None:
                # No infections found
                for f in files:
                    results.append(ClamScanResult(file_path=f, infected=False))
                return results

            # Build lookup of infected files
            infected_map: dict[str, str] = {}
            for fpath, (status, sig) in scan_result.items():
                if status == "FOUND":
                    infected_map[fpath] = sig

            for f in files:
                if f in infected_map:
                    results.append(ClamScanResult(
                        file_path=f, infected=True, signature=infected_map[f]
                    ))
                else:
                    results.append(ClamScanResult(file_path=f, infected=False))
            return results
        except Exception as e:
            logger.warning("ClamAV batch scan failed, falling back to individual scans: %s", e)
            # Fallback: scan files individually
            try:
                cd = _get_clamd()
                for f in files:
                    try:
                        result = cd.scan(f)
                        if result is None:
                            results.append(ClamScanResult(file_path=f, infected=False))
                            continue
                        status, sig = result.get(f, ("OK", None))
                        results.append(ClamScanResult(
                            file_path=f,
                            infected=(status == "FOUND"),
                            signature=sig if status == "FOUND" else None,
                        ))
                    except Exception as inner_e:
                        results.append(ClamScanResult(
                            file_path=f, infected=False, error=str(inner_e)
                        ))
            except Exception as conn_e:
                return [ClamScanResult(
                    file_path=dir_path, infected=False,
                    error=f"ClamAV connection failed: {conn_e}",
                )]
            return results

    return await loop.run_in_executor(None, _batch_scan)
