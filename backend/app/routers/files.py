import asyncio
import dataclasses
import os

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse

from app.models.firmware import Firmware
from app.routers.deps import resolve_firmware
from app.services.file_service import FileService
from app.services.jsonb_normalizers import _normalize_firmware_device_metadata

router = APIRouter(prefix="/api/v1/projects/{project_id}/files", tags=["files"])


def get_file_service(
    firmware: Firmware = Depends(resolve_firmware),
) -> FileService:
    """Build a FileService from the resolved firmware.

    Phase 3a: include every detection root (scatter dirs, raw-image dirs)
    from the JSONB cache so the UI exposes them as top-level virtual
    entries alongside ``rootfs/``.
    """
    extra_roots: list[str] = []
    meta = _normalize_firmware_device_metadata(firmware.device_metadata)
    cached = meta.get("detection_roots")
    if isinstance(cached, list):
        extra_roots = [p for p in cached if isinstance(p, str)]
    return FileService(
        firmware.extracted_path,
        extraction_dir=firmware.extraction_dir,
        extra_roots=extra_roots,
    )


@router.get("")
async def list_directory(
    path: str = Query("/", description="Directory path to list"),
    service: FileService = Depends(get_file_service),
):
    loop = asyncio.get_running_loop()
    try:
        entries, truncated = await loop.run_in_executor(
            None, service.list_directory, path
        )
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    return {
        "path": path,
        "entries": [dataclasses.asdict(e) for e in entries],
        "truncated": truncated,
    }


@router.get("/read")
async def read_file(
    path: str = Query(..., description="File path to read"),
    offset: int = Query(0, ge=0, description="Byte offset to start reading from"),
    length: int | None = Query(None, ge=1, description="Number of bytes to read"),
    format: str = Query("auto", description="Response format: auto, base64"),
    service: FileService = Depends(get_file_service),
):
    loop = asyncio.get_running_loop()
    try:
        content = await loop.run_in_executor(
            None, service.read_file, path, offset, length, format
        )
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except PermissionError as e:
        raise HTTPException(403, str(e))
    return dataclasses.asdict(content)


@router.get("/info")
async def file_info(
    path: str = Query(..., description="File path to inspect"),
    service: FileService = Depends(get_file_service),
):
    loop = asyncio.get_running_loop()
    try:
        info = await loop.run_in_executor(None, service.file_info, path)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except PermissionError as e:
        raise HTTPException(403, str(e))
    return dataclasses.asdict(info)


@router.get("/download")
async def download_file(
    path: str = Query(..., description="File path to download"),
    service: FileService = Depends(get_file_service),
):
    loop = asyncio.get_running_loop()
    try:
        real_path = await loop.run_in_executor(None, service._resolve, path)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except PermissionError as e:
        raise HTTPException(403, str(e))
    if not os.path.isfile(real_path):  # noqa: ASYNC240 — endpoint pre-flight stat after resolve; sync stat acceptable (single file, no walk)
        raise HTTPException(400, "Path is not a file")
    filename = os.path.basename(real_path)
    return FileResponse(
        path=real_path,
        filename=filename,
        media_type="application/octet-stream",
    )


@router.get("/uefi-modules")
async def list_uefi_modules(
    service: FileService = Depends(get_file_service),
):
    """List UEFI firmware modules (DXE drivers, PEI, SMM) with GUIDs and types.

    Only works for UEFI firmware extracted via UEFIExtract. Returns an empty
    list for non-UEFI firmware.
    """
    from app.ai.tools.uefi import _KNOWN_GUIDS, _parse_info_txt

    loop = asyncio.get_running_loop()

    def _scan_modules() -> list[dict]:
        # Find the .dump directory
        root_path = service.extracted_root
        dump_dir = None
        if root_path.endswith(".dump"):
            dump_dir = root_path
        else:
            try:
                for entry in os.scandir(root_path):
                    if entry.is_dir() and entry.name.endswith(".dump"):
                        dump_dir = entry.path
                        break
            except OSError:
                pass
            # Check parent (extraction_dir)
            if not dump_dir and service.extraction_dir:
                try:
                    for entry in os.scandir(service.extraction_dir):
                        if entry.is_dir() and entry.name.endswith(".dump"):
                            dump_dir = entry.path
                            break
                except OSError:
                    pass

        if not dump_dir:
            return []

        modules = []
        for dirpath, dirs, files in os.walk(dump_dir):
            if "info.txt" not in files:
                continue
            info = _parse_info_txt(os.path.join(dirpath, "info.txt"))
            file_guid = info.get("File GUID", "")
            if not file_guid:
                continue

            guid = file_guid.strip().upper()
            subtype = info.get("Subtype", "")
            dirname = os.path.basename(dirpath)
            # Extract human-readable name from dirname (e.g. "34 SataController")
            parts = dirname.split(" ", 1)
            dir_label = parts[1] if len(parts) > 1 else ""
            # Check if dirname label is just the GUID (not useful)
            known_name = _KNOWN_GUIDS.get(guid, "")
            display_name = known_name or (dir_label if dir_label and dir_label != guid else "")

            # Gather section info for this module
            sections = []
            has_pe32 = False
            pe32_path = None
            for child_dir in sorted(os.listdir(dirpath)):
                child_full = os.path.join(dirpath, child_dir)
                if not os.path.isdir(child_full):
                    continue
                child_info_path = os.path.join(child_full, "info.txt")
                if not os.path.isfile(child_info_path):
                    continue
                child_info = _parse_info_txt(child_info_path)
                section_type = child_info.get("Subtype", child_dir.split(" ", 1)[-1] if " " in child_dir else child_dir)
                body_path = os.path.join(child_full, "body.bin")
                body_size = os.path.getsize(body_path) if os.path.isfile(body_path) else 0
                is_pe = False
                if "PE32" in section_type and os.path.isfile(body_path) and body_size > 64:
                    try:
                        with open(body_path, "rb") as bf:
                            is_pe = bf.read(2) == b"MZ"
                    except OSError:
                        pass
                if is_pe:
                    has_pe32 = True
                    pe32_path = os.path.relpath(body_path, os.path.dirname(dump_dir))
                sections.append({
                    "type": section_type,
                    "size": body_size,
                    "is_pe": is_pe,
                })

            modules.append({
                "guid": guid,
                "type": subtype or "Unknown",
                "name": display_name,
                "size": info.get("Full size", ""),
                "path": os.path.relpath(dirpath, dump_dir),
                "sections": sections,
                "has_pe32": has_pe32,
                "pe32_path": pe32_path,
                "text": info.get("Text", ""),
                "checksum_valid": "valid" in info.get("Header checksum", ""),
            })

        return modules

    try:
        modules = await loop.run_in_executor(None, _scan_modules)
    except Exception as e:
        raise HTTPException(500, f"Failed to scan UEFI modules: {e}")

    return {
        "modules": modules,
        "total": len(modules),
        "is_uefi": len(modules) > 0,
    }


@router.get("/search")
async def search_files(
    pattern: str = Query(..., description="Glob pattern to search for"),
    path: str = Query("/", description="Directory to search in"),
    service: FileService = Depends(get_file_service),
):
    loop = asyncio.get_running_loop()
    matches, truncated = await loop.run_in_executor(
        None, service.search_files, pattern, path
    )
    return {
        "pattern": pattern,
        "matches": matches,
        "truncated": truncated,
    }
