"""Force a firmware function to return a constant, by patching its entry.

The auth-bypass primitive for daemon fuzzing (feedback #4): web daemons like
httpd (CivetWeb) embed their auth check *in the binary*, so an LD_PRELOAD shim
can't interpose it (interposition only affects cross-module calls). Instead we
overwrite the target function's first instructions with an architecture-specific
"return <value>" stub, producing a patched copy in the project carved/ dir. Run
that patched binary as a fuzzing target (start_fuzzing_campaign harness_binary=…,
desock=true) and the fuzzer reaches post-auth request handlers.

Generalises beyond auth: neutralise any gate (license/crypto/CRC check) the
agent identifies by reverse-engineering. Pure ELF edit — no sandbox needed.
"""

from __future__ import annotations

import logging
import os
import shutil
import struct
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.firmware import Firmware
from app.utils.sandbox import validate_path

logger = logging.getLogger(__name__)


@dataclass
class PatchResult:
    ok: bool
    patched_virtual_path: str | None
    function: str
    addr: int | None
    arch: str
    mode: str  # "arm" | "thumb" | "aarch64" | "mips" | ""
    stub_hex: str
    detail: str


class BinaryPatchError(RuntimeError):
    pass


class BinaryPatchService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def patch_function_return(
        self,
        project_id: UUID,
        firmware_id: UUID,
        binary_path: str,
        function: str,
        return_value: int = 1,
        name: str | None = None,
        thumb: bool | None = None,
    ) -> PatchResult:
        if not (0 <= return_value <= 0xFFFF):
            raise BinaryPatchError("return_value must be in 0..65535")

        firmware = await self._load_firmware(project_id, firmware_id)
        if not firmware.extracted_path or not os.path.isdir(firmware.extracted_path):
            raise BinaryPatchError("firmware has no extracted rootfs on disk")

        real = self._resolve(firmware.extracted_path, binary_path)

        from elftools.elf.elffile import ELFFile

        with open(real, "rb") as f:
            elf = ELFFile(f)
            machine = elf["e_machine"]
            little = elf.little_endian
            addr, sym_thumb = self._resolve_symbol(elf, function)
            is_thumb = thumb if thumb is not None else sym_thumb
            file_off = self._vaddr_to_offset(elf, addr)

        stub, mode = self._build_stub(machine, little, is_thumb, return_value)
        if stub is None:
            raise BinaryPatchError(
                f"unsupported architecture for patching: {machine}"
            )

        # Copy the binary into carved/patched/<name> and overwrite the entry.
        carved = self._ensure_carved_dir(firmware)
        patched_dir = os.path.join(carved, "patched")
        os.makedirs(patched_dir, exist_ok=True)
        try:
            os.chmod(patched_dir, 0o2775)
        except OSError:
            pass
        out_name = name or (os.path.basename(real) + ".patched")
        if "/" in out_name or ".." in out_name:
            raise BinaryPatchError("name must be a plain filename")
        out_host = os.path.join(patched_dir, out_name)
        shutil.copy2(real, out_host)
        try:
            os.chmod(out_host, 0o775)
        except OSError:
            pass

        with open(out_host, "r+b") as f:
            f.seek(file_off)
            f.write(stub)

        logger.info(
            "Patched %s::%s @0x%x (offset 0x%x) -> return %d [%s], out=%s",
            binary_path, function, addr, file_off, return_value, mode, out_host,
        )

        return PatchResult(
            ok=True,
            patched_virtual_path=f"/_carved/patched/{out_name}",
            function=function,
            addr=addr,
            arch=str(machine),
            mode=mode,
            stub_hex=stub.hex(),
            detail=(
                f"Patched {function} @0x{addr:x} (file offset 0x{file_off:x}) to "
                f"return {return_value}; wrote {len(stub)} bytes [{mode}]."
            ),
        )

    # ------------------------------------------------------------------
    # ELF helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_symbol(elf, function: str) -> tuple[int, bool]:
        """Return (vaddr, is_thumb) for a function symbol or a hex address."""
        # Allow a raw address (e.g. "0x132e8") for stripped/local-only targets.
        if function.lower().startswith("0x"):
            try:
                return int(function, 16), bool(int(function, 16) & 1)
            except ValueError:
                raise BinaryPatchError(f"invalid address: {function}")

        from elftools.elf.sections import SymbolTableSection

        for secname in (".symtab", ".dynsym"):
            sec = elf.get_section_by_name(secname)
            if not isinstance(sec, SymbolTableSection):
                continue
            for sym in sec.iter_symbols():
                if sym.name == function and sym["st_info"]["type"] == "STT_FUNC":
                    val = sym["st_value"]
                    # ARM Thumb functions have bit0 set in the symbol value.
                    return (val & ~1), bool(val & 1)
        raise BinaryPatchError(
            f"function symbol '{function}' not found (try a 0x… address, or check "
            "the symbol exists: readelf --syms)."
        )

    @staticmethod
    def _vaddr_to_offset(elf, vaddr: int) -> int:
        """Map a virtual address to a file offset via PT_LOAD segments."""
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            start = seg["p_vaddr"]
            end = start + seg["p_filesz"]
            if start <= vaddr < end:
                return seg["p_offset"] + (vaddr - start)
        raise BinaryPatchError(
            f"address 0x{vaddr:x} is not inside any loadable segment"
        )

    @staticmethod
    def _build_stub(
        machine: str, little: bool, thumb: bool, val: int
    ) -> tuple[bytes | None, str]:
        end = "<" if little else ">"
        if machine == "EM_ARM":
            if thumb:
                if val > 0xFF:
                    raise BinaryPatchError("thumb return value must be 0..255")
                # movs r0,#val ; bx lr  (both 16-bit, always little-endian halfwords)
                return struct.pack("<HH", 0x2000 | (val & 0xFF), 0x4770), "thumb"
            if val > 0xFF:
                raise BinaryPatchError("arm return value must be 0..255")
            mov = 0xE3A00000 | (val & 0xFF)   # mov r0, #val
            bxlr = 0xE12FFF1E                 # bx lr
            return struct.pack(end + "II", mov, bxlr), "arm"
        if machine == "EM_AARCH64":
            movz = 0x52800000 | ((val & 0xFFFF) << 5)  # movz w0, #val
            ret = 0xD65F03C0                            # ret
            return struct.pack("<II", movz, ret), "aarch64"
        if machine == "EM_MIPS":
            jr = 0x03E00008                    # jr $ra
            ori = 0x34020000 | (val & 0xFFFF)  # ori $v0, $zero, val (delay slot)
            return struct.pack(end + "II", jr, ori), "mips"
        return None, ""

    # ------------------------------------------------------------------

    @staticmethod
    def _resolve(extracted_path: str, path: str) -> str:
        clean = path.strip()
        for prefix in ("/rootfs/", "rootfs/"):
            if clean.startswith(prefix):
                clean = "/" + clean[len(prefix):]
                break
        real = validate_path(extracted_path, clean)
        if not os.path.isfile(real):
            raise BinaryPatchError(
                f"binary not found at firmware path '{path}' (resolved to {real})"
            )
        return real

    async def _load_firmware(self, project_id: UUID, firmware_id: UUID) -> Firmware:
        result = await self.db.execute(
            select(Firmware).where(
                Firmware.id == firmware_id,
                Firmware.project_id == project_id,
            )
        )
        firmware = result.scalar_one_or_none()
        if firmware is None:
            raise BinaryPatchError("firmware not found for this project")
        return firmware

    @staticmethod
    def _ensure_carved_dir(firmware: Firmware) -> str:
        if not firmware.storage_path:
            raise BinaryPatchError("firmware has no storage_path on disk")
        carved = os.path.join(os.path.dirname(firmware.storage_path), "carved")
        os.makedirs(carved, exist_ok=True)
        try:
            os.chmod(carved, 0o2775)
        except OSError:
            pass
        return carved
