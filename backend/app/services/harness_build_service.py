"""Service for the fuzzing harness-build sandbox.

Cross-compiles a fuzzing harness that links a firmware shared library, for the
firmware's architecture, against the firmware's own libraries (so the harness
runs under qemu-user with the real .so + its deps). Uses bundled Bootlin
old-glibc toolchains so the harness needs only base glibc symbol versions and
runs against the firmware's (typically older) libc.

The built ELF lands in the project's carved/ dir (visible at /_carved/), then a
normal fuzzing campaign runs it under afl-fuzz -Q with AFL_INST_LIBS=1 (it's a
thin lib-backed binary, so that auto-enables) and QEMU_LD_PREFIX=/firmware.

Mirrors CarvingService's network-less, non-root, read-only-root sandbox.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass
from uuid import UUID

import docker
import docker.errors
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.firmware import Firmware
from app.utils.sandbox import validate_path

logger = logging.getLogger(__name__)

# Architectures we bundle a cross toolchain for (must match harness-build image).
_SUPPORTED_ARCH_KEYS = {"armhf", "armel", "aarch64", "mips", "mipsel"}

_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# Scaffold wrapping the user-supplied harness body. The user defines
# `harness_one`; this provides main() reading the fuzz input (AFL file arg @@
# or stdin) into a buffer and calling it once.
_SCAFFOLD = """
/* ===== wairz harness scaffold ===== */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* The user body below must define:
 *     void harness_one(const unsigned char *data, size_t len);
 * declaring the target function(s) with their real (reverse-engineered)
 * signatures and calling them with the fuzz input.
 */
/* ===== user harness body ===== */
{user_source}
/* ===== wairz entrypoint ===== */
#ifndef WAIRZ_NO_MAIN
int main(int argc, char **argv) {{
    static unsigned char _wz_buf[1 << 20];
    size_t _wz_len;
    FILE *_wz_f = (argc > 1) ? fopen(argv[1], "rb") : stdin;
    if (!_wz_f) return 2;
    _wz_len = fread(_wz_buf, 1, sizeof(_wz_buf), _wz_f);
    if (argc > 1) fclose(_wz_f);
    harness_one(_wz_buf, _wz_len);
    return 0;
}}
#endif
"""


@dataclass
class HarnessBuildResult:
    ok: bool
    arch: str
    elf_virtual_path: str | None  # /_carved/harnesses/<name>
    log: str
    glibc_max: str | None = None
    # Entry address + ELF type for optional QEMU persistent-mode fuzzing.
    harness_one_addr: str | None = None
    elf_type: str | None = None


class HarnessBuildError(RuntimeError):
    pass


class HarnessBuildService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self._settings = get_settings()
        self._client: docker.DockerClient | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def build_harness(
        self,
        project_id: UUID,
        firmware_id: UUID,
        lib_path: str,
        harness_source: str,
        name: str,
        arch: str | None = None,
    ) -> HarnessBuildResult:
        if not _NAME_RE.match(name or ""):
            raise HarnessBuildError(
                "name must be a simple filename (alphanumeric, '.', '_', '-')"
            )
        if not harness_source or "harness_one" not in harness_source:
            raise HarnessBuildError(
                "harness_source must define `void harness_one(const unsigned "
                "char *data, size_t len)` (the fuzz entrypoint)."
            )

        firmware = await self._load_firmware(project_id, firmware_id)
        if not firmware.extracted_path or not os.path.isdir(firmware.extracted_path):  # noqa: ASYNC240 — pre-flight stat before bounded sync work
            raise HarnessBuildError("firmware has no extracted rootfs on disk")

        arch_key = self._resolve_arch(firmware, arch)

        # Resolve the target library to a path inside the rootfs and to the
        # path it will have inside the build container (/firmware/...).
        lib_real, lib_container = self._resolve_lib(firmware.extracted_path, lib_path)

        # Compose the full source and stage it + the output under carved/.
        carved_dir = self._ensure_carved_dir(firmware)
        harness_dir = os.path.join(carved_dir, "harnesses")  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
        os.makedirs(harness_dir, exist_ok=True)
        try:
            os.chmod(harness_dir, 0o2775)  # noqa: S103 — container-shared dir must be group-writable for non-root build user  # nosec B103
        except OSError:
            pass

        src_host = os.path.join(harness_dir, f"{name}.c")  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
        full_source = _SCAFFOLD.format(user_source=harness_source)
        with open(src_host, "w") as f:  # noqa: ASYNC230 — bounded file I/O in service path; analysis/patch target
            f.write(full_source)
        try:
            os.chmod(src_host, 0o664)  # nosec B103 — container-shared path needs group-writable bits for non-root build user
        except OSError:
            pass

        out_host = os.path.join(harness_dir, name)  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
        # Remove any stale ELF so we don't report success on a failed rebuild.
        try:
            os.remove(out_host)
        except FileNotFoundError:
            pass

        env = {
            "WZ_ARCH": arch_key,
            "WZ_SRC": f"/carved/harnesses/{name}.c",
            "WZ_LIB": lib_container,
            "WZ_OUT": f"/carved/harnesses/{name}",
        }
        log = await self._run_build(firmware, carved_dir, env)

        ok = os.path.isfile(out_host)  # noqa: ASYNC240 — pre-flight stat before bounded sync work

        def _grab(pat: str) -> str | None:
            m = re.search(pat, log)
            return m.group(1) if m else None

        return HarnessBuildResult(
            ok=ok,
            arch=arch_key,
            elf_virtual_path=f"/_carved/harnesses/{name}" if ok else None,
            log=log,
            glibc_max=_grab(r"GLIBC_MAX:\s*(\S+)"),
            harness_one_addr=_grab(r"ADDR_harness_one:\s*(\S+)"),
            elf_type=_grab(r"ELF_TYPE:\s*(\S+)"),
        )

    # ------------------------------------------------------------------
    # Build container (one-shot)
    # ------------------------------------------------------------------

    async def _run_build(
        self, firmware: Firmware, carved_dir: str, env: dict[str, str]
    ) -> str:
        client = self._get_docker_client()

        extracted_host = self._resolve_host_path(firmware.extracted_path)
        carved_host = self._resolve_host_path(carved_dir)
        if extracted_host is None or carved_host is None:
            raise HarnessBuildError(
                "could not resolve host paths for harness-build mounts"
            )

        volumes = {
            extracted_host: {"bind": "/firmware", "mode": "ro"},
            carved_host: {"bind": "/carved", "mode": "rw"},
        }

        def _run() -> str:
            container = client.containers.run(
                image=self._settings.harness_build_image,
                command=["/opt/build-harness.sh"],
                environment=env,
                detach=True,
                volumes=volumes,
                network_mode="none",
                mem_limit=f"{self._settings.harness_build_memory_limit_mb}m",
                nano_cpus=int(self._settings.harness_build_cpu_limit * 1e9),
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                read_only=True,
                tmpfs={"/tmp": "rw,size=512m,mode=1777"},
                user="1000:1000",
                working_dir="/carved",
                labels={"wairz.type": "harness-build",
                        "wairz.firmware_id": str(firmware.id)},
                auto_remove=False,
            )
            try:
                try:
                    container.wait(timeout=self._settings.harness_build_timeout)
                except Exception as exc:
                    logger.warning("harness build wait failed/timed out: %s", exc)
                    try:
                        container.kill()
                    except Exception:
                        pass
                logs = container.logs(stdout=True, stderr=True)
                return logs.decode("utf-8", errors="replace")
            finally:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

        return await asyncio.to_thread(_run)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_arch(self, firmware: Firmware, arch: str | None) -> str:
        if arch:
            key = arch.lower()
            if key not in _SUPPORTED_ARCH_KEYS:
                raise HarnessBuildError(
                    f"unsupported arch '{arch}'. Supported: "
                    f"{', '.join(sorted(_SUPPORTED_ARCH_KEYS))}"
                )
            return key

        fw_arch = (firmware.architecture or "").lower()
        if fw_arch in ("aarch64", "arm64"):
            return "aarch64"
        if fw_arch in ("mipsel", "mipsle"):
            return "mipsel"
        if fw_arch in ("mips", "mipsbe"):
            return "mips"
        if fw_arch in ("arm", "armhf", "armel"):
            # Hard-float (ARMv7/VFP) userlands need the eabihf toolchain.
            from app.services.emulation import EmulationService
            isa = EmulationService._detect_arm_isa(firmware.extracted_path)
            return "armhf" if isa == "armv7-hf" else "armel"
        raise HarnessBuildError(
            f"no bundled toolchain for firmware arch '{firmware.architecture}'. "
            f"Supported: {', '.join(sorted(_SUPPORTED_ARCH_KEYS))}. "
            "Pass arch= to override."
        )

    @staticmethod
    def _resolve_lib(extracted_path: str, lib_path: str) -> tuple[str, str]:
        """Resolve a firmware-relative .so path to (real_path, container_path).

        Accepts /rootfs/-prefixed or bare rootfs paths. container_path is where
        the .so appears inside the build sandbox (rootfs mounted at /firmware).
        """
        clean = lib_path.strip()
        for prefix in ("/rootfs/", "rootfs/"):
            if clean.startswith(prefix):
                clean = "/" + clean[len(prefix):]
                break
        real = validate_path(extracted_path, clean)
        if not os.path.isfile(real):  # noqa: ASYNC240 — pre-flight stat before bounded sync work
            raise HarnessBuildError(
                f"target library not found at firmware path '{lib_path}' "
                f"(resolved to {real})"
            )
        rel = os.path.relpath(os.path.realpath(real),  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
                              os.path.realpath(extracted_path))  # noqa: ASYNC240 — pre-flight stat before bounded sync work
        if rel.startswith(".."):
            raise HarnessBuildError("library path escapes the firmware rootfs")
        return real, "/firmware/" + rel

    async def _load_firmware(
        self, project_id: UUID, firmware_id: UUID
    ) -> Firmware:
        result = await self.db.execute(
            select(Firmware).where(
                Firmware.id == firmware_id,
                Firmware.project_id == project_id,
            )
        )
        firmware = result.scalar_one_or_none()
        if firmware is None:
            raise HarnessBuildError("firmware not found for this project")
        return firmware

    @staticmethod
    def _ensure_carved_dir(firmware: Firmware) -> str:
        if not firmware.storage_path:
            raise HarnessBuildError("firmware has no storage_path on disk")
        carved = os.path.join(os.path.dirname(firmware.storage_path), "carved")  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
        os.makedirs(carved, exist_ok=True)
        try:
            os.chmod(carved, 0o2775)  # noqa: S103 — container-shared dir must be group-writable for non-root build user  # nosec B103
        except OSError:
            pass
        return carved

    def _get_docker_client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def _resolve_host_path(self, container_path: str) -> str | None:
        """Translate an in-backend path to a host-visible path for bind mounts."""
        real_path = os.path.realpath(container_path)  # noqa: ASYNC240 — pre-flight stat before bounded sync work
        if not os.path.exists("/.dockerenv"):  # noqa: ASYNC240 — pre-flight stat before bounded sync work
            return real_path
        client = self._get_docker_client()
        hostname = os.environ.get("HOSTNAME", "")
        if not hostname:
            return real_path
        try:
            our_container = client.containers.get(hostname)
            for mount in our_container.attrs.get("Mounts", []):
                dest = mount.get("Destination", "")
                source = mount.get("Source", "")
                if not dest or not source:
                    continue
                if real_path.startswith(dest + os.sep) or real_path == dest:
                    relative = os.path.relpath(real_path, dest)
                    return os.path.join(source, relative)  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
        except Exception:
            logger.warning("harness-build path translation failed for %s", real_path)
        return None
