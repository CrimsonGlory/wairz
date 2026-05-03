"""Docker container lifecycle helpers for the emulation subpackage.

Extracted from ``emulation_service.py`` as step 2/7 of the Phase 5 split.

All functions here are free functions (not methods) — they either take a
``Container`` and stream files, or they take a path and resolve a host
translation. None depend on ``EmulationService`` instance state; the
Docker client is fetched via ``app.utils.docker_client.get_docker_client``
at call time rather than passed in, matching the monolith's pattern
(client-per-call, no caching).

Public surface:

- ``STUB_PROFILE_MAP`` — arch × profile → list of .so filenames.
- ``copy_dir_to_container`` — stream a host directory's contents into
  the container's dst_path via put_archive.
- ``copy_file_to_container`` — stream a single host file into the
  container's dst_path via put_archive.
- ``put_file_in_container`` — write literal string content into a file
  inside the container (avoids heredoc/shell escaping).
- ``fix_firmware_permissions`` — restore +x bits and repair corrupted
  symlinks after binwalk extraction.
- ``inject_stub_libraries`` — copy pre-compiled LD_PRELOAD stubs into
  the firmware rootfs, selected by stub_profile + architecture.
- ``read_container_qemu_log`` — read ``/tmp/qemu-system.log`` from a
  running/stopped container, truncated to max_bytes.
- ``resolve_host_path`` — map a backend-internal path to the host path
  the Docker daemon must mount to reach the same bytes.
"""

import io
import logging
import os
import tarfile

import docker

from app.utils.docker_client import get_docker_client

logger = logging.getLogger(__name__)


#: Stub-profile × architecture → list of .so filenames to copy from
#: ``/opt/stubs/`` inside the emulation image into the firmware rootfs.
#: Used by :func:`inject_stub_libraries`.
STUB_PROFILE_MAP: dict[str, dict[str, list[str]]] = {
    "none": {},
    "generic": {
        "mipsel": ["stubs_generic_mipsel.so"],
        "mips": ["stubs_generic_mips.so"],
        "arm": ["stubs_generic_arm.so"],
        "aarch64": ["stubs_generic_aarch64.so"],
    },
    "tenda": {
        "mipsel": ["stubs_generic_mipsel.so", "stubs_tenda_mipsel.so"],
        "mips": ["stubs_generic_mips.so", "stubs_tenda_mips.so"],
        "arm": ["stubs_generic_arm.so", "stubs_tenda_arm.so"],
        "aarch64": ["stubs_generic_aarch64.so", "stubs_tenda_aarch64.so"],
    },
}


def copy_dir_to_container(
    container: "docker.models.containers.Container",
    src_path: str,
    dst_path: str,
) -> None:
    """Copy a directory tree into a running container using put_archive.

    Creates a tar archive of ``src_path`` contents and streams it into
    ``dst_path`` inside the container.
    """
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode="w") as tar:
        # Add all files from src_path, with arcname="" so they land
        # directly in dst_path (not in a subdirectory)
        for entry in os.scandir(src_path):
            tar.add(entry.path, arcname=entry.name)
    tar_stream.seek(0)

    container.put_archive(dst_path, tar_stream)


def copy_file_to_container(
    container: "docker.models.containers.Container",
    src_path: str,
    dst_path: str,
) -> None:
    """Copy a single file into a running container using put_archive."""
    dst_dir = os.path.dirname(dst_path)
    dst_name = os.path.basename(dst_path)

    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode="w") as tar:
        tar.add(src_path, arcname=dst_name)
    tar_stream.seek(0)

    container.put_archive(dst_dir, tar_stream)


def put_file_in_container(
    container: "docker.models.containers.Container",
    path: str,
    content: str,
    mode: int = 0o755,
) -> None:
    """Write a file into a Docker container using put_archive.

    This avoids heredoc/shell escaping issues that can corrupt file content
    when using ``container.exec_run`` with ``cat << EOF``.
    """
    filename = os.path.basename(path)
    directory = os.path.dirname(path)

    data = content.encode("utf-8")
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode="w") as tar:
        info = tarfile.TarInfo(name=filename)
        info.size = len(data)
        info.mode = mode
        tar.addfile(info, io.BytesIO(data))
    tar_stream.seek(0)
    container.put_archive(directory, tar_stream)


def fix_firmware_permissions(
    container: "docker.models.containers.Container",
) -> None:
    """Fix execute permissions and broken symlinks in firmware.

    Binwalk extraction often loses execute bits and corrupts symlinks
    (replacing them with small files containing the original symlink
    target as text, or just null bytes). This function:
    1. Makes files in common binary/library directories executable.
    2. Restores corrupted symlinks across the entire firmware tree by
       reading small file contents to recover the original target path.
    3. Falls back to heuristics for .so versioned libraries and busybox.
    """
    bin_dirs = [
        "/firmware/bin", "/firmware/sbin",
        "/firmware/usr/bin", "/firmware/usr/sbin",
        "/firmware/lib", "/firmware/usr/lib",
        "/firmware/lib32", "/firmware/usr/lib32",
    ]
    for d in bin_dirs:
        # Use argv-list form with test + chmod to avoid any shell
        # interpolation. The test command returns 0 only when d exists;
        # non-zero exit from exec_run is intentionally ignored here.
        test_result = container.exec_run(["test", "-d", d])
        if test_result.exit_code == 0:
            container.exec_run(["chmod", "-R", "+x", d])

    # Generic symlink restoration script.
    # Binwalk corruption patterns:
    #   a) Small file whose content IS the symlink target (as text, possibly null-padded)
    #   b) Small file of pure null bytes (target lost — need heuristics)
    #
    # Strategy:
    #   Pass 1: Scan entire tree for small files (<256 bytes). Read content.
    #           If content looks like a path, restore symlink.
    #   Pass 2: Fix remaining .so stubs using versioned-name matching.
    #   Pass 3: Fix remaining null stubs in bin/sbin using busybox (if present).
    fix_symlinks_script = r"""
FIXED=0
PASS1=0
PASS2=0
PASS3=0

# --- Pass 1: Content-based symlink recovery (most reliable) ---
# Scan the entire firmware tree for small regular files whose content
# looks like a symlink target path (e.g., "busybox", "../lib/libc.so.6",
# "/usr/bin/python3").
find /firmware -type f -size -256c 2>/dev/null | while read stub; do
    # Read file content, strip null bytes and whitespace
    target=$(tr -d '\000' < "$stub" 2>/dev/null | tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    # Skip empty content
    [ -z "$target" ] && continue

    # Validate: target must look like a path (relative or absolute)
    # and contain only valid path characters
    case "$target" in
        /*|./*|../*)
            # Absolute or explicit relative path — good
            ;;
        *)
            # Bare name — only accept if it contains no spaces/specials
            # and is short (likely "busybox", "bash", etc.)
            case "$target" in
                *[[:space:]]*|*[^a-zA-Z0-9._-]*) continue ;;
            esac
            [ ${#target} -gt 64 ] && continue
            ;;
    esac

    # Don't create circular symlinks
    stubname=$(basename "$stub")
    targetname=$(basename "$target")
    [ "$stubname" = "$targetname" ] && [ "$target" = "$targetname" ] && continue

    # Replace the stub with a symlink
    rm -f "$stub"
    ln -s "$target" "$stub"
    PASS1=$((PASS1 + 1))
done

# --- Pass 2: Versioned .so heuristic for remaining stubs ---
# Some corrupted .so stubs may have been pure null (no readable target).
# Match libfoo.so -> libfoo.so.X.Y.Z by name pattern.
for dir in /firmware/lib /firmware/usr/lib /firmware/lib32 /firmware/usr/lib32; do
    [ -d "$dir" ] || continue
    for stub in $(find "$dir" -maxdepth 1 \( -name '*.so' -o -name '*.so.[0-9]*' \) 2>/dev/null); do
        # Skip if already a symlink (fixed in pass 1)
        [ -L "$stub" ] && continue
        [ -f "$stub" ] || continue
        size=$(stat -c%s "$stub" 2>/dev/null || echo 999999)
        [ "$size" -lt 256 ] || continue
        base=$(basename "$stub")
        best=""
        best_len=0
        for candidate in "$dir"/${base}*; do
            [ -f "$candidate" ] || [ -L "$candidate" ] || continue
            cand_name=$(basename "$candidate")
            [ "$cand_name" = "$base" ] && continue
            cand_size=$(stat -c%s "$candidate" 2>/dev/null || echo 0)
            [ "$cand_size" -gt 256 ] || [ -L "$candidate" ] || continue
            cand_len=${#cand_name}
            if [ "$cand_len" -gt "$best_len" ]; then
                best="$cand_name"
                best_len=$cand_len
            fi
        done
        if [ -n "$best" ]; then
            rm -f "$stub"
            ln -s "$best" "$stub"
            PASS2=$((PASS2 + 1))
        fi
    done
done

# --- Pass 3: Busybox fallback for remaining null stubs ---
# Only applies to files in bin/sbin dirs that are still tiny and not
# yet symlinks. This is the last resort for pure-null stubs.
bb=""
for candidate in /firmware/bin/busybox /firmware/usr/bin/busybox; do
    if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then
        cand_size=$(stat -c%s "$candidate" 2>/dev/null || echo 0)
        if [ "$cand_size" -gt 1000 ]; then
            # Strip /firmware prefix so symlinks work as both chroot
            # and ext4 root paths
            bb="${candidate#/firmware}"
            break
        fi
    fi
done
if [ -n "$bb" ]; then
    for dir in /firmware/bin /firmware/sbin /firmware/usr/bin /firmware/usr/sbin; do
        [ -d "$dir" ] || continue
        for stub in "$dir"/*; do
            # Skip symlinks (already fixed) and directories
            [ -L "$stub" ] && continue
            [ -f "$stub" ] || continue
            size=$(stat -c%s "$stub" 2>/dev/null || echo 999999)
            [ "$size" -lt 64 ] || continue
            name=$(basename "$stub")
            [ "$name" = "busybox" ] && continue
            # Verify it's actually null/empty content (not a real tiny script)
            content=$(tr -d '\000' < "$stub" 2>/dev/null)
            [ -z "$content" ] || continue
            rm -f "$stub"
            ln -s "$bb" "$stub"
            PASS3=$((PASS3 + 1))
        done
    done
fi

echo "Symlink repair: pass1=$PASS1 pass2=$PASS2 pass3=$PASS3"
"""
    result = container.exec_run(["sh", "-c", fix_symlinks_script])
    output = result.output.decode("utf-8", errors="replace").strip()
    if output:
        logger.info("Firmware symlink repair: %s", output)


def inject_stub_libraries(
    container: "docker.models.containers.Container",
    architecture: str | None,
    stub_profile: str = "none",
) -> None:
    """Copy arch-matched LD_PRELOAD stub libraries into the firmware rootfs.

    Pre-compiled stubs live in ``/opt/stubs/`` inside the emulation container.
    Based on the stub_profile, copies the appropriate .so files into
    ``/firmware/opt/stubs/`` so they're available inside the emulated firmware.

    Profiles:
      - ``"none"``: no stubs injected
      - ``"generic"``: MTD flash + wireless ioctl stubs
      - ``"tenda"``: generic + Tenda-specific function stubs
    """
    if stub_profile == "none" or not architecture:
        if stub_profile != "none":
            logger.debug("No architecture for stub injection, skipping")
        return

    arch_map = STUB_PROFILE_MAP.get(stub_profile, {})
    stub_files = arch_map.get(architecture, [])
    if not stub_files:
        logger.debug(
            "No stub libraries for profile=%s arch=%s", stub_profile, architecture
        )
        return

    # Build shell command to copy all stubs
    copy_cmds = ["mkdir -p /firmware/opt/stubs"]
    for stub_file in stub_files:
        copy_cmds.append(
            f"if [ -f /opt/stubs/{stub_file} ]; then "
            f"cp /opt/stubs/{stub_file} /firmware/opt/stubs/{stub_file} && "
            f"chmod 755 /firmware/opt/stubs/{stub_file} && "
            f"echo 'OK: {stub_file}'; else echo 'MISSING: {stub_file}'; fi"
        )

    result = container.exec_run(["sh", "-c", " && ".join(copy_cmds)])
    output = result.output.decode("utf-8", errors="replace").strip()
    for line in output.splitlines():
        if line.startswith("OK:"):
            logger.info("Injected stub: %s", line[4:].strip())
        elif line.startswith("MISSING:"):
            logger.warning("Stub not found in container: %s", line[9:].strip())


def read_container_qemu_log(
    container: "docker.models.containers.Container",
    max_bytes: int = 4000,
    quiet: bool = False,
) -> str:
    """Read QEMU launch log + serial-console buffer from inside a container.

    The launch log (/tmp/qemu-system.log) holds the start-system-mode.sh
    banner (kernel format, ext4 image creation, QEMU command line). The
    serial log (/tmp/qemu-serial.log) is QEMU's chardev ``logfile=`` — a
    passive copy of every byte that crossed the guest serial port,
    including kernel printk, init script output, and panic traces.

    Returns both, separated by a header. Falls back to container logs if
    neither file is available.
    """
    sections: list[str] = []
    try:
        result = container.exec_run(["cat", "/tmp/qemu-system.log"])
        launch = result.output.decode("utf-8", errors="replace")
        if len(launch) > max_bytes:
            launch = launch[-max_bytes:] + "\n... [truncated]"
        launch = launch.strip()
        sections.append(launch if launch else "(launch log empty)")
    except Exception:
        if not quiet:
            logger.debug("Could not read QEMU launch log from container", exc_info=True)

    try:
        # Strip null bytes — QEMU pads serial output with them on some
        # arch/console combinations and they confuse downstream readers.
        result = container.exec_run([
            "sh", "-c",
            "[ -f /tmp/qemu-serial.log ] && tr -d '\\000' "
            "< /tmp/qemu-serial.log || true",
        ])
        serial = result.output.decode("utf-8", errors="replace")
        if len(serial) > max_bytes:
            serial = serial[-max_bytes:] + "\n... [truncated]"
        serial = serial.strip()
        if serial:
            sections.append(
                "--- Serial console (kernel + init output) ---\n" + serial
            )
    except Exception:
        if not quiet:
            logger.debug("Could not read QEMU serial log from container", exc_info=True)

    if sections:
        return "\n\n".join(sections)

    # Fall back to container logs if we couldn't read either file.
    try:
        log = container.logs(tail=50).decode("utf-8", errors="replace")
        return log.strip() if log.strip() else "(no log available)"
    except Exception:
        logger.debug("Failed to read container logs", exc_info=True)
        return "(no log available)"


def resolve_host_path(container_path: str) -> str | None:
    """Resolve a path inside this container to a host path for Docker mounts.

    When the backend runs inside Docker and uses the Docker socket, volume
    mounts reference HOST paths, not container paths. This function
    inspects our own container's mounts to translate paths.

    If not running in Docker, returns the path as-is.
    Returns ``None`` if the path is not on any mount (baked into image).
    """
    real_path = os.path.realpath(container_path)

    # Not running in Docker — path is already a host path
    if not os.path.exists("/.dockerenv"):
        return real_path

    client = get_docker_client()

    # Find our own container by hostname (Docker sets HOSTNAME to container ID)
    hostname = os.environ.get("HOSTNAME", "")
    if not hostname:
        return real_path

    try:
        our_container = client.containers.get(hostname)
        mounts = our_container.attrs.get("Mounts", [])

        for mount in mounts:
            dest = mount.get("Destination", "")
            source = mount.get("Source", "")
            if not dest or not source:
                continue

            # Check if our path falls under this mount
            if real_path.startswith(dest + os.sep) or real_path == dest:
                relative = os.path.relpath(real_path, dest)
                host_path = os.path.join(source, relative)
                logger.info(
                    "Path translation: %s -> %s (via mount %s -> %s)",
                    real_path, host_path, source, dest,
                )
                return host_path

    except Exception:
        logger.warning(
            "Could not inspect own container for path translation: %s",
            real_path, exc_info=True,
        )

    # Path is not on any Docker mount — baked into the container image
    return None
