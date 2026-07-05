"""RTOS detection service — identifies RTOS and companion components from firmware binaries.

5-tier detection: magic bytes, string patterns, symbols, ELF sections, VxWorks symtab heuristic.
Also detects companion components: network stacks, filesystems, crypto libraries.
Synchronous module — call via loop.run_in_executor() in async code.
"""

import logging
import re
import struct

logger = logging.getLogger(__name__)
MAX_SCAN_SIZE = 1024 * 1024  # 1MB for string scanning

# LIEF lazy-loading (same pattern as binary_analysis_service.py)
_lief_loaded = False
_lief = None


def _ensure_lief():
    global _lief_loaded, _lief
    if _lief_loaded:
        return
    try:
        import lief
        _lief = lief
    except ImportError:
        logger.warning("LIEF not installed — tier 3/4 detection unavailable")
    _lief_loaded = True


# -- Helpers ---------------------------------------------------------------

def _result(name: str, display: str, version: str | None, confidence: str,
            methods: list[str], meta: dict | None = None) -> dict:
    return {"rtos_name": name, "rtos_display_name": display, "version": version,
            "confidence": confidence, "detection_methods": methods,
            "metadata": meta or {}}


def _extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    strings, current = [], bytearray()
    for byte in data:
        if 0x20 <= byte < 0x7F:
            current.append(byte)
        else:
            if len(current) >= min_length:
                strings.append(current.decode("ascii"))
            current = bytearray()
    if len(current) >= min_length:
        strings.append(current.decode("ascii"))
    return strings


def _read_bytes(path: str, max_bytes: int | None = None) -> bytes:
    with open(path, "rb") as f:
        return f.read(max_bytes) if max_bytes else f.read()


def _parse_binary(path: str):
    _ensure_lief()
    if _lief is None:
        return None
    try:
        return _lief.parse(path)
    except Exception:
        return None


def _get_arch_endian(binary) -> tuple[str | None, str | None]:
    _ensure_lief()
    if _lief is None or binary is None:
        return None, None
    try:
        if isinstance(binary, _lief.ELF.Binary):
            h = binary.header
            arch_map = {_lief.ELF.ARCH.ARM: "arm", _lief.ELF.ARCH.AARCH64: "aarch64",
                        _lief.ELF.ARCH.MIPS: "mips", _lief.ELF.ARCH.I386: "x86",
                        _lief.ELF.ARCH.X86_64: "x86_64", _lief.ELF.ARCH.PPC: "ppc",
                        _lief.ELF.ARCH.PPC64: "ppc64"}
            arch = arch_map.get(h.machine_type)
            endian = "big" if h.identity_data == _lief.ELF.ELF_DATA.MSB else "little"
            return arch, endian
        if isinstance(binary, _lief.PE.Binary):
            pe_map = {_lief.PE.Header.MACHINE_TYPES.I386: "x86",
                      _lief.PE.Header.MACHINE_TYPES.AMD64: "x86_64",
                      _lief.PE.Header.MACHINE_TYPES.ARM: "arm",
                      _lief.PE.Header.MACHINE_TYPES.ARM64: "aarch64"}
            return pe_map.get(binary.header.machine), "little"
    except Exception:
        pass
    return None, None


def _get_symbols(binary) -> set[str]:
    names: set[str] = set()
    if binary is None:
        return names
    _ensure_lief()
    if _lief is None:
        return names
    try:
        if isinstance(binary, _lief.ELF.Binary):
            for s in binary.symtab_symbols:
                if s.name:
                    names.add(s.name)
            for s in binary.dynamic_symbols:
                if s.name:
                    names.add(s.name)
        elif isinstance(binary, _lief.PE.Binary):
            for s in binary.symbols:
                if s.name:
                    names.add(s.name)
            if binary.has_exports:
                for e in binary.get_export().entries:
                    if e.name:
                        names.add(e.name)
            for imp in binary.imports:
                for e in imp.entries:
                    if e.name:
                        names.add(e.name)
    except Exception:
        pass
    return names


def _get_sections(binary) -> set[str]:
    names: set[str] = set()
    if binary is None:
        return names
    try:
        for s in binary.sections:
            if s.name:
                names.add(s.name)
    except Exception:
        pass
    return names


def _count_hits(symbols: set[str], targets: list[str]) -> int:
    return sum(1 for t in targets if t in symbols)


# -- Tier 1: Magic bytes ---------------------------------------------------

def _tier1_magic(data: bytes) -> dict | None:
    if len(data) < 8:
        return None
    h4 = struct.unpack_from("<I", data, 0)[0]

    # Zephyr MCUboot: 0x96f3b83d
    if h4 == 0x96F3B83D:
        ver, meta = None, {}
        if len(data) >= 0x1C:
            maj, mn = struct.unpack_from("<BB", data, 0x14)
            rev, bld = struct.unpack_from("<HI", data, 0x16)
            ver = f"{maj}.{mn}.{rev}+{bld}"
            meta["mcuboot_version"] = ver
        return _result("zephyr", "Zephyr", ver, "high", ["magic_bytes"], meta)

    # QNX startup header: 0x00ff7eeb
    if h4 == 0x00FF7EEB:
        endian = "little"
        if len(data) >= 8:
            flags1 = struct.unpack_from("<H", data, 0x06)[0]
            if flags1 & 0x02:
                endian = "big"
        return _result("qnx", "QNX Neutrino", None, "high", ["magic_bytes"],
                        {"endianness_from_header": endian})

    # QNX IFS: "imagefs" / "sfegami"
    if data[:7] in (b"imagefs", b"sfegami"):
        endian = "little" if data[:7] == b"imagefs" else "big"
        return _result("qnx", "QNX Neutrino", None, "high", ["magic_bytes"],
                        {"image_type": "IFS", "endianness_from_header": endian})

    # VxWorks MemFS: "OWOWOWOW"
    if data[:8] == b"OWOWOWOW":
        return _result("vxworks", "VxWorks", None, "medium", ["magic_bytes"],
                        {"image_type": "MemFS"})

    # Zephyr binary descriptor in first 64KB
    zd_magic = struct.pack("<Q", 0xB9863E5A7EA46046)
    pos = data[:min(len(data), 65536)].find(zd_magic)
    if pos >= 0:
        ver, meta = None, {}
        try:
            off = pos + 8
            for _ in range(32):
                if off + 4 > len(data):
                    break
                tag_t, tag_l = struct.unpack_from("<HH", data, off)
                if tag_t == 0 or tag_l == 0:
                    break
                if tag_t == 0x1900 and off + 4 + tag_l <= len(data):
                    ver = data[off + 4:off + 4 + tag_l].decode("ascii", errors="ignore").rstrip("\x00")
                    meta["kernel_version_tag"] = ver
                    break
                off += 4 + tag_l
        except Exception:
            pass
        return _result("zephyr", "Zephyr", ver, "high", ["magic_bytes"], meta)
    return None


# -- Tier 2: String patterns -----------------------------------------------

_THREADX_RE = re.compile(r"ThreadX\s+[\w\-]+/[\w\-]+\s+Version\s+[G]?(\d[\d.]+)")
_FREERTOS_RE = re.compile(r"FreeRTOS\s+V(\d+\.\d+\.\d+)")
_VXWORKS_VER_RE = re.compile(r"VxWorks.*version\s+'(\d+\.\d+)")
_WIND_VER_RE = re.compile(r"WIND version\s+(\d+\.\d+)")
_VXWORKS_BOOT_RE = re.compile(r"\w+\(\d+,\d+\)\S+:\S+\s+[ehbgufst]\w*=")
_ZEPHYR_BOOT_RE = re.compile(r"Booting Zephyr OS build\s+(\S+)")
_ZEPHYR_VER_RE = re.compile(r"zephyr-v(\d+\.\d+\.\d+)")
_QNX_VER_RE = re.compile(r"QNX Neutrino\s+(\d+\.\d+)")
_SAFERTOS_VER_RE = re.compile(r"SafeRTOS\s+V(\d+)")


def _tier2_strings(strings: list[str]) -> dict | None:
    joined = "\n".join(strings)
    string_set = set(strings)

    # ThreadX (VERY HIGH — _tx_version_id always present)
    m = _THREADX_RE.search(joined)
    if m:
        return _result("threadx", "ThreadX", m.group(1), "high", ["version_string"])

    # uC/OS-III
    if any(s in joined for s in ("uC/OS-III Idle Task", "uC/OS-III Stat Task", "uC/OS-III Timer Task")):
        return _result("ucos-iii", "uC/OS-III", None, "high", ["version_string"])

    # uC/OS-II
    if any(s in joined for s in ("uC/OS-II Idle", "uC/OS-II Stat")):
        return _result("ucos-ii", "uC/OS-II", None, "high", ["version_string"])

    # FreeRTOS version string
    m = _FREERTOS_RE.search(joined)
    if m:
        is_amazon = "Amazon FreeRTOS" in joined
        n = "amazon-freertos" if is_amazon else "freertos"
        d = "Amazon FreeRTOS" if is_amazon else "FreeRTOS"
        return _result(n, d, m.group(1), "high", ["version_string"])

    if "Amazon FreeRTOS" in joined:
        return _result("amazon-freertos", "Amazon FreeRTOS", None, "high", ["version_string"])

    # VxWorks explicit
    if "VxWorks" in joined:
        ver = None
        m = _VXWORKS_VER_RE.search(joined) or _WIND_VER_RE.search(joined)
        if m:
            ver = m.group(1)
        return _result("vxworks", "VxWorks", ver, "high", ["version_string"])

    # Zephyr boot/version
    for rx in (_ZEPHYR_BOOT_RE, _ZEPHYR_VER_RE):
        m = rx.search(joined)
        if m:
            return _result("zephyr", "Zephyr", m.group(1), "high", ["version_string"])

    # QNX Neutrino
    m = _QNX_VER_RE.search(joined)
    if m:
        return _result("qnx", "QNX Neutrino", m.group(1), "high", ["version_string"])

    # SafeRTOS
    m = _SAFERTOS_VER_RE.search(joined)
    if m:
        return _result("safertos", "SafeRTOS", m.group(1), "high", ["version_string"])
    if "SAFERTOS" in joined:
        return _result("safertos", "SafeRTOS", None, "high", ["version_string"])

    # VxWorks boot line (MEDIUM)
    if _VXWORKS_BOOT_RE.search(joined):
        return _result("vxworks", "VxWorks", None, "medium", ["version_string"],
                        {"matched": "boot_line_pattern"})

    # FreeRTOS fallback: co-occurrence of IDLE + Tmr Svc (MEDIUM)
    if "IDLE" in string_set and "Tmr Svc" in string_set:
        return _result("freertos", "FreeRTOS", None, "medium", ["version_string"],
                        {"matched": "task_name_heuristic"})
    return None


# -- Tier 3: Symbol/function name scan -------------------------------------

# (rtos_name, display, high_symbols, medium_symbols)
_SYM_SIGS: list[tuple[str, str, list[str], list[str]]] = [
    ("freertos", "FreeRTOS",
     ["xTaskCreate", "vTaskStartScheduler", "pvPortMalloc", "vPortFree", "xPortSysTickHandler"],
     ["xQueueCreate", "xSemaphoreCreateBinary", "xTimerCreate"]),
    ("zephyr", "Zephyr",
     ["k_thread_create", "k_sem_init", "z_cstart", "z_main_thread"],
     ["k_mutex_init", "k_msgq_init", "k_work_init"]),
    ("vxworks", "VxWorks",
     ["taskSpawn", "semBCreate", "msgQCreate", "kernelVersion", "tickAnnounce"],
     ["muxDevLoad", "intConnect", "sysClkRateGet"]),
    ("threadx", "ThreadX",
     ["tx_kernel_enter", "tx_thread_create", "tx_application_define"],
     ["tx_semaphore_create", "tx_mutex_create", "tx_queue_create"]),
    ("qnx", "QNX Neutrino",
     ["ChannelCreate", "ConnectAttach", "MsgSend", "MsgReceive", "MsgReply"],
     ["resmgr_attach", "dispatch_create", "pulse_attach"]),
    ("ucos", "uC/OS",
     ["OSInit", "OSStart", "OSTaskCreate", "OSTimeDly", "OSVersion"], []),
]
_UCOS3_ONLY = ["OSTaskQPend", "OSTaskQPost", "OSTaskSemPend", "OSTaskSemPost"]


def _tier3_symbols(symbols: set[str]) -> dict | None:
    if not symbols:
        return None

    # SafeRTOS: xTaskInitializeScheduler, or FreeRTOS symbols WITHOUT pvPortMalloc
    freertos_hi = ["xTaskCreate", "vTaskStartScheduler", "pvPortMalloc", "vPortFree", "xPortSysTickHandler"]
    has_fr = _count_hits(symbols, freertos_hi) >= 2
    if "xTaskInitializeScheduler" in symbols or (has_fr and "pvPortMalloc" not in symbols):
        indicator = "xTaskInitializeScheduler" if "xTaskInitializeScheduler" in symbols else "freertos_without_pvPortMalloc"
        return _result("safertos", "SafeRTOS", None, "high", ["symbols"],
                        {"safertos_indicator": indicator})

    # uC/OS-III vs uC/OS-II
    ucos_hi = ["OSInit", "OSStart", "OSTaskCreate", "OSTimeDly", "OSVersion"]
    if _count_hits(symbols, ucos_hi) >= 3:
        if _count_hits(symbols, _UCOS3_ONLY) >= 2:
            return _result("ucos-iii", "uC/OS-III", None, "high", ["symbols"])
        return _result("ucos", "uC/OS", None, "high", ["symbols"])

    # General symbol matching
    for name, display, hi_syms, med_syms in _SYM_SIGS:
        h = _count_hits(symbols, hi_syms)
        m = _count_hits(symbols, med_syms)
        if h >= 3:
            return _result(name, display, None, "high", ["symbols"],
                           {"high_symbol_matches": h, "medium_symbol_matches": m})
        if h >= 2 and m >= 1:
            return _result(name, display, None, "medium", ["symbols"],
                           {"high_symbol_matches": h, "medium_symbol_matches": m})
    return None


# -- Tier 4: ELF section scan ----------------------------------------------

_ZEPHYR_SECTS = {".device_handles", "_k_sem_area", ".init_PRE_KERNEL_1",
                  "_k_timer_area", "_k_mutex_area", "_k_msgq_area",
                  "_k_heap_area", "_k_event_area", "_k_queue_area"}
_QNX_SECTS = {".QNX_info", ".QNX_usage"}


def _tier4_sections(binary, sections: set[str]) -> dict | None:
    _ensure_lief()
    if _lief is None or binary is None:
        return None

    z_hits = sections & _ZEPHYR_SECTS
    if len(z_hits) >= 2:
        return _result("zephyr", "Zephyr", None, "high", ["sections"],
                        {"matched_sections": sorted(z_hits)})

    q_hits = sections & _QNX_SECTS
    if q_hits:
        return _result("qnx", "QNX Neutrino", None, "high", ["sections"],
                        {"matched_sections": sorted(q_hits)})

    # QNX ELF OSABI == 3
    try:
        if isinstance(binary, _lief.ELF.Binary):
            ident = binary.header.identity
            if len(ident) > 7 and ident[7] == 3:
                return _result("qnx", "QNX Neutrino", None, "high", ["elf_osabi"],
                               {"osabi": 3})
    except Exception:
        pass
    return None


# -- Tier 5: VxWorks symbol table heuristic --------------------------------

_VXW_MARKERS = [b"\x00bzero\x00", b"\x00usrInit\x00", b"\x00bfill\x00",
                b"\x00_bzero\x00", b"\x00_usrInit\x00"]
_VALID_SYMTYPES = set(range(20))
_ENTRY_SIZES = [0x10, 0x14, 0x18]


def _tier5_vxworks_symtab(data: bytes) -> dict | None:
    if len(data) < 100 * 1024:
        return None
    for marker in _VXW_MARKERS:
        pos = data.find(marker)
        if pos < 0:
            continue
        for esz in _ENTRY_SIZES:
            base = pos - (pos % esz)
            consecutive, off = 0, base
            while off + esz <= len(data) and consecutive < 100:
                if data[off + esz - 1] == 0x00 and data[off + esz - 2] in _VALID_SYMTYPES:
                    consecutive += 1
                    off += esz
                else:
                    break
            if consecutive >= 20:
                return _result("vxworks", "VxWorks", None, "high",
                               ["symbol_table_heuristic"],
                               {"entry_size": esz, "consecutive_entries": consecutive})
    return None


# -- FreeRTOS heap variant detection ----------------------------------------

def _detect_freertos_heap(symbols: set[str], strings: list[str]) -> str | None:
    if "vPortDefineHeapRegions" in symbols:
        return "heap_5"
    joined = " ".join(strings)
    all_names = symbols | set(strings)
    if "xFreeBytesRemaining" in joined or "xFreeBytesRemaining" in symbols:
        return "heap_2" if ("xBlockAllocatedBit" in joined or "xBlockAllocatedBit" in symbols) else "heap_4"
    if "pvPortMalloc" in symbols and "vPortFree" not in symbols:
        return "heap_1"
    return None


# -- Companion component detection ------------------------------------------

# (name, category, comp_type, symbols, version_regex, string_marker)
_COMPANIONS: list[tuple[str, str, str, list[str], str | None, str | None]] = [
    # Network stacks
    ("lwIP", "network_stack", "library",
     ["pbuf_alloc", "tcp_write", "udp_send", "netconn_new", "netif_add", "lwip_socket"],
     r"lwIP/(\d+\.\d+\.\d+)", None),
    ("FreeRTOS+TCP", "network_stack", "library",
     ["FreeRTOS_socket", "FreeRTOS_sendto", "FreeRTOS_IPInit"],
     r"V(\d+\.\d+\.\d+)", None),
    ("NetX Duo", "network_stack", "library",
     ["nx_ip_create", "nx_packet_pool_create", "nx_tcp_socket_create"], None, "NetX"),
    ("uIP", "network_stack", "library", ["uip_init", "uip_input", "uip_send"], None, None),
    ("Zephyr Net", "network_stack", "library",
     ["net_if_get_default", "net_context_connect", "net_pkt_alloc"], None, None),
    # Filesystems
    ("LittleFS", "filesystem", "library",
     ["lfs_mount", "lfs_file_open", "lfs_format"], None, None),
    ("FatFS", "filesystem", "library",
     ["f_mount", "f_open", "f_read", "f_write"], None, "FatFs"),
    ("SPIFFS", "filesystem", "library", ["SPIFFS_mount", "SPIFFS_open"], None, None),
    ("FileX", "filesystem", "library", ["fx_media_open", "fx_file_open"], None, "FileX"),
    # Crypto
    ("wolfSSL", "crypto", "library",
     ["wolfSSL_Init", "wolfSSL_CTX_new", "wc_InitSha256"],
     r"wolfSSL[^\d]*(\d+\.\d+\.\d+)", "wolfSSL"),
    ("mbedTLS", "crypto", "library",
     ["mbedtls_ssl_init", "mbedtls_sha256_init", "mbedtls_aes_init"],
     r"Mbed TLS (\d+\.\d+\.\d+)", None),
    ("tinycrypt", "crypto", "library",
     ["tc_sha256_init", "tc_aes128_set_encrypt_key"], None, None),
    ("BearSSL", "crypto", "library",
     ["br_ssl_client_init_full", "br_sha256_init"], None, None),
]

_LITTLEFS_MAGIC = b"littlefs"
_SPIFFS_MAGIC = struct.pack("<I", 0x20140529)
_MBEDTLS_POLAR_RE = re.compile(r"PolarSSL (\d+\.\d+\.\d+)")


def extract_companion_components(file_path: str) -> list[dict]:
    """Extract companion components (network stacks, filesystems, crypto libs).

    Args:
        file_path: Path to the firmware binary file.

    Returns:
        List of dicts with name, version, type, category, confidence, detection_method.
    """
    results: list[dict] = []
    try:
        data = _read_bytes(file_path, MAX_SCAN_SIZE)
    except OSError:
        logger.warning("Cannot read file for companion detection: %s", file_path)
        return results

    strings = _extract_strings(data)
    joined = "\n".join(strings)
    binary = _parse_binary(file_path)
    symbols = _get_symbols(binary) if binary else set()
    seen: set[str] = set()

    for name, cat, ctype, sym_list, ver_re, str_marker in _COMPANIONS:
        if name in seen:
            continue
        matched_by, version = None, None
        hits = _count_hits(symbols, sym_list)
        if hits >= 2:
            matched_by = "symbols"
        if str_marker and str_marker in joined:
            matched_by = matched_by or "version_string"
        if not matched_by:
            continue
        if ver_re:
            m = re.search(ver_re, joined)
            if m:
                version = m.group(1)
                matched_by = "version_string"
        seen.add(name)
        results.append({"name": name, "version": version, "type": ctype,
                        "category": cat, "confidence": "high" if hits >= 3 else "medium",
                        "detection_method": matched_by})

    # Magic-byte detections
    if _LITTLEFS_MAGIC in data and "LittleFS" not in seen:
        results.append({"name": "LittleFS", "version": None, "type": "library",
                        "category": "filesystem", "confidence": "high",
                        "detection_method": "magic_bytes"})
    if _SPIFFS_MAGIC in data and "SPIFFS" not in seen:
        results.append({"name": "SPIFFS", "version": None, "type": "library",
                        "category": "filesystem", "confidence": "medium",
                        "detection_method": "magic_bytes"})
    if "FatFS" not in seen and any(m in joined for m in ("FatFs", "ChaN")):
        results.append({"name": "FatFS", "version": None, "type": "library",
                        "category": "filesystem", "confidence": "high",
                        "detection_method": "version_string"})

    # mbedTLS PolarSSL fallback version
    for r in results:
        if r["name"] == "mbedTLS" and r["version"] is None:
            m = _MBEDTLS_POLAR_RE.search(joined)
            if m:
                r["version"] = m.group(1)
    return results


# -- Main API --------------------------------------------------------------

def detect_rtos(file_path: str) -> dict | None:
    """Detect RTOS from a binary file.

    Runs a 5-tier detection pipeline from most specific (magic bytes) to
    least specific (VxWorks symbol table heuristic). Returns a structured
    result dict on the first confident match, or None if no RTOS detected.

    Args:
        file_path: Path to the firmware binary file.

    Returns:
        Dict with rtos_name, rtos_display_name, version, confidence,
        detection_methods, architecture, endianness, and metadata — or None.
    """
    try:
        data = _read_bytes(file_path, MAX_SCAN_SIZE)
    except OSError:
        logger.warning("Cannot read file for RTOS detection: %s", file_path)
        return None

    # Tier 1: Magic bytes
    result = _tier1_magic(data)

    # Tier 2: String patterns
    strings: list[str] = []
    if result is None:
        strings = _extract_strings(data)
        result = _tier2_strings(strings)

    # Parse binary for tiers 3-4
    binary = _parse_binary(file_path)
    symbols = _get_symbols(binary) if binary else set()
    sections = _get_sections(binary) if binary else set()

    # Tier 3: Symbols
    if result is None:
        result = _tier3_symbols(symbols)

    # Tier 4: ELF sections
    if result is None:
        result = _tier4_sections(binary, sections)

    # Tier 5: VxWorks symbol table heuristic
    if result is None:
        full_data = data
        if len(data) == MAX_SCAN_SIZE:
            try:
                full_data = _read_bytes(file_path)
            except OSError:
                pass
        result = _tier5_vxworks_symtab(full_data)

    if result is None:
        return None

    # Enrich with architecture/endianness
    arch, endian = _get_arch_endian(binary)
    result["architecture"] = arch
    result["endianness"] = endian

    # Cross-tier corroboration: if strings matched but symbols also match, merge
    if symbols and result.get("detection_methods"):
        sym_result = _tier3_symbols(symbols)
        if sym_result and sym_result["rtos_name"] == result["rtos_name"]:
            methods = set(result["detection_methods"])
            methods.update(sym_result["detection_methods"])
            result["detection_methods"] = sorted(methods)
            if result["confidence"] == "medium":
                result["confidence"] = "high"

    # FreeRTOS heap variant
    if result["rtos_name"] in ("freertos", "amazon-freertos"):
        if not strings:
            strings = _extract_strings(data)
        heap = _detect_freertos_heap(symbols, strings)
        if heap:
            result.setdefault("metadata", {})["heap_variant"] = heap

    return result


# ---------------------------------------------------------------------------
# Lightweight kind classifier — used by the unpack pipeline to tag each
# firmware as "linux", "rtos", or "unknown" immediately after extraction.
# This is a separate, simpler path from the detailed ``detect_rtos`` above:
# detect_rtos is used by MCP tools for rich RTOS analysis; detect_firmware_kind
# is the fast gating step in the unpack worker.
# ---------------------------------------------------------------------------

import os
from dataclasses import dataclass

from elftools.elf.elffile import ELFFile

# String markers — byte literals so we can scan raw binaries without
# decoding. Each tuple is (marker, weight). We require either one
# weight>=2 hit or two weight==1 hits to call a flavor.
_FREERTOS_MARKERS: tuple[tuple[bytes, int], ...] = (
    (b"xTaskCreate", 2),
    (b"pxCurrentTCB", 2),
    (b"vTaskStartScheduler", 2),
    (b"FreeRTOS", 1),
    (b"vTaskDelay", 1),
    (b"prvIdleTask", 1),
    (b"xQueueGenericSend", 1),
)

_ZEPHYR_MARKERS: tuple[tuple[bytes, int], ...] = (
    (b"Booting Zephyr OS", 3),
    (b"ZEPHYR_BASE", 2),
    (b"z_thread_", 1),
    (b"k_thread_create", 1),
    (b"_ZEPHYR_", 1),
    (b"sys_clock_announce", 1),
)

# Heuristics for baremetal Cortex-M: we look for ARM ELFs *without* any
# of the above RTOS markers and with a vector-table-like layout.
_FLAVOR_THRESHOLD = 2  # cumulative weight needed to call a match

# How much of each candidate file to scan. Most RTOS images are small
# (< 4 MB); cap at 16 MB so a misclassified Linux blob doesn't blow
# memory if it gets here.
_SCAN_BUDGET_BYTES = 16 * 1024 * 1024


@dataclass
class KindDetection:
    kind: str  # "linux" | "rtos" | "unknown"
    flavor: str | None
    notes: str


def _score_markers(
    blob: bytes, markers: tuple[tuple[bytes, int], ...]
) -> int:
    """Sum weights of every marker present in *blob*."""
    return sum(weight for marker, weight in markers if marker in blob)


def _read_capped(path: str, cap: int = _SCAN_BUDGET_BYTES) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(cap)
    except OSError:
        return b""


def _candidate_files(
    firmware_path: str, extraction_dir: str | None
) -> list[str]:
    """Files worth scanning for RTOS signatures.

    Always include the original firmware image. If we have an extraction
    directory, also include any ELFs and any large flat binaries siblings
    found in it (those are usually the kernel/firmware blob binwalk
    surfaced from a wrapping container format).
    """
    seen: set[str] = set()
    out: list[str] = []

    def _add(p: str) -> None:
        rp = os.path.realpath(p)
        if rp in seen:
            return
        seen.add(rp)
        out.append(p)

    if os.path.isfile(firmware_path):
        _add(firmware_path)

    if not extraction_dir or not os.path.isdir(extraction_dir):
        return out

    # Walk the extraction tree, collecting ELFs and big flat blobs. Cap
    # at ~30 candidates so degenerate trees don't make us scan forever.
    max_candidates = 30
    for root, _dirs, files in os.walk(extraction_dir):
        for name in files:
            if len(out) >= max_candidates:
                return out
            full = os.path.join(root, name)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            # Skip tiny files; signatures don't fit
            if size < 1024:
                continue
            ext = os.path.splitext(name)[1].lower()
            # Skip JSON/log sidecars binwalk leaves around
            if ext in {".json", ".txt", ".log"}:
                continue
            _add(full)

    return out


def _detect_freertos_or_zephyr(
    candidates: list[str],
) -> tuple[str | None, str]:
    """Return ``(flavor, notes)`` if any candidate matches FreeRTOS/Zephyr."""
    best: tuple[int, str | None, str] = (0, None, "")  # (score, flavor, source path)

    for path in candidates:
        blob = _read_capped(path)
        if not blob:
            continue
        for flavor, markers in (
            ("freertos", _FREERTOS_MARKERS),
            ("zephyr", _ZEPHYR_MARKERS),
        ):
            score = _score_markers(blob, markers)
            if score >= _FLAVOR_THRESHOLD and score > best[0]:
                best = (score, flavor, path)

    if best[1] is None:
        return None, ""
    return best[1], f"matched {best[1]} markers (score={best[0]}) in {os.path.basename(best[2])}"


def _looks_like_cortex_m_elf(path: str) -> bool:
    """Whether *path* is an ARM ELF that walks like baremetal Cortex-M.

    Heuristic: ARM ELF (e_machine == EM_ARM) with ARM v6-M / v7-M / v8-M
    architecture tag, OR a section called ``.isr_vector`` / a symbol
    ``Reset_Handler``. We can't reliably read attributes from every
    toolchain output so we look at multiple weak signals.
    """
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != b"\x7fELF":
                return False
            f.seek(0)
            elf = ELFFile(f)
            if elf.header.e_machine != "EM_ARM":
                return False

            # .isr_vector is the canonical Cortex-M vector-table section
            # name across CMSIS and Zephyr/STM32/NXP startup files.
            for section in elf.iter_sections():
                name = section.name or ""
                if name in (".isr_vector", ".vectors", ".vector_table"):
                    return True

            # Symbol fallback — Reset_Handler is the ARM-Cortex-M ABI
            # convention; ARM A-profile uses _start instead.
            symtab = elf.get_section_by_name(".symtab")
            if symtab is not None:
                for sym in symtab.iter_symbols():
                    if sym.name in ("Reset_Handler", "g_pfnVectors"):
                        return True
    except Exception:
        return False
    return False


def _looks_like_cortex_m_raw(path: str) -> bool:
    """Heuristic vector-table check on a raw (non-ELF) firmware blob.

    Cortex-M reset state: word 0 = initial SP (must point into RAM),
    word 1 = Reset_Handler address (must be in flash with the Thumb bit
    set, i.e. odd). We sample a handful of vendor RAM/flash splits — the
    common ones, not exhaustively.
    """
    try:
        with open(path, "rb") as f:
            head = f.read(8)
            if len(head) < 8:
                return False
    except OSError:
        return False

    initial_sp, reset_handler = struct.unpack("<II", head)

    # Reset handler must have the Thumb bit set on Cortex-M
    if reset_handler & 1 == 0:
        return False

    # Initial SP commonly lives in 0x20000000 (SRAM) or 0x10000000.
    # Reset handler commonly lives in 0x00000000 (alias), 0x08000000
    # (STM32 flash), 0x00100000 (NXP), 0x00010000 (TI). We accept these
    # ranges as evidence; one false positive is cheaper than a miss
    # because the user can override.
    sp_ok = (
        0x20000000 <= initial_sp <= 0x2FFFFFFF
        or 0x10000000 <= initial_sp <= 0x1FFFFFFF
    )
    reset_target = reset_handler & ~1
    rh_ok = (
        reset_target < 0x00200000  # generic flash low region
        or 0x08000000 <= reset_target <= 0x08FFFFFF  # STM32
        or 0x10000000 <= reset_target <= 0x1FFFFFFF  # NXP / Nordic
    )
    return sp_ok and rh_ok


def _detect_baremetal_cortex_m(candidates: list[str]) -> tuple[bool, str]:
    """Check whether any candidate looks like baremetal Cortex-M."""
    for path in candidates:
        if _looks_like_cortex_m_elf(path):
            return True, f"Cortex-M ELF layout in {os.path.basename(path)}"
        if _looks_like_cortex_m_raw(path):
            return True, f"Cortex-M reset vector in {os.path.basename(path)}"
    return False, ""


def detect_firmware_kind(
    firmware_path: str,
    extraction_dir: str | None,
    fs_root: str | None,
) -> KindDetection:
    """Classify a firmware image as Linux, RTOS, or unknown.

    *fs_root* should be the result of ``find_filesystem_root``. When it
    is non-None we trust it and short-circuit to ``linux``.
    """
    if fs_root is not None:
        return KindDetection(kind="linux", flavor=None, notes="filesystem root located")

    candidates = _candidate_files(firmware_path, extraction_dir)
    if not candidates:
        return KindDetection(kind="unknown", flavor=None, notes="no candidate files to scan")

    flavor, notes = _detect_freertos_or_zephyr(candidates)
    if flavor is not None:
        return KindDetection(kind="rtos", flavor=flavor, notes=notes)

    is_cm, cm_notes = _detect_baremetal_cortex_m(candidates)
    if is_cm:
        return KindDetection(kind="rtos", flavor="baremetal-cortexm", notes=cm_notes)

    return KindDetection(
        kind="unknown",
        flavor=None,
        notes="no Linux rootfs and no recognised RTOS signatures",
    )
