"""Synthetic fixture builders for hardware firmware parser tests.

Each function returns bytes representing a minimal-but-valid instance of
its respective format.  NO binaries are checked in — all fixtures are
generated at test time.  Keep these helpers tight; they're called once
per test via ``tmp_path``.
"""

from __future__ import annotations

import struct
from datetime import UTC
from typing import Any

# -----------------------------------------------------------------------------
# ELF helpers (shared by .ko, OP-TEE TA, Qualcomm single-file MBN variants).
# -----------------------------------------------------------------------------

# ELF64 LE structure constants.
_ELF_MAGIC = b"\x7fELF"
_ELFCLASS64 = 2
_ELFDATA2LSB = 1
_EV_CURRENT = 1
_ELFOSABI_SYSV = 0
_ET_REL = 1
_ET_DYN = 3
_EM_X86_64 = 62
_EM_AARCH64 = 183
_SHT_NULL = 0
_SHT_PROGBITS = 1
_SHT_STRTAB = 3


def _pad(data: bytes, align: int) -> bytes:
    rem = len(data) % align
    if rem == 0:
        return data
    return data + b"\x00" * (align - rem)


def _build_minimal_elf64(
    *,
    e_type: int,
    e_machine: int,
    sections: list[tuple[str, bytes]],
    entry: int = 0,
) -> bytes:
    """Build a minimal ELF64 LE binary with the given (name, payload) sections.

    Produces a well-formed ELF file with a ``.shstrtab`` section and one
    ``SHT_PROGBITS`` per named section.  No program headers, no symbol table.
    """
    eh_size = 64
    sh_ent_size = 64

    # Build .shstrtab first so we can embed section name offsets.
    shstrtab = bytearray(b"\x00")  # index 0 = empty string
    name_offsets = {"": 0}
    all_names = [""] + [name for name, _ in sections] + [".shstrtab"]
    for nm in all_names[1:]:
        if nm in name_offsets:
            continue
        name_offsets[nm] = len(shstrtab)
        shstrtab.extend(nm.encode("ascii") + b"\x00")

    # Place section data after the ELF header.  shstrtab is the last section.
    section_datas: list[tuple[str, bytes, int]] = []  # (name, data, sh_type)
    for name, payload in sections:
        section_datas.append((name, payload, _SHT_PROGBITS))

    # Offsets: header, then each section payload (aligned to 4), then shstrtab, then section headers.
    cursor = eh_size
    offsets_and_sizes: list[tuple[int, int]] = []
    body = bytearray()
    for _name, payload, _t in section_datas:
        if cursor % 4 != 0:
            pad = 4 - (cursor % 4)
            body.extend(b"\x00" * pad)
            cursor += pad
        offsets_and_sizes.append((cursor, len(payload)))
        body.extend(payload)
        cursor += len(payload)

    # Align before shstrtab.
    if cursor % 4 != 0:
        pad = 4 - (cursor % 4)
        body.extend(b"\x00" * pad)
        cursor += pad
    shstrtab_offset = cursor
    body.extend(shstrtab)
    shstrtab_size = len(shstrtab)
    cursor += shstrtab_size

    # Align before section header table.
    if cursor % 8 != 0:
        pad = 8 - (cursor % 8)
        body.extend(b"\x00" * pad)
        cursor += pad
    shoff = cursor

    num_sections = 1 + len(section_datas) + 1  # NULL + user + .shstrtab
    shstrndx = num_sections - 1

    # Build section headers.
    sh_table = bytearray()
    # NULL section
    sh_table.extend(
        struct.pack(
            "<IIQQQQIIQQ",
            0,  # sh_name
            _SHT_NULL,  # sh_type
            0,  # sh_flags
            0,  # sh_addr
            0,  # sh_offset
            0,  # sh_size
            0,  # sh_link
            0,  # sh_info
            0,  # sh_addralign
            0,  # sh_entsize
        )
    )
    for (nm, payload, sht), (off, sz) in zip(section_datas, offsets_and_sizes, strict=True):
        sh_table.extend(
            struct.pack(
                "<IIQQQQIIQQ",
                name_offsets[nm],
                sht,
                0,
                0,
                off,
                sz,
                0,
                0,
                1,
                0,
            )
        )
    # .shstrtab section header
    sh_table.extend(
        struct.pack(
            "<IIQQQQIIQQ",
            name_offsets[".shstrtab"],
            _SHT_STRTAB,
            0,
            0,
            shstrtab_offset,
            shstrtab_size,
            0,
            0,
            1,
            0,
        )
    )

    ehdr = bytearray()
    ehdr.extend(_ELF_MAGIC)
    ehdr.extend(bytes([
        _ELFCLASS64,
        _ELFDATA2LSB,
        _EV_CURRENT,
        _ELFOSABI_SYSV,
    ]))
    ehdr.extend(b"\x00" * 8)  # padding e_ident[9..15]
    ehdr.extend(struct.pack(
        "<HHIQQQIHHHHHH",
        e_type,
        e_machine,
        _EV_CURRENT,
        entry,  # e_entry
        0,  # e_phoff
        shoff,
        0,  # e_flags
        eh_size,
        0,  # e_phentsize
        0,  # e_phnum
        sh_ent_size,
        num_sections,
        shstrndx,
    ))
    assert len(ehdr) == eh_size
    return bytes(ehdr) + bytes(body) + bytes(sh_table)


# -----------------------------------------------------------------------------
# DTB fixture (uses the `fdt` library at test-time).
# -----------------------------------------------------------------------------


def build_minimal_dtb() -> bytes:
    """Build a tiny DTB with model + compatible + firmware-name props."""
    import fdt  # type: ignore

    dt = fdt.FDT()
    # dt.root is a Node('/') created by FDT constructor; populate it.
    dt.root.append(fdt.PropStrings("model", "wairz,test-device"))
    dt.root.append(fdt.PropStrings("compatible", "wairz,test-v1", "qcom,sm8450-test"))
    wifi = fdt.Node("wifi@0")
    wifi.append(fdt.PropStrings("compatible", "qcom,wcn6750-wifi"))
    wifi.append(fdt.PropStrings("firmware-name", "wcn6750.bin"))
    dt.root.append(wifi)
    return dt.to_dtb(version=17)


def build_minimal_dtbo(sub_dtbs: list[bytes]) -> bytes:
    """Wrap ``sub_dtbs`` in an Android DTBO header (big-endian)."""
    magic = 0xD7B7AB1E
    header_size = 32
    dt_entry_size = 32  # spec: 32 bytes per entry (7 u32 + rsvd)
    dt_entry_count = len(sub_dtbs)
    dt_entries_offset = header_size
    entries_total = dt_entry_count * dt_entry_size
    body_start = header_size + entries_total
    # Compute offsets.
    dt_blobs = b""
    offsets_and_sizes: list[tuple[int, int]] = []
    cursor = body_start
    for blob in sub_dtbs:
        offsets_and_sizes.append((cursor, len(blob)))
        dt_blobs += blob
        cursor += len(blob)
    total_size = cursor
    header = struct.pack(
        ">8I",
        magic,
        total_size,
        header_size,
        dt_entry_size,
        dt_entry_count,
        dt_entries_offset,
        2048,
        1,
    )
    entries = b""
    for off, sz in offsets_and_sizes:
        # Entry: dt_size, dt_offset, id, rev, custom[4]
        entries += struct.pack(">8I", sz, off, 0, 0, 0, 0, 0, 0)
    return header + entries + dt_blobs


# -----------------------------------------------------------------------------
# Kernel module (.ko) fixture.
# -----------------------------------------------------------------------------


def build_minimal_ko(modinfo_pairs: list[tuple[str, str]], *, with_signature: bool = False) -> bytes:
    """Build a minimal ELF64 x86_64 ET_REL with a ``.modinfo`` section."""
    modinfo = b""
    for key, value in modinfo_pairs:
        modinfo += f"{key}={value}".encode() + b"\x00"

    elf = _build_minimal_elf64(
        e_type=_ET_REL,
        e_machine=_EM_X86_64,
        sections=[(".modinfo", modinfo)],
    )
    if with_signature:
        # Append a fake PKCS7 blob + module signature info struct + magic.
        # modinfo_sig layout is a trailing struct, but for our parser the
        # presence of the magic in the last N bytes is sufficient.
        sig_body = b"\x30\x82\x00\x10FAKE-CMS-BLOB"
        sig_info = b"\x00" * 12 + struct.pack("<I", len(sig_body))
        magic = b"~Module signature appended~"
        elf = elf + sig_body + sig_info + magic
    return elf


# -----------------------------------------------------------------------------
# OP-TEE TA fixture.
# -----------------------------------------------------------------------------


def build_minimal_optee_ta(uuid_bytes: bytes, *, ta_version: str = "1.0.0") -> bytes:
    """Build a minimal AArch64 ELF DYN with a ``.ta_head`` and TA_VERSION string."""
    if len(uuid_bytes) != 16:
        raise ValueError("uuid_bytes must be exactly 16 bytes")
    # ta_head: 16-byte UUID + 32 bytes of other header fields.
    ta_head = uuid_bytes + b"\x00" * 32
    version_section = f"TA_VERSION={ta_version}".encode() + b"\x00"
    return _build_minimal_elf64(
        e_type=_ET_DYN,
        e_machine=_EM_AARCH64,
        sections=[
            (".ta_head", ta_head),
            (".rodata", version_section),
        ],
    )


# -----------------------------------------------------------------------------
# Qualcomm MBN v3 fixture.
# -----------------------------------------------------------------------------


def build_mbn_v3(
    *,
    image_id: int = 12,
    code: bytes = b"CODE" * 64,
    sig: bytes = b"SIGNATURE" * 32,
    cert_chain: bytes = b"",
    version_string: str = "SDM660.MBN.1.0",
) -> bytes:
    """Build a 40-byte MBN v3 header + code + sig + cert_chain blob.

    File size = 40 + code_size + sig_size + cert_chain_size; this matches
    the v3 detection heuristic in the parser.
    """
    code_size = len(code)
    sig_size = len(sig)
    cert_size = len(cert_chain)
    image_size = code_size + sig_size + cert_size
    sig_ptr = 0
    cert_chain_ptr = 0
    header = struct.pack(
        "<10I",
        0x844BDCD1,  # codeword
        0x73D71034,  # magic
        image_id,
        3,  # flash_parti_ver
        0,  # image_src
        0x80000000,  # image_dest_ptr
        image_size,
        code_size,
        sig_ptr,
        sig_size,
    )
    # Plus 8 more bytes for cert_chain_ptr/size (v3+cert variant).
    ext = struct.pack("<2I", cert_chain_ptr, cert_size)
    # Embed a QC_IMAGE_VERSION_STRING somewhere in code payload for scanner.
    verbytes = f"QC_IMAGE_VERSION_STRING = {version_string}".encode() + b"\x00"
    # Keep code_size as declared; pad or embed the version string inline.
    if len(verbytes) <= code_size:
        code = verbytes + code[len(verbytes):]
    return header + ext + code[: code_size] + sig + cert_chain


def build_self_signed_cert_der(common_name: str = "Wairz Test Signer") -> bytes:
    """Generate a self-signed RSA-2048 cert in DER (for MBN cert-chain fixture)."""
    from datetime import datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(tz=UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
    )
    cert = builder.sign(private_key=key, algorithm=hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


# -----------------------------------------------------------------------------
# Broadcom / raw binary fixtures.
# -----------------------------------------------------------------------------


def build_broadcom_firmware(version_str: str = "7.35.180.11") -> bytes:
    """Build a fake brcmfmac .bin with an embedded version string."""
    padding = b"\x00" * 256
    body = (
        padding
        + b"wl0: Broadcom: Wireless LAN Driver version "
        + version_str.encode("ascii")
        + b"\x00"
        + padding
        + b"Firmware: 4366c0-roml/pcie-ag-ext\x00"
        + padding * 4
    )
    return body


def build_raw_bin_with_version(version_str: str = "1.2.3") -> bytes:
    """Build a simple binary with an embedded VERSION_STRING for raw_bin tests."""
    prefix = b"\x00" * 64
    body = f"VERSION_STRING = {version_str}".encode() + b"\x00"
    # Pad to at least min-file-size & include some random-looking bytes.
    payload = prefix + body + bytes(range(256)) * 32
    return payload


def build_high_entropy_blob(size: int = 2048) -> bytes:
    """Build a pseudo-random blob (deterministic) for entropy > 7.5 assertions."""
    import hashlib

    out = bytearray()
    seed = b"wairz-hwfw-entropy"
    while len(out) < size:
        seed = hashlib.sha256(seed).digest()
        out.extend(seed)
    return bytes(out[:size])


# -----------------------------------------------------------------------------
# MediaTek LK partition record (Phase 3).
# -----------------------------------------------------------------------------


def build_mtk_lk_partition(
    *,
    partition_name: str = "lk",
    partition_size: int = 0x100000,
    magic_version: int = 0xFFFFFFFF,
    file_info_offset: int = 0x200,
    payload: bytes | None = None,
) -> bytes:
    """Build a 1024-byte buffer starting with a MediaTek LK partition record.

    Layout: 4-byte magic + 4 u32 fields, then a 32-byte name at offset 32.
    """
    magic = 0x58881688
    header = bytearray(512)
    struct.pack_into(
        "<IIII",
        header,
        0,
        magic,
        file_info_offset,
        partition_size,
        magic_version,
    )
    name_bytes = partition_name.encode("ascii")[:31]
    header[32 : 32 + len(name_bytes)] = name_bytes
    # zero pad rest of name
    payload_bytes = payload if payload is not None else b"\x00" * 512
    return bytes(header) + payload_bytes


# -----------------------------------------------------------------------------
# MediaTek preloader (Phase 3).
# -----------------------------------------------------------------------------


def build_mtk_preloader(
    *,
    file_ver: str = "V1.0",
    sig_type: int = 1,
    file_len: int = 0x10000,
    load_addr: int = 0x201000,
    file_id: str = "pm",
    total_size: int = 512,
) -> bytes:
    """Build a fake MediaTek preloader with GFH_FILE_INFO at offset 8."""
    out = bytearray(total_size)
    out[0:4] = b"MMM\x01"
    gfh_off = 8
    # GFH_FILE_INFO fields (see parser for layout).
    gfh_magic = b"MMM"
    gfh_version = 1
    gfh_size = 50
    gfh_type = 0x0000
    id_bytes = file_id.encode("ascii")[:4].ljust(4, b"\x00")
    flash_dev = 0
    sig_len = 256 if sig_type else 0
    max_size = file_len
    content_offset = 0
    jump_offset = 0
    attr = 0
    ver_bytes = file_ver.encode("ascii")[:8].ljust(8, b"\x00")
    struct.pack_into(
        "<3sBHH4sBBIIIIIII8s",
        out,
        gfh_off,
        gfh_magic,
        gfh_version,
        gfh_size,
        gfh_type,
        id_bytes,
        flash_dev,
        sig_type,
        load_addr,
        file_len,
        max_size,
        content_offset,
        sig_len,
        jump_offset,
        attr,
        ver_bytes,
    )
    return bytes(out)


# -----------------------------------------------------------------------------
# MediaTek MD1IMG (modem image) (Phase 3).
# -----------------------------------------------------------------------------


def build_mtk_md1img(
    *,
    sections: list[tuple[str, int, int]] | None = None,
    magic_offset: int = 0x48,
    total_size: int = 8 * 1024,
    chipset: str = "MT6771",
    version: str = "v1.2.3",
) -> bytes:
    """Build a fake MD1IMG modem image with a section table.

    ``sections`` is a list of ``(name, offset, size)`` tuples.  Default set
    is ``[("md1rom", 0x400, 0x800), ("cert_md", 0xc00, 0x200)]``.
    """
    if sections is None:
        sections = [("md1rom", 0x400, 0x800), ("cert_md", 0xC00, 0x200)]

    buf = bytearray(total_size)
    # Place the MD1IMG magic
    buf[magic_offset : magic_offset + 6] = b"MD1IMG"
    # Section table directly after the magic, 20-byte stride.
    table_off = magic_offset + len(b"MD1IMG")
    for i, (name, off, sz) in enumerate(sections):
        record_off = table_off + i * 20
        if record_off + 20 > len(buf):
            break
        name_bytes = name.encode("ascii")[:7].ljust(8, b"\x00")
        buf[record_off : record_off + 8] = name_bytes
        struct.pack_into("<II", buf, record_off + 8, off, sz)
        # Zero the reserved tail (indices 16..20 within the record).
    # Insert a chipset + version banner after the table so the parser can
    # pick them up.
    banner = f"{chipset} md1rom_version:{version}\x00".encode("ascii")
    banner_off = table_off + len(sections) * 20 + 32
    if banner_off + len(banner) <= len(buf):
        buf[banner_off : banner_off + len(banner)] = banner
    return bytes(buf)


# -----------------------------------------------------------------------------
# MediaTek Wi-Fi header (Phase 3).
# -----------------------------------------------------------------------------


def build_mtk_wifi_hdr(
    *,
    timestamp: str = "20230401120000",
    at_offset: int = 0x20,
    total_size: int = 4 * 1024,
    build_id: str | None = "20230401120000-1.2.3",
) -> bytes:
    """Build a fake mt76 Wi-Fi firmware with an ASCII build timestamp."""
    buf = bytearray(total_size)
    ts_bytes = timestamp.encode("ascii")
    if at_offset + len(ts_bytes) <= len(buf):
        buf[at_offset : at_offset + len(ts_bytes)] = ts_bytes
    if build_id:
        bid = f"BUILD_ID:{build_id}\x00".encode("ascii")
        off = at_offset + 32
        if off + len(bid) <= len(buf):
            buf[off : off + len(bid)] = bid
    return bytes(buf)


# -----------------------------------------------------------------------------
# Awinic ACF (Phase 3).
# -----------------------------------------------------------------------------


def build_awinic_acf(
    *,
    acf_version: int = 1,
    chip_id: str = "aw88266",
    profile_count: int = 4,
    total_size: int = 1024,
) -> bytes:
    """Build a minimal Awinic ACF file: AWINIC magic + version + chip id + profile count."""
    buf = bytearray(total_size)
    buf[0:6] = b"AWINIC"
    struct.pack_into("<I", buf, 6, acf_version)
    chip_bytes = chip_id.encode("ascii")[:7].ljust(8, b"\x00")
    buf[10:18] = chip_bytes
    struct.pack_into("<I", buf, 18, profile_count)
    return bytes(buf)


# -----------------------------------------------------------------------------
# Linux kernel-Image fixtures (zImage / uImage / vmlinuz / Image).
# -----------------------------------------------------------------------------


def build_minimal_kernel_image(
    *,
    config_text: str | None = None,
    version: str = "5.10.0",
    banner_extra: str = "",
    include_ikcfg: bool = True,
    padding_before_banner: int = 4096,
    padding_before_ikcfg: int = 1024,
    pad_kind: bytes = b"\x00",
) -> bytes:
    """Synthesize a minimal Linux kernel image with embedded IKCFG + banner.

    Layout::

        <padding> <Linux version BANNER \0>
        <padding> IKCFG_ST <gzip(config_text)> IKCFG_ED <trailing pad>

    Returns the bytes of the synthetic kernel.  Mirrors the on-disk
    shape of a real kernel binary closely enough that the parser's
    byte-scan path resolves both markers correctly.
    """
    import gzip as _gzip

    from app.services.hardware_firmware.parsers._kernel_ikconfig import (
        IKCFG_ED,
        IKCFG_ST,
    )

    if config_text is None:
        # Sensible default — exercise all three line shapes the parser
        # recognises: =y, ="value", `# CONFIG_FOO is not set`.
        config_text = (
            "# Linux/arm64 5.10.0 Kernel Configuration\n"
            "CONFIG_RANDOMIZE_BASE=y\n"
            "CONFIG_HARDENED_USERCOPY=y\n"
            "CONFIG_DEVMEM=y\n"
            "CONFIG_DEVKMEM=y\n"
            "# CONFIG_MODULE_SIG is not set\n"
            "# CONFIG_SECURITY_SELINUX is not set\n"
            "CONFIG_LOCALVERSION=\"-tegra\"\n"
        )

    banner_str = f"Linux version {version}{banner_extra}\x00"
    banner_bytes = banner_str.encode("ascii")

    parts: list[bytes] = []
    parts.append(pad_kind * padding_before_banner)
    parts.append(banner_bytes)
    if include_ikcfg:
        parts.append(pad_kind * padding_before_ikcfg)
        parts.append(IKCFG_ST)
        parts.append(_gzip.compress(config_text.encode("utf-8")))
        parts.append(IKCFG_ED)
    parts.append(pad_kind * 256)
    return b"".join(parts)


# -----------------------------------------------------------------------------
# Generic helpers.
# -----------------------------------------------------------------------------


def write_fixture(path: Any, data: bytes) -> str:
    """Write ``data`` to ``path`` and return the filesystem path as a string."""
    with open(path, "wb") as f:
        f.write(data)
    return str(path)
