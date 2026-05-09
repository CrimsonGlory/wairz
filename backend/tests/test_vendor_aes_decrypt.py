"""Regression tests for _detect_openssl_key_triples + _decrypt_vendor_encrypted_archives.

Guards the RespArray/target-ld v1.12 use case:
    A vendor firmware ships both encrypted payloads (.tar.xz whose first
    bytes are AES ciphertext, not XZ magic) and a recovery rootfs that
    hardcodes the decryption key+iv in a shell script so the running
    device can decrypt incoming updates. Wairz must find the key and
    auto-decrypt during unpack, so the real rootfs surfaces to the user
    without manual operator work.

Shapes covered:
    - Positive: recovery shell script → key+iv extracted → encrypted
      .tar.xz decrypts → inner content extracted to _extract/ sibling.
    - Multiple key triples in the same tree — decryptor tries each.
    - Flag-order variants (-K before -iv / -iv before -K).
    - `openssl enc -aes-128-cbc` shell-script variant.
    - Negative: plaintext .tar.xz with valid XZ magic is never touched.
    - Negative: no shell scripts → detector returns [] → decryptor no-op.
    - Safety: wrong-key decryption never passes the magic gate.
"""
from __future__ import annotations

import io
import lzma
import os
import subprocess
import tarfile
from pathlib import Path

from app.workers.unpack_common import (
    _archive_ext_for,
    _decrypt_vendor_encrypted_archives,
    _detect_openssl_key_triples,
)

# Known-good AES-128-CBC key+iv (not secret — synthetic for tests).
_KEY_128_HEX = "43c8e032ff65f5cc762d1dc15580d425"
_IV_HEX = "50719d498aa89db2d3fccac9ff310c79"


def _write_update_script(path: Path, key_hex: str, iv_hex: str, algo: str = "aes-128-cbc") -> None:
    """Shell script shaped like RespArray's /sbin/force_update.sh."""
    path.write_text(
        "#!/bin/sh\n"
        "log() { echo \"$1\"; }\n"
        "case $file_name in\n"
        "    rootfs_partition.tar.xz)\n"
        "        log \"$file_name installing ...\"\n"
        f"        openssl {algo} -d -in tmp_download/middle_files/$file_name "
        f"-out tmp_rootfs/tmp_decrypt/$file_name -K {key_hex} -iv {iv_hex} -p > /dev/null\n"
        "        ;;\n"
        "esac\n"
    )


def _make_tar_xz_bytes(content: bytes, member_name: str = "inner.bin") -> bytes:
    """Build a valid tar.xz in-memory with a single file member."""
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        ti = tarfile.TarInfo(member_name)
        ti.size = len(content)
        tf.addfile(ti, io.BytesIO(content))
    return lzma.compress(tar_buf.getvalue(), format=lzma.FORMAT_XZ)


def _write_encrypted_tarxz(
    path: Path,
    key_hex: str,
    iv_hex: str,
    content: bytes,
) -> None:
    """Build a tar.xz of a single file, then AES-128-CBC encrypt it.

    After encryption the file's first bytes will NOT match XZ magic —
    matching the vendor shape Wairz must auto-decrypt.
    """
    plain_xz_bytes = _make_tar_xz_bytes(content)
    # Encrypt via openssl subprocess for bit-exact parity with the
    # production decrypt path (which also shells out to openssl).
    result = subprocess.run(
        [
            "openssl", "aes-128-cbc", "-e",
            "-K", key_hex,
            "-iv", iv_hex,
        ],
        input=plain_xz_bytes,
        capture_output=True,
        check=True,
    )
    path.write_bytes(result.stdout)


class TestArchiveExtension:
    def test_recognises_tar_xz(self):
        assert _archive_ext_for("/tmp/rootfs_partition.tar.xz") == ".tar.xz"

    def test_recognises_tar_gz(self):
        assert _archive_ext_for("/tmp/boot.tar.gz") == ".tar.gz"

    def test_prefers_longest_match(self):
        # ".tar.xz" wins over ".xz"
        assert _archive_ext_for("/tmp/foo.tar.xz") == ".tar.xz"

    def test_unknown_extension(self):
        assert _archive_ext_for("/tmp/random.bin") is None
        assert _archive_ext_for("/tmp/script.sh") is None


class TestDetectKeyTriples:
    def test_extracts_key_iv_from_shell_script(self, tmp_path: Path) -> None:
        _write_update_script(tmp_path / "force_update.sh", _KEY_128_HEX, _IV_HEX)
        triples = _detect_openssl_key_triples(str(tmp_path))
        assert len(triples) == 1
        t = triples[0]
        assert t.algo == "aes-128-cbc"
        assert t.key_hex == _KEY_128_HEX
        assert t.iv_hex == _IV_HEX
        assert t.source.endswith(":6")  # openssl line is at line 6

    def test_handles_iv_before_key(self, tmp_path: Path) -> None:
        script = tmp_path / "update.sh"
        script.write_text(
            f"#!/bin/sh\nopenssl aes-128-cbc -d -iv {_IV_HEX} -K {_KEY_128_HEX} -in foo -out bar\n"
        )
        triples = _detect_openssl_key_triples(str(tmp_path))
        assert len(triples) == 1
        assert triples[0].key_hex == _KEY_128_HEX
        assert triples[0].iv_hex == _IV_HEX

    def test_handles_enc_prefix(self, tmp_path: Path) -> None:
        script = tmp_path / "install.sh"
        script.write_text(
            f"#!/bin/sh\nopenssl enc -aes-128-cbc -d -K {_KEY_128_HEX} -iv {_IV_HEX} -in foo\n"
        )
        triples = _detect_openssl_key_triples(str(tmp_path))
        assert len(triples) == 1
        assert triples[0].algo == "aes-128-cbc"

    def test_aes_256_detected(self, tmp_path: Path) -> None:
        script = tmp_path / "update.sh"
        key_256 = "a" * 64
        script.write_text(
            f"#!/bin/sh\nopenssl aes-256-cbc -d -K {key_256} -iv {_IV_HEX}\n"
        )
        triples = _detect_openssl_key_triples(str(tmp_path))
        assert len(triples) == 1
        assert triples[0].algo == "aes-256-cbc"
        assert triples[0].key_hex == key_256

    def test_multiple_triples_deduplicated(self, tmp_path: Path) -> None:
        """Same key+iv in two files → reported once."""
        _write_update_script(tmp_path / "force_update.sh", _KEY_128_HEX, _IV_HEX)
        _write_update_script(tmp_path / "normal_update.sh", _KEY_128_HEX, _IV_HEX)
        triples = _detect_openssl_key_triples(str(tmp_path))
        assert len(triples) == 1

    def test_no_scripts_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "README.txt").write_text("No secrets here.")
        triples = _detect_openssl_key_triples(str(tmp_path))
        assert triples == []

    def test_algo_key_length_mismatch_rejected(self, tmp_path: Path) -> None:
        """aes-128-cbc requires 32 hex chars; 64 hex is aes-256 — must not match as 128."""
        script = tmp_path / "update.sh"
        script.write_text(
            f"#!/bin/sh\nopenssl aes-128-cbc -d -K {'a' * 64} -iv {_IV_HEX}\n"
        )
        triples = _detect_openssl_key_triples(str(tmp_path))
        assert triples == []


class TestDecryptVendorArchives:
    def test_decrypts_encrypted_tar_xz(self, tmp_path: Path) -> None:
        # Build the shape: /extraction/target/payload.tar.xz (encrypted)
        #                  /extraction/sbin/update.sh         (has key)
        sbin = tmp_path / "sbin"
        sbin.mkdir()
        _write_update_script(sbin / "update.sh", _KEY_128_HEX, _IV_HEX)
        target = tmp_path / "target"
        target.mkdir()
        payload = target / "payload.tar.xz"
        _write_encrypted_tarxz(payload, _KEY_128_HEX, _IV_HEX, b"secret rootfs content")
        # Verify the encrypted file does NOT start with XZ magic
        with open(payload, "rb") as f:
            assert not f.read(6).startswith(b"\xfd7zXZ\x00")

        triples = _detect_openssl_key_triples(str(tmp_path))
        assert len(triples) == 1

        results = _decrypt_vendor_encrypted_archives(str(tmp_path), triples)
        assert len(results) == 1
        archive_path, triple_used = results[0]
        assert os.path.realpath(archive_path) == os.path.realpath(str(payload))
        assert triple_used.key_hex == _KEY_128_HEX

        # Extracted content must exist
        out_dir = str(payload) + "_extract"
        assert os.path.isdir(out_dir)
        inner = os.path.join(out_dir, "inner.bin")
        assert os.path.isfile(inner)
        with open(inner, "rb") as f:
            assert f.read() == b"secret rootfs content"

    def test_plaintext_archive_left_alone(self, tmp_path: Path) -> None:
        """A valid XZ file with correct magic must NOT be touched by the decryptor."""
        _write_update_script(tmp_path / "update.sh", _KEY_128_HEX, _IV_HEX)
        target = tmp_path / "target"
        target.mkdir()
        real_xz = target / "plain.tar.xz"
        real_xz.write_bytes(_make_tar_xz_bytes(b"plaintext body"))
        assert real_xz.exists()
        before_size = real_xz.stat().st_size

        triples = _detect_openssl_key_triples(str(tmp_path))
        results = _decrypt_vendor_encrypted_archives(str(tmp_path), triples)
        # Plaintext file was skipped
        assert len(results) == 0
        # File untouched
        assert real_xz.stat().st_size == before_size
        # No _extract sibling was created
        assert not (target / "plain.tar.xz_extract").exists()

    def test_no_key_no_decrypt(self, tmp_path: Path) -> None:
        """If no shell scripts with hardcoded keys, decryptor is a no-op."""
        target = tmp_path / "target"
        target.mkdir()
        # Encrypted file exists, but no key source
        payload = target / "payload.tar.xz"
        _write_encrypted_tarxz(payload, _KEY_128_HEX, _IV_HEX, b"data")
        triples = _detect_openssl_key_triples(str(tmp_path))
        assert triples == []
        results = _decrypt_vendor_encrypted_archives(str(tmp_path), triples)
        assert results == []
        assert not (target / "payload.tar.xz_extract").exists()

    def test_wrong_key_does_not_pass_magic_gate(self, tmp_path: Path) -> None:
        """A shell script with a DIFFERENT key must not accidentally decrypt the payload."""
        sbin = tmp_path / "sbin"
        sbin.mkdir()
        wrong_key = "deadbeef" * 4  # 32 hex, 16 bytes — wrong
        _write_update_script(sbin / "update.sh", wrong_key, _IV_HEX)
        target = tmp_path / "target"
        target.mkdir()
        payload = target / "payload.tar.xz"
        _write_encrypted_tarxz(payload, _KEY_128_HEX, _IV_HEX, b"data")

        triples = _detect_openssl_key_triples(str(tmp_path))
        assert len(triples) == 1
        assert triples[0].key_hex == wrong_key  # the detector found the WRONG key

        results = _decrypt_vendor_encrypted_archives(str(tmp_path), triples)
        # The magic gate must reject the garbage output
        assert results == []
        assert not (target / "payload.tar.xz_extract").exists()

    def test_multiple_triples_first_working_wins(self, tmp_path: Path) -> None:
        """Two scripts with different keys; the right one works."""
        _write_update_script(tmp_path / "wrong.sh", "00" * 16, _IV_HEX)
        _write_update_script(tmp_path / "right.sh", _KEY_128_HEX, _IV_HEX)
        target = tmp_path / "target"
        target.mkdir()
        payload = target / "payload.tar.xz"
        _write_encrypted_tarxz(payload, _KEY_128_HEX, _IV_HEX, b"xyz")

        triples = _detect_openssl_key_triples(str(tmp_path))
        assert len(triples) == 2

        results = _decrypt_vendor_encrypted_archives(str(tmp_path), triples)
        assert len(results) == 1
        assert results[0][1].key_hex == _KEY_128_HEX
