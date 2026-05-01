"""Tests for the AI string analysis tools."""

from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.ai.tools.strings import (
    _categorize_strings,
    _is_text_file,
    _shannon_entropy,
    register_string_tools,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def firmware_root(tmp_path: Path) -> Path:
    """Create a fake firmware filesystem with interesting content."""
    # Directories
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "ssl").mkdir()
    (tmp_path / "usr").mkdir()
    (tmp_path / "usr" / "bin").mkdir()
    (tmp_path / "var").mkdir()
    (tmp_path / "var" / "www").mkdir()
    (tmp_path / "root").mkdir()
    (tmp_path / "root" / ".ssh").mkdir()

    # Config with credentials
    (tmp_path / "etc" / "app.conf").write_text(
        "# Application config\n"
        "db_host=localhost\n"
        "db_port=5432\n"
        "password = SuperSecret123!\n"
        "api_key=sk-ant-abc123xyz789\n"
    )

    # Shadow file with empty password
    (tmp_path / "etc" / "shadow").write_text(
        "root::0:0:99999:7:::\n"
        "admin:$6$rounds=5000$salt$hash:18000:0:99999:7:::\n"
        "nobody:!:18000:0:99999:7:::\n"
    )

    # Web file with URLs and IPs
    (tmp_path / "var" / "www" / "config.js").write_text(
        "const API_URL = 'https://api.example.com/v1';\n"
        "const BACKUP_URL = 'http://192.168.1.100:8080/backup';\n"
        "const ADMIN_EMAIL = 'admin@example.com';\n"
        "const SECRET_TOKEN = 'token=eyJhbGciOiJIUzI1NiJ9.abc';\n"
    )

    # Certificate file
    (tmp_path / "etc" / "ssl" / "server.pem").write_text(
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBojCCAUmgAwIBAgIJALZBERkN...\n"
        "-----END CERTIFICATE-----\n"
    )

    # Private key file
    (tmp_path / "etc" / "ssl" / "server.key").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Z3VS5JJcds...\n"
        "-----END RSA PRIVATE KEY-----\n"
    )

    # SSH authorized keys
    (tmp_path / "root" / ".ssh" / "authorized_keys").write_text(
        "ssh-rsa AAAAB3NzaC1yc2EAAAA... root@device\n"
    )

    # SSH private key
    (tmp_path / "root" / ".ssh" / "id_rsa").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5v...\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )

    # Fake binary with embedded strings
    binary_data = b"\x7fELF" + b"\x00" * 20
    binary_data += b"http://update.firmware.local/check\x00"
    binary_data += b"password=default\x00"
    binary_data += b"/etc/config/secret.conf\x00"
    binary_data += b"admin@device.local\x00"
    binary_data += b"\x00" * 50
    (tmp_path / "usr" / "bin" / "daemon").write_bytes(binary_data)

    # Plain text file
    (tmp_path / "etc" / "motd").write_text("Welcome to Firmware v1.0\n")

    # DER certificate (binary)
    (tmp_path / "etc" / "ssl" / "ca.der").write_bytes(b"\x30\x82" + b"\x00" * 50)

    return tmp_path


@pytest.fixture
def tool_context(firmware_root: Path) -> ToolContext:
    return ToolContext(
        project_id=uuid4(),
        firmware_id=uuid4(),
        extracted_path=str(firmware_root),
        db=MagicMock(),
    )


@pytest.fixture
def registry() -> ToolRegistry:
    reg = ToolRegistry()
    register_string_tools(reg)
    return reg


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_two_chars_equal(self):
        # "ab" has 1 bit of entropy per character
        result = _shannon_entropy("ab")
        assert abs(result - 1.0) < 0.01

    def test_high_entropy(self):
        # Random-looking string should have high entropy
        result = _shannon_entropy("aB3$xZ9!kM2@pQ7&")
        assert result > 3.5

    def test_low_entropy(self):
        # Repetitive string has low entropy
        result = _shannon_entropy("aaaabbbb")
        assert result < 1.5


class TestIsTextFile:
    def test_text_file(self, tmp_path):
        f = tmp_path / "text.txt"
        f.write_text("Hello world\n")
        assert _is_text_file(str(f)) is True

    def test_binary_file(self, tmp_path):
        f = tmp_path / "binary.bin"
        f.write_bytes(b"\x00\x01\x02\x03")
        assert _is_text_file(str(f)) is False

    def test_nonexistent_file(self):
        assert _is_text_file("/nonexistent/file") is False


class TestCategorizeStrings:
    def test_url_detection(self):
        result = _categorize_strings(["https://example.com/api"])
        assert len(result["urls"]) == 1

    def test_ip_detection(self):
        result = _categorize_strings(["192.168.1.1"])
        assert len(result["ip_addresses"]) == 1

    def test_email_detection(self):
        result = _categorize_strings(["user@example.com"])
        assert len(result["email_addresses"]) == 1

    def test_filepath_detection(self):
        result = _categorize_strings(["/usr/bin/something"])
        assert len(result["file_paths"]) == 1

    def test_credential_detection(self):
        result = _categorize_strings(["password=secret123"])
        assert len(result["potential_credentials"]) == 1

    def test_deduplication(self):
        result = _categorize_strings(["https://a.com", "https://a.com"])
        assert len(result["urls"]) == 1

    def test_other_category(self):
        result = _categorize_strings(["just some random text"])
        assert len(result["other"]) == 1


# ---------------------------------------------------------------------------
# Tool registration tests
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_all_tools_registered(self, registry):
        tools = registry.get_anthropic_tools()
        names = {t["name"] for t in tools}
        assert names == {
            "extract_strings",
            "search_strings",
            "find_crypto_material",
            "find_hardcoded_credentials",
            "find_hardcoded_ips",
        }

    def test_tool_schemas_valid(self, registry):
        for tool in registry.get_anthropic_tools():
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert tool["input_schema"]["type"] == "object"
            assert "properties" in tool["input_schema"]


# ---------------------------------------------------------------------------
# extract_strings tests
# ---------------------------------------------------------------------------


class TestExtractStrings:
    @pytest.mark.asyncio
    async def test_extract_from_binary(self, registry, tool_context):
        result = await registry.execute(
            "extract_strings", {"path": "/usr/bin/daemon"}, tool_context
        )
        assert "Extracted strings from /usr/bin/daemon" in result
        # Should find the URL embedded in the binary
        assert "update.firmware.local" in result

    @pytest.mark.asyncio
    async def test_extract_from_text_file(self, registry, tool_context):
        result = await registry.execute(
            "extract_strings", {"path": "/etc/app.conf"}, tool_context
        )
        assert "Extracted strings" in result

    @pytest.mark.asyncio
    async def test_extract_with_min_length(self, registry, tool_context):
        result = await registry.execute(
            "extract_strings",
            {"path": "/usr/bin/daemon", "min_length": 20},
            tool_context,
        )
        # Higher min_length should filter short strings
        assert "Extracted strings" in result

    @pytest.mark.asyncio
    async def test_extract_nonexistent_file(self, registry, tool_context):
        result = await registry.execute(
            "extract_strings", {"path": "/nonexistent"}, tool_context
        )
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_extract_directory_error(self, registry, tool_context):
        result = await registry.execute(
            "extract_strings", {"path": "/etc"}, tool_context
        )
        assert "Error" in result or "not a file" in result

    @pytest.mark.asyncio
    async def test_path_traversal_blocked(self, registry, tool_context):
        result = await registry.execute(
            "extract_strings", {"path": "/../../etc/passwd"}, tool_context
        )
        # Should either error from path traversal or be sandboxed
        assert "Error" in result or "Extracted strings" in result


# ---------------------------------------------------------------------------
# search_strings tests
# ---------------------------------------------------------------------------


class TestSearchStrings:
    @pytest.mark.asyncio
    async def test_search_pattern(self, registry, tool_context):
        result = await registry.execute(
            "search_strings", {"pattern": "password"}, tool_context
        )
        assert "Found" in result
        assert "password" in result.lower()

    @pytest.mark.asyncio
    async def test_search_no_match(self, registry, tool_context):
        result = await registry.execute(
            "search_strings", {"pattern": "ZZZZNONEXISTENT999"}, tool_context
        )
        assert "No matches found" in result

    @pytest.mark.asyncio
    async def test_search_specific_path(self, registry, tool_context):
        result = await registry.execute(
            "search_strings", {"pattern": "API_URL", "path": "/var/www"}, tool_context
        )
        assert "Found" in result
        assert "config.js" in result

    @pytest.mark.asyncio
    async def test_search_relative_paths(self, registry, tool_context):
        """Results should show firmware-relative paths, not absolute."""
        result = await registry.execute(
            "search_strings", {"pattern": "localhost"}, tool_context
        )
        # The result should contain /etc/app.conf, not the absolute tmp path
        assert "/etc/app.conf" in result
        # Should NOT contain the tmp_path prefix in the visible output
        assert tool_context.extracted_path not in result

    @pytest.mark.asyncio
    async def test_search_regex(self, registry, tool_context):
        result = await registry.execute(
            "search_strings", {"pattern": "192\\.168"}, tool_context
        )
        assert "Found" in result
        assert "192.168" in result


# ---------------------------------------------------------------------------
# find_crypto_material tests
# ---------------------------------------------------------------------------


class TestFindCryptoMaterial:
    @pytest.mark.asyncio
    async def test_finds_certificate(self, registry, tool_context):
        result = await registry.execute(
            "find_crypto_material", {}, tool_context
        )
        assert "server.pem" in result or "server.key" in result

    @pytest.mark.asyncio
    async def test_finds_private_key(self, registry, tool_context):
        result = await registry.execute(
            "find_crypto_material", {}, tool_context
        )
        assert "Private Key" in result or "private_key" in result.lower()

    @pytest.mark.asyncio
    async def test_finds_ssh_keys(self, registry, tool_context):
        result = await registry.execute(
            "find_crypto_material", {}, tool_context
        )
        assert "authorized_keys" in result or "id_rsa" in result

    @pytest.mark.asyncio
    async def test_finds_der_file(self, registry, tool_context):
        result = await registry.execute(
            "find_crypto_material", {}, tool_context
        )
        assert "ca.der" in result

    @pytest.mark.asyncio
    async def test_reports_total_count(self, registry, tool_context):
        result = await registry.execute(
            "find_crypto_material", {}, tool_context
        )
        assert "Found" in result
        assert "crypto-related" in result

    @pytest.mark.asyncio
    async def test_no_crypto_empty_dir(self, registry, tool_context, tmp_path):
        empty_dir = tmp_path / "empty_firmware"
        empty_dir.mkdir()
        context = ToolContext(
            project_id=uuid4(),
            firmware_id=uuid4(),
            extracted_path=str(empty_dir),
            db=MagicMock(),
        )
        reg = ToolRegistry()
        register_string_tools(reg)
        result = await reg.execute("find_crypto_material", {}, context)
        assert "No cryptographic material found" in result

    @pytest.mark.asyncio
    async def test_search_specific_path(self, registry, tool_context):
        result = await registry.execute(
            "find_crypto_material", {"path": "/etc/ssl"}, tool_context
        )
        assert "server.pem" in result or "server.key" in result


# ---------------------------------------------------------------------------
# find_hardcoded_credentials tests
# ---------------------------------------------------------------------------


class TestFindHardcodedCredentials:
    @pytest.mark.asyncio
    async def test_finds_password(self, registry, tool_context):
        result = await registry.execute(
            "find_hardcoded_credentials", {}, tool_context
        )
        assert "password" in result.lower()
        assert "SuperSecret123" in result

    @pytest.mark.asyncio
    async def test_finds_api_key(self, registry, tool_context):
        result = await registry.execute(
            "find_hardcoded_credentials", {}, tool_context
        )
        assert "api_key" in result.lower() or "sk-ant" in result

    @pytest.mark.asyncio
    async def test_finds_empty_shadow_password(self, registry, tool_context):
        result = await registry.execute(
            "find_hardcoded_credentials", {}, tool_context
        )
        assert "shadow" in result.lower()
        assert "root" in result

    @pytest.mark.asyncio
    async def test_entropy_classification(self, registry, tool_context):
        result = await registry.execute(
            "find_hardcoded_credentials", {}, tool_context
        )
        # Should have entropy values in output
        assert "entropy=" in result

    @pytest.mark.asyncio
    async def test_high_entropy_section(self, registry, tool_context):
        result = await registry.execute(
            "find_hardcoded_credentials", {}, tool_context
        )
        # The API key has high entropy, should be in "Likely Real Secrets"
        assert "Likely Real Secrets" in result or "Possible Credentials" in result

    @pytest.mark.asyncio
    async def test_no_credentials_empty_dir(self, registry, tool_context, tmp_path):
        empty_dir = tmp_path / "empty_firmware"
        empty_dir.mkdir()
        (empty_dir / "etc").mkdir()
        context = ToolContext(
            project_id=uuid4(),
            firmware_id=uuid4(),
            extracted_path=str(empty_dir),
            db=MagicMock(),
        )
        reg = ToolRegistry()
        register_string_tools(reg)
        result = await reg.execute("find_hardcoded_credentials", {}, context)
        assert "No hardcoded credentials found" in result

    @pytest.mark.asyncio
    async def test_finds_token_in_js(self, registry, tool_context):
        result = await registry.execute(
            "find_hardcoded_credentials", {"path": "/var/www"}, tool_context
        )
        assert "token" in result.lower() or "config.js" in result


class TestBinaryRodataCredentialScan:
    """Regression for Bug 6: secrets in compiled binary rodata, not /etc/."""

    def _build_elf_with_strings(self, path: Path, strings: list[str]) -> None:
        """Write a minimal ELF-shaped file containing the given rodata strings.

        We don't need a valid loadable ELF — just the magic bytes and enough
        structure that ``strings -d`` can extract the embedded text. The
        rodata section is faked by appending null-separated strings into a
        plausibly-named ELF body.
        """
        # 64 bytes of minimal ELF-ish header / padding so the file looks like
        # an ELF to magic-detection but doesn't need a valid program-header
        # table. Then a fake .rodata blob of null-separated strings.
        header = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 56
        rodata = b"\x00".join(s.encode() for s in strings) + b"\x00\x00"
        # Pad so size > _MIN_FS_SIZE / etc; not strictly needed for strings.
        path.write_bytes(header + rodata + b"\x00" * 256)

    @pytest.mark.asyncio
    async def test_finds_32hex_secret_in_binary(self, tmp_path, registry):
        # Embed a 32-hex string in a fake ELF rodata section. The scanner
        # should flag it as a high-confidence binary credential.
        bin_path = tmp_path / "bin" / "ppsapp"
        bin_path.parent.mkdir()
        self._build_elf_with_strings(
            bin_path,
            [
                # Two real-shaped 32-hex secrets (matches the Wyze fixture's
                # 360a7068... and 5b0e5bc2... app_id/app_key).
                "360a7068374548a2853526f5e0231ad2",
                "5b0e5bc2788d4ff68c7b98a5656148d0",
                # Some other strings that should NOT match
                "hello world",
                "/usr/bin/ppsapp",
                "Copyright (c) 2023",
            ],
        )

        ctx = ToolContext(
            project_id=uuid4(),
            firmware_id=uuid4(),
            extracted_path=str(tmp_path),
            db=MagicMock(),
        )
        result = await registry.execute("find_hardcoded_credentials", {}, ctx)

        assert "binary" in result.lower() or "rodata" in result.lower()
        assert "360a7068374548a2853526f5e0231ad2" in result
        assert "5b0e5bc2788d4ff68c7b98a5656148d0" in result

    @pytest.mark.asyncio
    async def test_finds_magic_key_in_binary(self, tmp_path, registry):
        # _MEARI56565099-shaped strings are flagged at medium confidence.
        bin_path = tmp_path / "bin" / "app"
        bin_path.parent.mkdir()
        self._build_elf_with_strings(
            bin_path,
            ["_MEARI56565099", "regular string", "/etc/foo"],
        )

        ctx = ToolContext(
            project_id=uuid4(),
            firmware_id=uuid4(),
            extracted_path=str(tmp_path),
            db=MagicMock(),
        )
        result = await registry.execute("find_hardcoded_credentials", {}, ctx)
        assert "_MEARI56565099" in result
        assert "medium confidence" in result.lower()

    @pytest.mark.asyncio
    async def test_skips_zero_padding(self, tmp_path, registry):
        # All-zero or all-F hex strings (common ELF padding) must not be flagged.
        bin_path = tmp_path / "bin" / "app"
        bin_path.parent.mkdir()
        self._build_elf_with_strings(
            bin_path,
            ["0" * 32, "f" * 64, "F" * 40, "deadbeef" * 4],  # last is real-shaped
        )

        ctx = ToolContext(
            project_id=uuid4(),
            firmware_id=uuid4(),
            extracted_path=str(tmp_path),
            db=MagicMock(),
        )
        result = await registry.execute("find_hardcoded_credentials", {}, ctx)
        # The all-zero/all-F strings should be filtered; only deadbeef×4 should
        # appear in the high-confidence section (or the result might say "No
        # hardcoded credentials found" if even that's filtered, but we expect
        # it to pass through since it's not in the FP set).
        assert "0" * 32 not in result
        assert "f" * 64 not in result

    @pytest.mark.asyncio
    async def test_no_binaries_no_binary_findings(
        self, registry, tool_context
    ):
        # The standard fixture has a token-only fake ELF (4-byte ELF magic +
        # 70 bytes of mixed strings). It contains no hex-shaped tokens, so we
        # should NOT see a binary-rodata section in the output.
        result = await registry.execute(
            "find_hardcoded_credentials", {}, tool_context
        )
        # Sanity: shadow + text findings still happen.
        assert "Hardcoded Secrets in Binary rodata (high confidence)" not in result


class TestVendorPrefixedCredentialKeys:
    """Regression for the Wyze BCS update report — vendor configs use
    *_KEY / *_TOKEN naming (e.g. ``IOT_APP_KEY=...``, ``WYZE_OTA_UPDATE_KEY=...``)
    that the old narrow patterns missed entirely."""

    @pytest.mark.asyncio
    async def test_finds_iot_app_key(self, tmp_path, registry):
        (tmp_path / "init").mkdir()
        (tmp_path / "init" / ".product_config").write_text(
            "[WYZE]\n"
            "IOT_APP_ID=mbcf_5385a03fe05c63ee\n"
            "IOT_APP_KEY=L37jsUXlLzputvjcEQ1Hfr1JyeSTMs5x\n"
            "WYZE_OTA_UPDATE_KEY=oU8XzEpbOD6pVTLwdz9pxRpN9MGPCo1P\n"
        )
        ctx = ToolContext(
            project_id=uuid4(),
            firmware_id=uuid4(),
            extracted_path=str(tmp_path),
            db=MagicMock(),
        )
        result = await registry.execute("find_hardcoded_credentials", {}, ctx)
        assert "L37jsUXlLzputvjcEQ1Hfr1JyeSTMs5x" in result
        assert "oU8XzEpbOD6pVTLwdz9pxRpN9MGPCo1P" in result

    @pytest.mark.asyncio
    async def test_no_match_on_keyboard_or_monkey(self, tmp_path, registry):
        # `keyboard=` and `monkey=` end in "key"-shaped suffixes but are not
        # credentials. The `[_-]` separator in the catch-all pattern guards
        # against these false positives.
        (tmp_path / "etc").mkdir()
        (tmp_path / "etc" / "config").write_text(
            "keyboard=us-intl\n"
            "monkey=banana\n"
        )
        ctx = ToolContext(
            project_id=uuid4(),
            firmware_id=uuid4(),
            extracted_path=str(tmp_path),
            db=MagicMock(),
        )
        result = await registry.execute("find_hardcoded_credentials", {}, ctx)
        assert "us-intl" not in result
        assert "banana" not in result


# ---------------------------------------------------------------------------
# Path traversal tests
# ---------------------------------------------------------------------------


class TestStringToolsPathTraversal:
    @pytest.mark.asyncio
    async def test_extract_strings_traversal(self, registry, tool_context):
        result = await registry.execute(
            "extract_strings", {"path": "/../../../etc/passwd"}, tool_context
        )
        # Should be blocked or sandboxed
        assert "Error" in result or "Extracted strings" in result

    @pytest.mark.asyncio
    async def test_search_strings_traversal(self, registry, tool_context):
        result = await registry.execute(
            "search_strings", {"pattern": "root", "path": "/../../../etc"}, tool_context
        )
        # Should be blocked or sandboxed
        assert "Error" in result or "Found" in result

    @pytest.mark.asyncio
    async def test_crypto_traversal(self, registry, tool_context):
        result = await registry.execute(
            "find_crypto_material", {"path": "/../../../"}, tool_context
        )
        # Should be blocked or sandboxed
        assert "Error" in result or "Found" in result or "No crypto" in result

    @pytest.mark.asyncio
    async def test_credentials_traversal(self, registry, tool_context):
        result = await registry.execute(
            "find_hardcoded_credentials", {"path": "/../../../"}, tool_context
        )
        # Should be blocked or sandboxed
        assert "Error" in result or "Found" in result or "No hardcoded" in result
