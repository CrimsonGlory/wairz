"""Tests for Android property file parsers."""


from app.utils.getprop import extract_device_metadata, parse_build_prop, parse_getprop_txt

# ---------------------------------------------------------------------------
# parse_getprop_txt
# ---------------------------------------------------------------------------

class TestParseGetpropTxt:
    def test_normal_input(self):
        text = (
            "[ro.build.version.release]: [14]\n"
            "[ro.product.model]: [Pixel 7]\n"
            "[ro.product.brand]: [google]\n"
        )
        result = parse_getprop_txt(text)
        assert result == {
            "ro.build.version.release": "14",
            "ro.product.model": "Pixel 7",
            "ro.product.brand": "google",
        }

    def test_empty_input(self):
        assert parse_getprop_txt("") == {}

    def test_blank_lines_skipped(self):
        text = "[ro.secure]: [1]\n\n\n[ro.debuggable]: [0]\n"
        result = parse_getprop_txt(text)
        assert len(result) == 2

    def test_malformed_lines_skipped(self):
        text = (
            "[ro.build.version.release]: [14]\n"
            "this is not a valid line\n"
            "ro.product.model=Pixel 7\n"
            "[ro.product.brand]: [google]\n"
        )
        result = parse_getprop_txt(text)
        assert result == {
            "ro.build.version.release": "14",
            "ro.product.brand": "google",
        }

    def test_missing_brackets(self):
        text = "ro.build.version.release: 14\n"
        assert parse_getprop_txt(text) == {}

    def test_empty_value(self):
        text = "[dalvik.vm.heapsize]: []\n"
        result = parse_getprop_txt(text)
        assert result == {"dalvik.vm.heapsize": ""}

    def test_value_with_brackets(self):
        text = "[ro.build.display.id]: [UP1A.231105.003]\n"
        result = parse_getprop_txt(text)
        assert result["ro.build.display.id"] == "UP1A.231105.003"


# ---------------------------------------------------------------------------
# parse_build_prop
# ---------------------------------------------------------------------------

class TestParseBuildProp:
    def test_normal_input(self):
        text = (
            "ro.build.version.release=14\n"
            "ro.product.model=Pixel 7\n"
        )
        result = parse_build_prop(text)
        assert result == {
            "ro.build.version.release": "14",
            "ro.product.model": "Pixel 7",
        }

    def test_comments_skipped(self):
        text = (
            "# This is a comment\n"
            "ro.secure=1\n"
            "# Another comment\n"
        )
        result = parse_build_prop(text)
        assert result == {"ro.secure": "1"}

    def test_empty_lines_skipped(self):
        text = "ro.secure=1\n\n\nro.debuggable=0\n"
        result = parse_build_prop(text)
        assert len(result) == 2

    def test_empty_input(self):
        assert parse_build_prop("") == {}

    def test_no_value_key(self):
        text = "ro.empty.key=\n"
        result = parse_build_prop(text)
        assert result == {"ro.empty.key": ""}

    def test_value_with_equals(self):
        text = "ro.build.fingerprint=google/oriole/oriole:14/UP1A=release\n"
        result = parse_build_prop(text)
        assert result["ro.build.fingerprint"] == "google/oriole/oriole:14/UP1A=release"

    def test_lines_without_equals_skipped(self):
        text = "no_equals_here\nro.valid=yes\n"
        result = parse_build_prop(text)
        assert result == {"ro.valid": "yes"}


# ---------------------------------------------------------------------------
# extract_device_metadata
# ---------------------------------------------------------------------------

FULL_PROPS = {
    "ro.product.model": "Pixel 7",
    "ro.product.brand": "google",
    "ro.build.version.release": "14",
    "ro.build.version.sdk": "34",
    "ro.build.version.security_patch": "2024-01-05",
    "ro.build.fingerprint": "google/oriole/oriole:14/UP1A.231105.003/11148006:user/release-keys",
    "ro.board.platform": "gs201",
    "ro.boot.flash.locked": "1",
    "ro.secure": "1",
    "ro.debuggable": "0",
    "ro.adb.secure": "1",
    "ro.crypto.state": "encrypted",
    "ro.boot.verifiedbootstate": "green",
    "ro.boot.selinux": "enforcing",
}


class TestExtractDeviceMetadata:
    def test_full_props(self):
        meta = extract_device_metadata(FULL_PROPS)
        assert meta["device_model"] == "Pixel 7"
        assert meta["manufacturer"] == "google"
        assert meta["android_version"] == "14"
        assert meta["api_level"] == 34
        assert meta["security_patch"] == "2024-01-05"
        assert meta["build_fingerprint"].startswith("google/oriole")
        assert meta["chipset"] == "gs201"
        assert meta["bootloader_state"] == "locked"
        assert meta["security_posture"]["ro_secure"] == "1"
        assert meta["security_posture"]["ro_debuggable"] == "0"
        assert meta["security_posture"]["verified_boot"] == "green"

    def test_partial_props_missing_fields(self):
        meta = extract_device_metadata({"ro.product.model": "Test"})
        assert meta["device_model"] == "Test"
        assert meta["manufacturer"] is None
        assert meta["android_version"] is None
        assert meta["api_level"] is None
        assert meta["chipset"] is None

    def test_api_level_as_int(self):
        meta = extract_device_metadata({"ro.build.version.sdk": "33"})
        assert meta["api_level"] == 33
        assert isinstance(meta["api_level"], int)

    def test_api_level_zero_becomes_none(self):
        meta = extract_device_metadata({"ro.build.version.sdk": "0"})
        assert meta["api_level"] is None

    def test_api_level_missing_becomes_none(self):
        meta = extract_device_metadata({})
        assert meta["api_level"] is None

    def test_api_level_invalid_becomes_none(self):
        meta = extract_device_metadata({"ro.build.version.sdk": "abc"})
        assert meta["api_level"] is None

    def test_bootloader_unlocked(self):
        meta = extract_device_metadata({"ro.boot.flash.locked": "0"})
        assert meta["bootloader_state"] == "unlocked"

    def test_bootloader_locked(self):
        meta = extract_device_metadata({"ro.boot.flash.locked": "1"})
        assert meta["bootloader_state"] == "locked"

    def test_bootloader_unknown_when_missing(self):
        meta = extract_device_metadata({})
        assert meta["bootloader_state"] == "unknown"

    def test_bootloader_unknown_when_unexpected_value(self):
        meta = extract_device_metadata({"ro.boot.flash.locked": "2"})
        assert meta["bootloader_state"] == "unknown"

    def test_security_posture_filters_none(self):
        meta = extract_device_metadata({"ro.secure": "1"})
        assert "ro_secure" in meta["security_posture"]
        assert "ro_debuggable" not in meta["security_posture"]
        assert "crypto_state" not in meta["security_posture"]

    def test_security_posture_empty_when_no_security_props(self):
        meta = extract_device_metadata({"ro.product.model": "Test"})
        assert meta["security_posture"] == {}

    def test_chipset_fallback_mediatek(self):
        meta = extract_device_metadata({"ro.mediatek.platform": "MT6893"})
        assert meta["chipset"] == "MT6893"

    def test_chipset_fallback_chipname(self):
        meta = extract_device_metadata({"ro.hardware.chipname": "exynos990"})
        assert meta["chipset"] == "exynos990"

    def test_chipset_prefers_board_platform(self):
        meta = extract_device_metadata({
            "ro.board.platform": "gs201",
            "ro.mediatek.platform": "MT6893",
        })
        assert meta["chipset"] == "gs201"


class TestRealisticGetpropOutput:
    """Integration-style test with realistic getprop output."""

    REALISTIC_GETPROP = """\
[dalvik.vm.appimageformat]: [lz4]
[dalvik.vm.heapgrowthlimit]: [256m]
[dalvik.vm.heapmaxfree]: [8m]
[dalvik.vm.heapsize]: [512m]
[gsm.operator.alpha]: [T-Mobile]
[persist.sys.timezone]: [America/New_York]
[ro.board.platform]: [gs201]
[ro.boot.flash.locked]: [0]
[ro.boot.selinux]: [enforcing]
[ro.boot.verifiedbootstate]: [orange]
[ro.build.fingerprint]: [google/oriole/oriole:14/UP1A.231105.003/11148006:user/release-keys]
[ro.build.version.release]: [14]
[ro.build.version.sdk]: [34]
[ro.build.version.security_patch]: [2024-01-05]
[ro.crypto.state]: [encrypted]
[ro.debuggable]: [1]
[ro.product.brand]: [google]
[ro.product.model]: [Pixel 6]
[ro.secure]: [0]
[ro.adb.secure]: [0]
"""

    def test_end_to_end(self):
        props = parse_getprop_txt(self.REALISTIC_GETPROP)
        assert len(props) == 20
        meta = extract_device_metadata(props)
        assert meta["device_model"] == "Pixel 6"
        assert meta["manufacturer"] == "google"
        assert meta["android_version"] == "14"
        assert meta["api_level"] == 34
        assert meta["bootloader_state"] == "unlocked"
        assert meta["chipset"] == "gs201"
        assert meta["security_posture"]["ro_debuggable"] == "1"
        assert meta["security_posture"]["verified_boot"] == "orange"
