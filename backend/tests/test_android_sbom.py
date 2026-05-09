"""Tests for Android SBOM parsing — build.prop and init.rc files."""

from pathlib import Path

import pytest

from app.services.sbom import SbomService


@pytest.fixture
def android_firmware_root(tmp_path: Path) -> Path:
    """Create a minimal Android firmware filesystem for SBOM tests.

    Layout:
        system/
            build.prop
            app/Settings/Settings.apk
            priv-app/SystemUI/SystemUI.apk
            etc/
                init/init.test.rc
                selinux/plat_sepolicy.cil
        vendor/
            build.prop
            etc/init/hw/init.vendor.rc
            lib/modules/test.ko
        init  (empty marker file)
        bin -> system/bin  (symlink, best-effort)
    """
    # system/build.prop
    system = tmp_path / "system"
    system.mkdir()
    (system / "build.prop").write_text(
        "# begin build properties\n"
        "ro.build.version.release=13\n"
        "ro.build.version.security_patch=2023-09-05\n"
        "ro.build.display.id=TP1A.220624.014\n"
        "ro.board.platform=msm8953\n"
        "ro.product.model=Pixel 4a\n"
    )

    # APK stubs
    (system / "app" / "Settings").mkdir(parents=True)
    (system / "app" / "Settings" / "Settings.apk").write_bytes(b"")
    (system / "priv-app" / "SystemUI").mkdir(parents=True)
    (system / "priv-app" / "SystemUI" / "SystemUI.apk").write_bytes(b"")

    # init.rc under system/etc/init
    (system / "etc" / "init").mkdir(parents=True)
    (system / "etc" / "init" / "init.test.rc").write_text(
        "# Test init file\n"
        "\n"
        "service healthd /system/bin/healthd\n"
        "    class core\n"
        "\n"
        "service surfaceflinger /system/bin/surfaceflinger\n"
        "    class core animation\n"
    )

    # SELinux
    (system / "etc" / "selinux").mkdir(parents=True)
    (system / "etc" / "selinux" / "plat_sepolicy.cil").write_bytes(b"")

    # system/bin for symlink target
    (system / "bin").mkdir(exist_ok=True)

    # vendor
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "build.prop").write_text(
        "ro.vendor.build.version.release=13\n"
        "ro.vendor.build.security_patch_level=2023-09-01\n"
    )
    (vendor / "etc" / "init" / "hw").mkdir(parents=True)
    (vendor / "etc" / "init" / "hw" / "init.vendor.rc").write_text(
        "service wifi_hal /vendor/bin/hw/android.hardware.wifi@1.0-service\n"
        "    class hal\n"
    )
    (vendor / "lib" / "modules").mkdir(parents=True)
    (vendor / "lib" / "modules" / "test.ko").write_bytes(b"")

    # Android init marker
    (tmp_path / "init").write_bytes(b"")

    # Symlink (best-effort — may fail on some filesystems)
    try:
        (tmp_path / "bin").symlink_to(str(system / "bin"))
    except OSError:
        pass

    return tmp_path


# -----------------------------------------------------------------------
# build.prop parsing tests
# -----------------------------------------------------------------------


class TestParseBuildProp:
    """Tests for SbomService._parse_build_prop()."""

    def test_standard_build_prop(self, android_firmware_root: Path):
        """Parses standard build.prop and creates an Android OS component."""
        svc = SbomService(str(android_firmware_root))
        prop_path = str(android_firmware_root / "system" / "build.prop")
        svc._parse_build_prop(prop_path)

        components = list(svc._components.values())
        # Should find the android OS component
        android_comps = [c for c in components if c.name == "android"]
        assert len(android_comps) == 1

        comp = android_comps[0]
        assert comp.version == "13"
        assert comp.type == "operating-system"
        assert comp.detection_source == "android_build_prop"
        assert comp.detection_confidence == "high"
        assert comp.metadata["security_patch"] == "2023-09-05"
        assert comp.metadata["platform"] == "msm8953"
        assert comp.metadata["model"] == "Pixel 4a"
        assert comp.metadata["build_id"] == "TP1A.220624.014"
        assert "cpe:2.3:o:google:android:13" in comp.cpe

    def test_build_prop_with_selinux_dir(self, android_firmware_root: Path):
        """When system/etc/selinux exists, an SELinux policy component is added."""
        svc = SbomService(str(android_firmware_root))
        prop_path = str(android_firmware_root / "system" / "build.prop")
        svc._parse_build_prop(prop_path)

        components = list(svc._components.values())
        selinux = [c for c in components if c.name == "android-selinux-policy"]
        assert len(selinux) == 1
        assert selinux[0].detection_source == "android_selinux"

    def test_missing_version_property(self, tmp_path: Path):
        """A build.prop without ro.build.version.release adds no android component."""
        (tmp_path / "system" / "etc" / "selinux").mkdir(parents=True)
        prop_file = tmp_path / "build.prop"
        prop_file.write_text(
            "ro.board.platform=exynos\n"
            "ro.product.model=Galaxy S21\n"
        )
        svc = SbomService(str(tmp_path))
        svc._parse_build_prop(str(prop_file))

        # No android OS component should be added
        android_comps = [c for c in svc._components.values() if c.name == "android"]
        assert len(android_comps) == 0

    def test_empty_build_prop(self, tmp_path: Path):
        """An empty build.prop file does not crash and adds nothing."""
        prop_file = tmp_path / "build.prop"
        prop_file.write_text("")
        svc = SbomService(str(tmp_path))
        svc._parse_build_prop(str(prop_file))
        assert len(svc._components) == 0

    def test_comments_and_blank_lines_ignored(self, tmp_path: Path):
        """Lines starting with # and blank lines are skipped."""
        prop_file = tmp_path / "build.prop"
        prop_file.write_text(
            "# This is a comment\n"
            "\n"
            "ro.build.version.release=12\n"
            "# Another comment\n"
        )
        # Need a system/etc/selinux dir to not produce that component
        svc = SbomService(str(tmp_path))
        svc._parse_build_prop(str(prop_file))

        android_comps = [c for c in svc._components.values() if c.name == "android"]
        assert len(android_comps) == 1
        assert android_comps[0].version == "12"

    def test_nonexistent_file(self, tmp_path: Path):
        """Calling _parse_build_prop on a nonexistent file does not raise."""
        svc = SbomService(str(tmp_path))
        svc._parse_build_prop(str(tmp_path / "does_not_exist"))
        assert len(svc._components) == 0


# -----------------------------------------------------------------------
# init.rc parsing tests
# -----------------------------------------------------------------------


class TestParseAndroidInitRc:
    """Tests for SbomService._parse_android_init_rc()."""

    def test_single_service(self, tmp_path: Path):
        """A single service declaration produces one init-<name> component."""
        rc_file = tmp_path / "init.test.rc"
        rc_file.write_text("service healthd /system/bin/healthd\n    class core\n")

        svc = SbomService(str(tmp_path))
        svc._parse_android_init_rc(str(rc_file), "system/etc/init")

        components = list(svc._components.values())
        assert len(components) == 1
        assert components[0].name == "init-healthd"
        assert components[0].metadata["binary"] == "/system/bin/healthd"
        assert components[0].detection_source == "android_init_service"
        assert components[0].type == "application"

    def test_multiple_services(self, tmp_path: Path):
        """Multiple service lines each produce a separate component."""
        rc_file = tmp_path / "init.rc"
        rc_file.write_text(
            "service healthd /system/bin/healthd\n"
            "    class core\n"
            "\n"
            "service surfaceflinger /system/bin/surfaceflinger\n"
            "    class core animation\n"
            "\n"
            "service wifi_hal /vendor/bin/hw/wifi@1.0-service\n"
            "    class hal\n"
        )

        svc = SbomService(str(tmp_path))
        svc._parse_android_init_rc(str(rc_file), "system/etc/init")

        components = list(svc._components.values())
        names = {c.name for c in components}
        assert names == {"init-healthd", "init-surfaceflinger", "init-wifi_hal"}

    def test_comments_and_blank_lines_skipped(self, tmp_path: Path):
        """Comments (# lines) and blanks do not produce components."""
        rc_file = tmp_path / "init.rc"
        rc_file.write_text(
            "# This is a comment\n"
            "\n"
            "service myservice /system/bin/myservice\n"
            "# Another comment\n"
            "    class main\n"
        )

        svc = SbomService(str(tmp_path))
        svc._parse_android_init_rc(str(rc_file), "etc/init")

        components = list(svc._components.values())
        assert len(components) == 1
        assert components[0].name == "init-myservice"

    def test_malformed_service_line_ignored(self, tmp_path: Path):
        """A 'service' line with fewer than 3 parts is silently skipped."""
        rc_file = tmp_path / "init.rc"
        rc_file.write_text(
            "service\n"
            "service incomplete\n"
            "service valid /system/bin/valid\n"
        )

        svc = SbomService(str(tmp_path))
        svc._parse_android_init_rc(str(rc_file), "etc/init")

        components = list(svc._components.values())
        assert len(components) == 1
        assert components[0].name == "init-valid"

    def test_empty_rc_file(self, tmp_path: Path):
        """An empty .rc file produces no components."""
        rc_file = tmp_path / "init.rc"
        rc_file.write_text("")

        svc = SbomService(str(tmp_path))
        svc._parse_android_init_rc(str(rc_file), "etc/init")

        assert len(svc._components) == 0

    def test_nonexistent_rc_file(self, tmp_path: Path):
        """Calling on a nonexistent file does not raise."""
        svc = SbomService(str(tmp_path))
        svc._parse_android_init_rc(str(tmp_path / "nope.rc"), "etc/init")
        assert len(svc._components) == 0

    def test_rel_dir_appears_in_file_paths(self, tmp_path: Path):
        """The rel_dir argument is used to construct the component file_paths."""
        rc_file = tmp_path / "init.vendor.rc"
        rc_file.write_text("service vendor_svc /vendor/bin/svc\n")

        svc = SbomService(str(tmp_path))
        svc._parse_android_init_rc(str(rc_file), "vendor/etc/init/hw")

        comp = list(svc._components.values())[0]
        assert comp.file_paths == ["/vendor/etc/init/hw/init.vendor.rc"]
