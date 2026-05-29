"""C4 android-posture walker registry-membership test (Rule #47).

C4 is ORDER-INDEPENDENT of C1/C2/C3 — it reads no other walker's output (it
synthesizes the gates_open deployment posture straight from the APK /
build.prop / device_owner XML tree). So the only Rule #47 contract here is
MEMBERSHIP: the safe-runner MUST be in WALKER_AUTO_TRIGGERS, else
android_posture_walk_status stays 'idle' forever (the 847eae9 orphan-state
failure mode — a walker that never auto-fires post-detection). This lives in
its own file (not the walker test file) so the Piece-3 walker commit stays
bisect-clean — the membership only becomes true once the Piece-5 registration
lands.
"""
from __future__ import annotations

from app.services import android_posture_walker


def test_c4_runner_registered_in_walker_auto_triggers():
    """The C4 safe-runner MUST be registered in WALKER_AUTO_TRIGGERS — else
    it never auto-fires post-detection and android_posture_walk_status stays
    'idle' forever (Rule #47 orphan-state trap, the 847eae9 failure mode)."""
    from app.workers.walker_registry import get_walker_auto_triggers

    runners = get_walker_auto_triggers()
    assert (
        android_posture_walker.auto_android_posture_walk_firmware_safe
        in runners
    ), (
        "auto_android_posture_walk_firmware_safe is NOT registered in "
        "WALKER_AUTO_TRIGGERS — the C4 walker will never auto-fire "
        "post-detection (Rule #47 orphan-state trap, the exact 847eae9 "
        "consumer-orphan failure mode)."
    )


def test_c4_runner_is_a_distinct_callable():
    """Defensive — the C4 runner must be its OWN callable, not an accidental
    alias of another walker's safe-runner (which would silently no-op C4)."""
    from app.services import network_exposure_walker, systemd_walker

    c4 = android_posture_walker.auto_android_posture_walk_firmware_safe
    assert c4 is not network_exposure_walker.auto_network_exposure_walk_firmware_safe
    assert c4 is not systemd_walker.auto_systemd_walk_firmware_safe
