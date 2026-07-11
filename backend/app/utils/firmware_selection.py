"""Helpers for choosing the "active" firmware version of a project.

Kept dependency-light so both routers/services and Pydantic schemas can import
it without pulling in heavy modules.
"""


def is_firmware_loadable(fw) -> bool:
    """Whether a firmware can actually be browsed/analyzed.

    Linux firmware needs an unpacked rootfs (``extracted_path``); RTOS/blob
    firmware is analyzable straight from its stored blob (``storage_path``).
    Duck-typed so it works on both ORM rows and Pydantic firmware schemas.
    """
    if getattr(fw, "extracted_path", None):
        return True
    if getattr(fw, "firmware_kind", None) == "rtos" and getattr(fw, "storage_path", None):
        return True
    return False


def pick_active_firmware(firmware_list):
    """Pick the default "active" firmware for a project.

    Prefers the most recently uploaded firmware that is actually loadable, so a
    newer upload that failed to unpack never masks an older working one. Falls
    back to the newest firmware overall when none are loadable yet. Returns
    ``None`` for an empty list.
    """
    if not firmware_list:
        return None
    loadable = [f for f in firmware_list if is_firmware_loadable(f)]
    pool = loadable or list(firmware_list)
    return max(pool, key=lambda f: f.created_at)
