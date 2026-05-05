"""Shared helpers for Android APK analysis tools.

Used by android.py, android_bytecode.py, and android_sast.py to avoid
duplicating APK resolution logic.
"""

from __future__ import annotations

import os

from app.ai.tool_registry import ToolContext

# Standard Android app directories within extracted firmware
APK_DIRS = (
    "system/app",
    "system/priv-app",
    "product/app",
    "product/priv-app",
    "vendor/app",
)

# Privileged app directory names paired with their partition prefixes.
# Used for firmware-context severity adjustment.
_PRIV_APP_PARTITIONS = ("system", "product", "vendor", "system_ext")


def find_apk(context: ToolContext, app_name: str | None, path: str | None) -> str:
    """Resolve an APK path from either *app_name* or *path*.

    Returns the absolute filesystem path to the APK file, validated
    against the sandbox.

    Raises ``ValueError`` with a user-friendly message on failure.
    """
    if path:
        resolved = context.resolve_path(path)
        if os.path.isfile(resolved) and resolved.lower().endswith(".apk"):
            return resolved
        # Maybe they gave a directory — look for an APK inside
        if os.path.isdir(resolved):
            for fname in os.listdir(resolved):
                if fname.lower().endswith(".apk"):
                    return os.path.join(resolved, fname)
        raise ValueError(
            f"No APK file found at path: {path}. "
            "Provide a direct path to an .apk file or use app_name instead."
        )

    if app_name:
        # Rule #16: walk every detection root, not just `extracted_path`.
        # Scatter-zip Android uploads expose multiple sibling partition
        # directories (system/, vendor/, product/) — APKs only present in
        # the secondary roots are otherwise invisible.
        for root in context.get_detection_roots():
            for app_dir in APK_DIRS:
                app_path = os.path.join(root, app_dir, app_name)
                if not os.path.isdir(app_path):
                    continue
                for fname in os.listdir(app_path):
                    if fname.lower().endswith(".apk"):
                        return os.path.join(app_path, fname)

        raise ValueError(
            f"App '{app_name}' not found in standard Android directories "
            f"({', '.join(APK_DIRS)}) under any detection root.  Use "
            "list_directory to browse the firmware or provide a direct path."
        )

    raise ValueError(
        "Provide either 'app_name' or 'path' to identify the APK to analyse."
    )


def check_androguard() -> str | None:
    """Return an error message if androguard is not installed, else None."""
    try:
        import androguard  # noqa: F401
        return None
    except ImportError:
        return (
            "Androguard is not installed in this environment. "
            "Install it with: pip install androguard>=4.1.2\n"
            "APK analysis requires the androguard package."
        )


def is_priv_app_path(apk_path: str, extracted_root: str) -> bool:
    """Check if an APK resides in a privileged app directory.

    Matches paths like ``system/priv-app/``, ``product/priv-app/``,
    ``vendor/priv-app/``, and ``system_ext/priv-app/`` — the actual
    Android firmware partition layouts for privileged apps.
    """
    rel = os.path.relpath(apk_path, extracted_root)
    parts = rel.split(os.sep)
    for i in range(len(parts) - 1):
        if parts[i] in _PRIV_APP_PARTITIONS and parts[i + 1] == "priv-app":
            return True
    return False
