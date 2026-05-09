"""SELinux policy analysis service for Android firmware.

Parses SELinux policy files (CIL, binary sepolicy) to identify permissive
domains, enforcement status, domain transitions, and security-relevant
policy characteristics.  Works offline with no external dependencies beyond
what ships in the container (setools / sesearch are optional).
"""

import logging
import os
import re
import subprocess

logger = logging.getLogger(__name__)

# Common locations for SELinux policy files in Android firmware
_POLICY_SEARCH_PATHS = [
    "system/etc/selinux",
    "vendor/etc/selinux",
    "odm/etc/selinux",
    "product/etc/selinux",
    "system_ext/etc/selinux",
]

_BINARY_POLICY_NAMES = [
    "plat_sepolicy.cil",
    "precompiled_sepolicy",
    "sepolicy",
]

# Top-level binary sepolicy locations
_ROOT_POLICY_PATHS = [
    "sepolicy",
    "system/sepolicy",
]


class SELinuxService:
    """Analyze SELinux policies from extracted Android firmware."""

    def __init__(self, extracted_root: str) -> None:
        self.extracted_root = os.path.realpath(extracted_root)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_policy(self) -> dict:
        """Full SELinux policy analysis.

        Returns a dict with keys:
          - has_selinux: bool
          - enforcement: dict from check_enforcement()
          - policy_files: list of relative paths to policy files found
          - permissive_domains: list of domain names
          - domain_count: int (approximate, from CIL type declarations)
          - neverallow_count: int (from CIL neverallow statements)
          - cil_stats: dict with counts of various statement types
        """
        policy_files = self._find_policy_files()
        if not policy_files:
            return {
                "has_selinux": False,
                "enforcement": {},
                "policy_files": [],
                "permissive_domains": [],
                "domain_count": 0,
                "neverallow_count": 0,
                "cil_stats": {},
            }

        enforcement = self.check_enforcement()
        permissive = self._find_permissive_domains_all(policy_files)
        cil_stats = self._gather_cil_stats(policy_files)

        return {
            "has_selinux": True,
            "enforcement": enforcement,
            "policy_files": [self._rel(p) for p in policy_files],
            "permissive_domains": sorted(set(permissive)),
            "domain_count": cil_stats.get("type_declarations", 0),
            "neverallow_count": cil_stats.get("neverallow_rules", 0),
            "cil_stats": cil_stats,
        }

    def check_enforcement(self) -> dict:
        """Check SELinux enforcement status from build properties.

        Returns a dict with:
          - enforcing: bool | None (None if unknown)
          - source: str describing where the info came from
          - details: dict of relevant properties found
        """
        result: dict = {
            "enforcing": None,
            "source": "unknown",
            "details": {},
        }

        # Check build.prop files for SELinux-related properties
        prop_files = [
            "system/build.prop",
            "vendor/build.prop",
            "default.prop",
            "system/etc/prop.default",
        ]

        se_props: dict[str, str] = {}
        for rel in prop_files:
            abs_path = os.path.join(self.extracted_root, rel)
            if not os.path.isfile(abs_path):
                continue
            try:
                with open(abs_path, errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if "=" not in line or line.startswith("#"):
                            continue
                        key, _, val = line.partition("=")
                        key = key.strip()
                        val = val.strip()
                        if "selinux" in key.lower() or key in (
                            "ro.build.selinux",
                            "ro.boot.selinux",
                            "security.selinux.status",
                        ):
                            se_props[key] = val
            except OSError:
                continue

        result["details"] = se_props

        # Determine enforcement
        if "ro.boot.selinux" in se_props:
            val = se_props["ro.boot.selinux"].lower()
            result["enforcing"] = val == "enforcing"
            result["source"] = "ro.boot.selinux"
        elif "ro.build.selinux" in se_props:
            val = se_props["ro.build.selinux"].lower()
            # ro.build.selinux=1 means enforcing on older Android
            result["enforcing"] = val in ("1", "enforcing")
            result["source"] = "ro.build.selinux"
        else:
            # Default: modern Android (5+) is always enforcing unless
            # explicitly disabled. If we see policy files, assume enforcing.
            policy_files = self._find_policy_files()
            if policy_files:
                result["enforcing"] = True
                result["source"] = "default (policy files present, modern Android enforces)"
            else:
                result["source"] = "no policy files or properties found"

        return result

    def find_permissive_domains(self, policy_path: str) -> list[str]:
        """Find permissive domains in a single policy file or directory.

        Tries (in order):
          1. setools Python API (SEPolicy)
          2. seinfo CLI tool
          3. CIL text parsing for (typepermissive ...) statements
        """
        abs_path = os.path.join(self.extracted_root, policy_path.lstrip("/"))
        abs_path = os.path.realpath(abs_path)
        if not abs_path.startswith(self.extracted_root):
            return []

        # If it's a directory, collect from all files inside
        if os.path.isdir(abs_path):
            return self._permissive_from_dir(abs_path)

        if not os.path.isfile(abs_path):
            return []

        # Try setools Python API
        domains = self._try_setools_permissive(abs_path)
        if domains is not None:
            return domains

        # Try seinfo CLI
        domains = self._try_seinfo_permissive(abs_path)
        if domains is not None:
            return domains

        # Fallback: CIL text parsing
        return self._parse_cil_permissive(abs_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _rel(self, abs_path: str) -> str:
        return "/" + os.path.relpath(abs_path, self.extracted_root)

    def _find_policy_files(self) -> list[str]:
        """Return absolute paths to all SELinux policy files found."""
        found: list[str] = []

        # Check standard Android policy directories
        for rel_dir in _POLICY_SEARCH_PATHS:
            abs_dir = os.path.join(self.extracted_root, rel_dir)
            if not os.path.isdir(abs_dir):
                continue
            for dirpath, _dirnames, filenames in os.walk(abs_dir):
                # Stay within extracted root
                real_dir = os.path.realpath(dirpath)
                if not real_dir.startswith(self.extracted_root):
                    continue
                for fname in filenames:
                    if fname.endswith((".cil", ".conf")) or fname in (
                        "sepolicy",
                        "precompiled_sepolicy",
                        "selinux_version",
                        "plat_sepolicy_and_mapping.sha256",
                    ):
                        found.append(os.path.join(real_dir, fname))

        # Check root-level policy files
        for rel in _ROOT_POLICY_PATHS:
            abs_path = os.path.join(self.extracted_root, rel)
            if os.path.isfile(abs_path) and abs_path not in found:
                found.append(os.path.realpath(abs_path))

        return found

    def _find_permissive_domains_all(self, policy_files: list[str]) -> list[str]:
        """Collect permissive domains from all discovered policy files."""
        domains: list[str] = []
        seen_dirs: set[str] = set()

        for pf in policy_files:
            parent = os.path.dirname(pf)
            if parent not in seen_dirs:
                seen_dirs.add(parent)
                domains.extend(self._permissive_from_dir(parent))

            # Also check the file itself if it's a binary policy
            if not pf.endswith(".cil"):
                result = self._try_setools_permissive(pf)
                if result is not None:
                    domains.extend(result)
                    continue
                result = self._try_seinfo_permissive(pf)
                if result is not None:
                    domains.extend(result)

        return domains

    def _permissive_from_dir(self, abs_dir: str) -> list[str]:
        """Collect permissive domains from CIL files in a directory."""
        domains: list[str] = []
        if not os.path.isdir(abs_dir):
            return domains
        for dirpath, _dirnames, filenames in os.walk(abs_dir):
            real_dir = os.path.realpath(dirpath)
            if not real_dir.startswith(self.extracted_root):
                continue
            for fname in filenames:
                if fname.endswith(".cil"):
                    domains.extend(
                        self._parse_cil_permissive(os.path.join(real_dir, fname))
                    )
        return domains

    def _parse_cil_permissive(self, filepath: str) -> list[str]:
        """Parse CIL file for (typepermissive ...) statements."""
        domains: list[str] = []
        try:
            with open(filepath, errors="replace") as f:
                for line in f:
                    line = line.strip()
                    # CIL format: (typepermissive domain_name)
                    m = re.match(r"\(typepermissive\s+(\S+)\)", line)
                    if m:
                        domains.append(m.group(1))
        except OSError:
            pass
        return domains

    def _try_setools_permissive(self, filepath: str) -> list[str] | None:
        """Try setools Python API. Returns None if not available."""
        try:
            import setools  # type: ignore[import-untyped]

            policy = setools.SELinuxPolicy(filepath)
            return [str(t) for t in policy.types() if t.ispermissive]
        except ImportError:
            return None
        except Exception as exc:
            logger.debug("setools failed on %s: %s", filepath, exc)
            return None

    def _try_seinfo_permissive(self, filepath: str) -> list[str] | None:
        """Try seinfo CLI tool. Returns None if not available."""
        try:
            proc = subprocess.run(
                ["seinfo", "-t", "--permissive", filepath],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode != 0:
                return None
            domains: list[str] = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("Permissive"):
                    domains.append(line)
            return domains
        except FileNotFoundError:
            return None
        except Exception as exc:
            logger.debug("seinfo failed on %s: %s", filepath, exc)
            return None

    def _gather_cil_stats(self, policy_files: list[str]) -> dict:
        """Count various CIL statement types across all .cil files."""
        stats = {
            "type_declarations": 0,
            "allow_rules": 0,
            "neverallow_rules": 0,
            "type_transitions": 0,
            "typepermissive": 0,
            "total_cil_files": 0,
        }

        patterns = {
            "type_declarations": re.compile(r"^\(type\s+"),
            "allow_rules": re.compile(r"^\(allow\s+"),
            "neverallow_rules": re.compile(r"^\(neverallow\s+"),
            "type_transitions": re.compile(r"^\(typetransition\s+"),
            "typepermissive": re.compile(r"^\(typepermissive\s+"),
        }

        seen: set[str] = set()
        for pf in policy_files:
            if not pf.endswith(".cil"):
                continue
            real = os.path.realpath(pf)
            if real in seen or not real.startswith(self.extracted_root):
                continue
            seen.add(real)
            stats["total_cil_files"] += 1
            try:
                with open(real, errors="replace") as f:
                    for line in f:
                        stripped = line.lstrip()
                        for key, pat in patterns.items():
                            if pat.match(stripped):
                                stats[key] += 1
                                break
            except OSError:
                continue

        return stats
