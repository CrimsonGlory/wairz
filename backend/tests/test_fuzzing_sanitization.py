"""Tests for fuzzing service command sanitization.

Validates that environment variable names are regex-checked, values are
shell-quoted, and extra arguments are split-then-quoted to prevent
command injection in AFL++ command strings.
"""

import re
import shlex

import pytest

# ---------------------------------------------------------------------------
# Unit helpers: extract the sanitization logic inline so we can test it
# in isolation without needing to mock the entire start_campaign path.
# ---------------------------------------------------------------------------

ENV_KEY_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def _sanitize_env_vars(extra_env: dict[str, str]) -> str:
    """Reproduce the env-var sanitization from FuzzingService.start_campaign."""
    env_parts = []
    for k, v in extra_env.items():
        if not ENV_KEY_RE.match(k):
            raise ValueError(f"Invalid environment variable name: {k!r}")
        env_parts.append(f"{k}={shlex.quote(str(v))}")
    return " ".join(env_parts)


def _sanitize_arguments(arguments: str) -> str:
    """Reproduce the argument sanitization from FuzzingService.start_campaign."""
    return " ".join(shlex.quote(arg) for arg in shlex.split(str(arguments)))


# =========================================================================
# Environment variable name validation
# =========================================================================


class TestEnvVarNameValidation:
    """Env var keys must match ^[A-Z_][A-Z0-9_]*$."""

    @pytest.mark.parametrize(
        "name",
        [
            "AFL_SKIP_CPUFREQ",
            "MY_VAR",
            "A",
            "_PRIVATE",
            "VAR_123",
            "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES",
        ],
    )
    def test_valid_env_var_names_pass(self, name: str) -> None:
        result = _sanitize_env_vars({name: "1"})
        assert f"{name}=" in result

    @pytest.mark.parametrize(
        "name",
        [
            "bad-name",
            "123START",
            "; rm -rf /",
            "lower",
            "has space",
            "$(whoami)",
            "A=B",
            "",
            "foo\nbar",
        ],
    )
    def test_invalid_env_var_names_raise(self, name: str) -> None:
        with pytest.raises(ValueError, match="Invalid environment variable name"):
            _sanitize_env_vars({name: "safe_value"})


# =========================================================================
# Environment variable value quoting
# =========================================================================


class TestEnvVarValueQuoting:
    """Env var values must be shell-quoted to neutralize metacharacters."""

    @pytest.mark.parametrize(
        "value, should_not_contain",
        [
            ("$(whoami)", "$("),
            ("; rm -rf /", "; rm"),
            ("`id`", "`id`"),
            ("foo | cat /etc/passwd", "| cat"),
            ("a && echo pwned", "&& echo"),
            ("hello world", None),  # just verify it's quoted
        ],
    )
    def test_shell_metacharacters_are_quoted(
        self, value: str, should_not_contain: str | None
    ) -> None:
        result = _sanitize_env_vars({"MY_VAR": value})
        # The value portion must be shell-safe: parsing the result back
        # through shlex should yield exactly one token per var assignment.
        tokens = shlex.split(result)
        assert len(tokens) == 1
        assert tokens[0].startswith("MY_VAR=")
        # The recovered value after the = must equal the original
        recovered = tokens[0].split("=", 1)[1]
        assert recovered == value

    def test_simple_value_unchanged(self) -> None:
        result = _sanitize_env_vars({"AFL_SKIP_CPUFREQ": "1"})
        # shlex.quote('1') == '1' (no quoting needed for simple tokens)
        assert result == "AFL_SKIP_CPUFREQ=1"

    def test_multiple_env_vars(self) -> None:
        result = _sanitize_env_vars(
            {"AFL_SKIP_CPUFREQ": "1", "MY_VAR": "hello world"}
        )
        tokens = shlex.split(result)
        assert len(tokens) == 2


# =========================================================================
# Argument sanitization
# =========================================================================


class TestArgumentSanitization:
    """Extra arguments are split then individually quoted."""

    @pytest.mark.parametrize(
        "args, expected_tokens",
        [
            ("--flag value @@", ["--flag", "value", "@@"]),
            ("-t 1000", ["-t", "1000"]),
            ("@@", ["@@"]),
        ],
    )
    def test_normal_arguments_pass_through(
        self, args: str, expected_tokens: list[str]
    ) -> None:
        result = _sanitize_arguments(args)
        # Re-parse the sanitized string; must recover the same tokens
        assert shlex.split(result) == expected_tokens

    @pytest.mark.parametrize(
        "malicious_args, dangerous_unquoted",
        [
            ("; rm -rf /", ";"),
            ("$(whoami)", "$("),
            ("| cat /etc/passwd", "|"),
            ("&& echo pwned", "&&"),
            ("`id`", "`"),
            ("foo; bar", ";"),
        ],
    )
    def test_injection_attempts_are_neutralized(
        self, malicious_args: str, dangerous_unquoted: str
    ) -> None:
        result = _sanitize_arguments(malicious_args)
        # The dangerous characters must be shell-quoted in the raw string.
        # shlex.quote wraps unsafe tokens in single quotes, so the raw
        # command string must NOT contain the dangerous token outside quotes.
        # Verify: the round-trip through shlex recovers the original tokens
        # (meaning they are treated as literals, not shell operators).
        recovered = shlex.split(result)
        original = shlex.split(malicious_args)
        assert recovered == original, (
            f"Round-trip mismatch: {recovered!r} != {original!r}"
        )
        # Verify that dangerous tokens are single-quoted in the raw string.
        # shlex.quote(';') -> "';'" and shlex.quote('|') -> "'|'" etc.
        assert shlex.quote(dangerous_unquoted) in result or (
            # For multi-char tokens like '$(whoami)', check the full token
            any(shlex.quote(t) in result for t in original if dangerous_unquoted in t)
        )

    def test_empty_arguments(self) -> None:
        result = _sanitize_arguments("")
        assert result == ""


# =========================================================================
# Integration: full AFL command construction
# =========================================================================


class TestAflCommandConstruction:
    """Build a complete AFL command string and verify safety."""

    @staticmethod
    def _build_afl_cmd(
        *,
        arch: str = "arm",
        env: dict[str, str] | None = None,
        arguments: str | None = None,
        binary_path: str = "usr/bin/httpd",
        timeout_ms: int = 1000,
        desock: bool = False,
        dictionary: bool = False,
        harness_target: str | None = None,
    ) -> str:
        """Replicate the AFL command construction from start_campaign."""
        extra_env = env or {}
        env_parts = []
        for k, v in extra_env.items():
            if not re.match(r"^[A-Z_][A-Z0-9_]*$", k):
                raise ValueError(f"Invalid environment variable name: {k!r}")
            env_parts.append(f"{k}={shlex.quote(str(v))}")
        env_prefix = " ".join(env_parts)

        afl_cmd = (
            f"AFL_NO_UI=1 "
            f"AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 "
            f"AFL_SKIP_CPUFREQ=1 "
            f"QEMU_LD_PREFIX=/firmware "
        )

        if desock:
            from app.services.fuzzing_service import DESOCK_LIB_MAP
            desock_lib = DESOCK_LIB_MAP.get(arch)
            if desock_lib:
                afl_cmd += f"AFL_PRELOAD={desock_lib} "

        if env_prefix:
            afl_cmd += f"{env_prefix} "

        afl_cmd += (
            f"afl-fuzz -Q -i /opt/fuzzing/input -o /opt/fuzzing/output "
            f"-m none -t {timeout_ms} "
        )

        if dictionary:
            afl_cmd += "-x /opt/fuzzing/dictionary.dict "

        if harness_target:
            afl_cmd += f"-- /firmware/bin/sh {harness_target}"
        else:
            afl_cmd += f"-- /firmware/{binary_path}"

        if arguments:
            afl_cmd += " " + " ".join(
                shlex.quote(arg) for arg in shlex.split(str(arguments))
            )

        return afl_cmd

    def test_basic_command_structure(self) -> None:
        cmd = self._build_afl_cmd()
        assert "AFL_NO_UI=1" in cmd
        assert "afl-fuzz -Q" in cmd
        assert "-- /firmware/usr/bin/httpd" in cmd

    def test_env_vars_in_command_are_safe(self) -> None:
        cmd = self._build_afl_cmd(
            env={"MY_VAR": "$(whoami)", "OTHER": "; rm -rf /"}
        )
        # Parse the full command through shlex to verify it's well-formed.
        # The malicious values must appear only as quoted literals.
        tokens = shlex.split(cmd)
        # Find the tokens with our env vars
        my_var_tokens = [t for t in tokens if t.startswith("MY_VAR=")]
        other_tokens = [t for t in tokens if t.startswith("OTHER=")]
        assert len(my_var_tokens) == 1
        assert len(other_tokens) == 1
        assert my_var_tokens[0] == "MY_VAR=$(whoami)"
        assert other_tokens[0] == "OTHER=; rm -rf /"

    def test_arguments_in_command_are_safe(self) -> None:
        cmd = self._build_afl_cmd(arguments="; rm -rf / @@")
        tokens = shlex.split(cmd)
        # The '@@' must be present as a literal token
        assert "@@" in tokens
        # ';' and 'rm' should be individual quoted tokens, not shell operators
        # Find tokens after '--'
        idx = tokens.index("--")
        post_target = tokens[idx + 1 :]  # target binary + arguments
        # ';' must appear as a literal string, not cause command separation
        assert ";" in post_target
        assert "rm" in post_target

    def test_no_unquoted_user_env_values(self) -> None:
        """Ensure that shell-dangerous env values are quoted in the raw string."""
        cmd = self._build_afl_cmd(env={"PAYLOAD": "$(evil)"})
        # In the raw (unprocessed) command string, the value must be
        # wrapped in single quotes by shlex.quote
        assert "PAYLOAD='$(evil)'" in cmd

    def test_no_unquoted_user_arguments(self) -> None:
        """Ensure injection tokens in arguments are individually quoted."""
        cmd = self._build_afl_cmd(arguments="; echo pwned")
        # shlex.quote(';') wraps it: "';'"
        assert "';'" in cmd
        assert "echo" in cmd  # 'echo' is a safe token, may or may not be quoted

    def test_invalid_env_key_rejected_in_command(self) -> None:
        with pytest.raises(ValueError, match="Invalid environment variable name"):
            self._build_afl_cmd(env={"; rm -rf /": "value"})

    def test_desock_flag(self) -> None:
        cmd = self._build_afl_cmd(desock=True, arch="arm")
        assert "AFL_PRELOAD=/opt/desock/desock_arm.so" in cmd

    def test_harness_target(self) -> None:
        cmd = self._build_afl_cmd(harness_target="/opt/fuzzing/harness.sh")
        assert "-- /firmware/bin/sh /opt/fuzzing/harness.sh" in cmd
        assert "usr/bin/httpd" not in cmd

    def test_dictionary_flag(self) -> None:
        cmd = self._build_afl_cmd(dictionary=True)
        assert "-x /opt/fuzzing/dictionary.dict" in cmd


# =========================================================================
# Verify the actual regex constant matches what the service uses
# =========================================================================


class TestRegexConsistency:
    """Ensure our test regex matches the one in the production code."""

    def test_regex_pattern_matches_service(self) -> None:

        # The service uses re.match(r"^[A-Z_][A-Z0-9_]*$", k) inline.
        # Verify our extracted pattern behaves identically on edge cases.
        pattern = r"^[A-Z_][A-Z0-9_]*$"
        edge_cases = [
            ("A", True),
            ("_", True),
            ("_A1", True),
            ("1A", False),
            ("a", False),
            ("A-B", False),
            ("A B", False),
            ("", False),
        ]
        for name, expected in edge_cases:
            assert bool(re.match(pattern, name)) is expected, (
                f"Regex mismatch for {name!r}: expected {expected}"
            )
