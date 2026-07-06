"""Contract tests for the ``app.ai.tools.fuzzing`` MCP tool handlers.

increase-coverage skill run: app/ai/tools/fuzzing.py sat at 6% coverage
(480 stmts / 451 miss) with no dedicated test file — only its underlying
service (``test_fuzzing_service.py``) and router (``test_fuzzing_router.py``)
were covered. This file exercises the MCP-facing handlers directly with a
``_StubContext`` + ``make_live_db`` (Rule #35b), mocking ``FuzzingService``
methods and the Docker client at the same boundaries the existing service/
router test files use, so the real AFL++ container never launches.

Scope: the pure helper functions (`_guess_file_extension`, `_is_cgi_binary`,
`_generate_cgi_harness`) plus the input-validation / branch-selection logic
in every handler. `_handle_diagnose_campaign`'s Docker-log-parsing branches
are covered for the common paths (container found/not-found, AFL log
pattern matches, low-coverage + hang-count heuristics); the full log-tail
formatting loop is exercised incidentally via the happy-path test.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.fuzzing import (
    _generate_cgi_harness,
    _guess_file_extension,
    _handle_analyze_target,
    _handle_check_status,
    _handle_diagnose_campaign,
    _handle_generate_dictionary,
    _handle_generate_harness,
    _handle_generate_seed_corpus,
    _handle_start_campaign,
    _handle_stop_campaign,
    _handle_triage_crash,
    _is_cgi_binary,
    register_fuzzing_tools,
)
from app.models import Firmware, Project
from app.models.fuzzing import FuzzingCampaign, FuzzingCrash
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub — the fuzzing handlers only touch db/firmware_id/project_id."""

    db: AsyncSession
    firmware_id: uuid.UUID
    project_id: uuid.UUID | None = None
    extracted_path: str | None = "/tmp/extract"
    detection_roots: list[str] = field(default_factory=list)

    def resolve_path(self, path: str) -> str:
        return f"/tmp/extract{path}"


@pytest.fixture
async def live_db():
    async with make_live_db() as db:
        yield db


async def _seed(db, *, extracted_path: str | None = "/tmp/extract") -> tuple[Project, Firmware]:
    project = Project(id=uuid.uuid4(), name="fuzz-tools-test", status="ready")
    db.add(project)
    await db.flush()

    firmware = Firmware(
        id=uuid.uuid4(),
        project_id=project.id,
        sha256="a" * 64,
        extracted_path=extracted_path,
        extraction_dir=extracted_path,
    )
    db.add(firmware)
    await db.flush()
    return project, firmware


def _campaign(project_id, firmware_id, **overrides) -> FuzzingCampaign:
    defaults = dict(
        id=uuid.uuid4(),
        project_id=project_id,
        firmware_id=firmware_id,
        binary_path="/usr/sbin/httpd",
        status="running",
        config={},
        stats={},
        crashes_count=0,
        error_message=None,
        container_id=None,
    )
    defaults.update(overrides)
    return FuzzingCampaign(**defaults)


# ---------------------------------------------------------------------------
# register_fuzzing_tools
# ---------------------------------------------------------------------------


def test_register_fuzzing_tools_registers_all_nine():
    registry = ToolRegistry()
    register_fuzzing_tools(registry)
    names = set(registry._tools.keys())
    assert names == {
        "analyze_fuzzing_target",
        "generate_fuzzing_dictionary",
        "generate_seed_corpus",
        "start_fuzzing_campaign",
        "check_fuzzing_status",
        "stop_fuzzing_campaign",
        "generate_fuzzing_harness",
        "triage_fuzzing_crash",
        "diagnose_fuzzing_campaign",
    }


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_guess_file_extension_xml():
    assert _guess_file_extension({"imports_of_interest": ["xmlParseFile"]}) == ".xml"


def test_guess_file_extension_json():
    assert _guess_file_extension({"imports_of_interest": ["cJSON_Parse"]}) == ".json"


def test_guess_file_extension_unknown():
    assert _guess_file_extension({"imports_of_interest": ["fopen"]}) == ""


def test_is_cgi_binary_via_getenv():
    analysis = {"imports_of_interest": ["getenv"], "network_functions": []}
    assert _is_cgi_binary(analysis, "myapp") is True


def test_is_cgi_binary_false_when_server_socket_present():
    analysis = {"imports_of_interest": ["getenv"], "network_functions": ["bind", "listen"]}
    assert _is_cgi_binary(analysis, "myapp") is False


def test_is_cgi_binary_via_name_heuristic():
    analysis = {"imports_of_interest": [], "network_functions": []}
    assert _is_cgi_binary(analysis, "goform") is True


def test_generate_cgi_harness_embeds_binary_path():
    harness = _generate_cgi_harness("/usr/bin/goform")
    assert "SCRIPT_NAME=\"/usr/bin/goform\"" in harness
    assert "exec /firmware/usr/bin/goform" in harness


# ---------------------------------------------------------------------------
# _handle_analyze_target
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyze_target_requires_binary_path(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_analyze_target({}, ctx)
    assert result == "Error: binary_path is required."


@pytest.mark.asyncio
async def test_analyze_target_firmware_not_found(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_analyze_target({"binary_path": "/bin/x"}, ctx)
    assert result == "Error: firmware not found."


@pytest.mark.asyncio
async def test_analyze_target_service_value_error(live_db):
    _, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.analyze_target",
        new=AsyncMock(side_effect=ValueError("binary not found")),
    ):
        result = await _handle_analyze_target({"binary_path": "/bin/x"}, ctx)
    assert result == "Error: binary not found"


@pytest.mark.asyncio
async def test_analyze_target_analysis_error_key(live_db):
    _, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.analyze_target",
        new=AsyncMock(return_value={"error": "ELF parse failed"}),
    ):
        result = await _handle_analyze_target({"binary_path": "/bin/x"}, ctx)
    assert "Error analyzing /bin/x: ELF parse failed" in result


@pytest.mark.asyncio
async def test_analyze_target_good_score_static_binary(live_db):
    _, firmware = await _seed(live_db)
    firmware.binary_info = {"is_static": True}
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)
    analysis = {
        "fuzzing_score": 75,
        "recommended_strategy": "stdin",
        "function_count": 12,
        "file_size": 4096,
        "dangerous_functions": ["strcpy"],
        "input_sources": ["read"],
        "network_functions": [],
        "protections": {"nx": True, "relro": "full", "canary": True, "pie": False},
    }
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.analyze_target",
        new=AsyncMock(return_value=analysis),
    ):
        result = await _handle_analyze_target({"binary_path": "/bin/x"}, ctx)
    assert "good target" in result
    assert "Dangerous sinks: strcpy" in result
    assert "No sysroot needed (static binary)" in result
    assert "good fuzzing target" in result


@pytest.mark.asyncio
async def test_analyze_target_moderate_score_dynamic_binary_missing_deps(live_db):
    _, firmware = await _seed(live_db)
    firmware.architecture = "arm"
    firmware.binary_info = {"is_static": False, "dependencies": ["libc.so.6"]}
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)
    analysis = {
        "fuzzing_score": 45,
        "recommended_strategy": "file",
        "function_count": 5,
        "file_size": 1024,
        "dangerous_functions": [],
        "input_sources": ["fread"],
        "network_functions": ["connect"],
        "protections": {},
    }
    with (
        patch(
            "app.ai.tools.fuzzing.FuzzingService.analyze_target",
            new=AsyncMock(return_value=analysis),
        ),
        patch("app.services.sysroot_service.get_sysroot_path", return_value="/sysroot/arm"),
        patch(
            "app.services.sysroot_service.check_dependencies",
            return_value={"missing": ["libc.so.6"]},
        ),
    ):
        result = await _handle_analyze_target({"binary_path": "/bin/x"}, ctx)
    assert "moderate" in result
    assert "Sysroot: /sysroot/arm" in result
    assert "Missing deps: libc.so.6" in result
    assert "Moderate fuzzing target" in result


@pytest.mark.asyncio
async def test_analyze_target_poor_score(live_db):
    _, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)
    analysis = {
        "fuzzing_score": 5,
        "recommended_strategy": "unknown",
        "function_count": 0,
        "file_size": 0,
        "dangerous_functions": [],
        "input_sources": [],
        "network_functions": [],
        "protections": {},
    }
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.analyze_target",
        new=AsyncMock(return_value=analysis),
    ):
        result = await _handle_analyze_target({"binary_path": "/bin/x"}, ctx)
    assert "poor target" in result
    assert "may not be a productive fuzzing target" in result


# ---------------------------------------------------------------------------
# _handle_generate_dictionary
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_dictionary_requires_binary_path(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_generate_dictionary({}, ctx)
    assert result == "Error: binary_path is required."


@pytest.mark.asyncio
async def test_generate_dictionary_not_unpacked(live_db):
    _, firmware = await _seed(live_db, extracted_path=None)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)
    result = await _handle_generate_dictionary({"binary_path": "/bin/x"}, ctx)
    assert result == "Error: firmware not found or not unpacked."


@pytest.mark.asyncio
async def test_generate_dictionary_happy_path_filters_entries(live_db):
    _, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)

    fake_proc = AsyncMock()
    fake_proc.communicate = AsyncMock(
        return_value=(
            b"GET\n%s\nabcXYZ12\nignored_because_over_16_characters_long\n=\n",
            b"",
        )
    )
    with patch(
        "asyncio.create_subprocess_exec", new=AsyncMock(return_value=fake_proc)
    ):
        result = await _handle_generate_dictionary({"binary_path": "/bin/httpd"}, ctx)

    assert "Generated AFL++ dictionary" in result
    assert 'token_' in result
    assert "GET" in result


@pytest.mark.asyncio
async def test_generate_dictionary_no_worthy_strings(live_db):
    _, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)

    fake_proc = AsyncMock()
    fake_proc.communicate = AsyncMock(return_value=(b"", b""))
    with patch(
        "asyncio.create_subprocess_exec", new=AsyncMock(return_value=fake_proc)
    ):
        result = await _handle_generate_dictionary({"binary_path": "/bin/httpd"}, ctx)

    assert result == "No dictionary-worthy strings found in the binary."


@pytest.mark.asyncio
async def test_generate_dictionary_timeout(live_db):
    _, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)

    fake_proc = MagicMock()
    # Plain MagicMock (not AsyncMock): asyncio.wait_for is fully mocked below
    # and never actually awaits this return value, so making it a coroutine
    # would just leak an "unawaited coroutine" warning.
    fake_proc.communicate = MagicMock(return_value=None)
    fake_proc.kill = MagicMock()
    with (
        patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=fake_proc)),
        patch("asyncio.wait_for", new=AsyncMock(side_effect=TimeoutError())),
    ):
        result = await _handle_generate_dictionary({"binary_path": "/bin/httpd"}, ctx)

    assert result == "Error: strings extraction timed out after 30 seconds."


@pytest.mark.asyncio
async def test_generate_dictionary_subprocess_error(live_db):
    _, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)

    with patch(
        "asyncio.create_subprocess_exec",
        new=AsyncMock(side_effect=OSError("strings not found")),
    ):
        result = await _handle_generate_dictionary({"binary_path": "/bin/httpd"}, ctx)

    assert "Error extracting strings" in result


# ---------------------------------------------------------------------------
# _handle_generate_seed_corpus (pure — no db access)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_seed_corpus_network():
    ctx = _StubContext(db=None, firmware_id=uuid.uuid4())
    result = await _handle_generate_seed_corpus({"input_type": "network"}, ctx)
    assert "network-based fuzzing" in result
    assert "seed_corpus values:" in result


@pytest.mark.asyncio
async def test_generate_seed_corpus_file():
    ctx = _StubContext(db=None, firmware_id=uuid.uuid4())
    result = await _handle_generate_seed_corpus({"input_type": "file"}, ctx)
    assert "file-based fuzzing" in result


@pytest.mark.asyncio
async def test_generate_seed_corpus_defaults_to_stdin():
    ctx = _StubContext(db=None, firmware_id=uuid.uuid4())
    result = await _handle_generate_seed_corpus({}, ctx)
    assert "stdin-based fuzzing" in result
    assert "Generated 5 seed inputs" in result


# ---------------------------------------------------------------------------
# _handle_generate_harness
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_harness_requires_binary_path(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_generate_harness({}, ctx)
    assert result == "Error: binary_path is required."


@pytest.mark.asyncio
async def test_generate_harness_firmware_not_found(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_generate_harness({"binary_path": "/bin/x"}, ctx)
    assert result == "Error: firmware not found."


@pytest.mark.asyncio
async def test_generate_harness_service_error(live_db):
    _, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.analyze_target",
        new=AsyncMock(side_effect=ValueError("no such binary")),
    ):
        result = await _handle_generate_harness({"binary_path": "/bin/x"}, ctx)
    assert result == "Error: no such binary"


@pytest.mark.asyncio
async def test_generate_harness_analysis_error_key(live_db):
    _, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.analyze_target",
        new=AsyncMock(return_value={"error": "bad elf"}),
    ):
        result = await _handle_generate_harness({"binary_path": "/bin/x"}, ctx)
    assert "Error analyzing /bin/x: bad elf" in result


@pytest.mark.asyncio
async def test_generate_harness_stdin_strategy(live_db):
    _, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)
    analysis = {"recommended_strategy": "stdin", "imports_of_interest": []}
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.analyze_target",
        new=AsyncMock(return_value=analysis),
    ):
        result = await _handle_generate_harness({"binary_path": "/bin/x"}, ctx)
    assert "STDIN fuzzing" in result


@pytest.mark.asyncio
async def test_generate_harness_file_strategy_with_extension(live_db):
    _, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)
    analysis = {
        "recommended_strategy": "file",
        "imports_of_interest": ["cJSON_Parse"],
    }
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.analyze_target",
        new=AsyncMock(return_value=analysis),
    ):
        result = await _handle_generate_harness({"binary_path": "/bin/parse"}, ctx)
    assert "FILE-based fuzzing" in result
    assert 'arguments: "@@.json"' in result


@pytest.mark.asyncio
async def test_generate_harness_network_cgi_strategy(live_db):
    _, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)
    analysis = {
        "recommended_strategy": "network",
        "imports_of_interest": ["getenv"],
        "network_functions": [],
    }
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.analyze_target",
        new=AsyncMock(return_value=analysis),
    ):
        result = await _handle_generate_harness({"binary_path": "/www/cgi-bin/x"}, ctx)
    assert "CGI-style via harness script" in result
    assert "harness_script: (the script above)" in result


@pytest.mark.asyncio
async def test_generate_harness_network_daemon_strategy(live_db):
    _, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)
    analysis = {
        "recommended_strategy": "network",
        "imports_of_interest": [],
        "network_functions": ["bind", "listen", "accept"],
    }
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.analyze_target",
        new=AsyncMock(return_value=analysis),
    ):
        result = await _handle_generate_harness({"binary_path": "/usr/sbin/httpd"}, ctx)
    assert "daemon-style with desock" in result
    assert "desock: true" in result


@pytest.mark.asyncio
async def test_generate_harness_input_type_override(live_db):
    _, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id)
    analysis = {"recommended_strategy": "network", "imports_of_interest": []}
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.analyze_target",
        new=AsyncMock(return_value=analysis),
    ):
        result = await _handle_generate_harness(
            {"binary_path": "/bin/x", "input_type": "stdin"}, ctx
        )
    assert "Using strategy: stdin" in result
    assert "STDIN fuzzing" in result


# ---------------------------------------------------------------------------
# _handle_start_campaign
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_campaign_requires_binary_path(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_start_campaign({}, ctx)
    assert result == "Error: binary_path is required."


@pytest.mark.asyncio
async def test_start_campaign_firmware_not_found(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_start_campaign({"binary_path": "/bin/x"}, ctx)
    assert result == "Error: firmware not found."


@pytest.mark.asyncio
async def test_start_campaign_value_error(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.create_campaign",
        new=AsyncMock(side_effect=ValueError("campaign already running")),
    ):
        result = await _handle_start_campaign({"binary_path": "/bin/x"}, ctx)
    assert result == "Error: campaign already running"


@pytest.mark.asyncio
async def test_start_campaign_unexpected_exception(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.create_campaign",
        new=AsyncMock(side_effect=RuntimeError("docker down")),
    ):
        result = await _handle_start_campaign({"binary_path": "/bin/x"}, ctx)
    assert "Error starting campaign: docker down" in result


@pytest.mark.asyncio
async def test_start_campaign_happy_path_builds_full_config(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    created = _campaign(project.id, firmware.id, status="created", error_message=None)
    started = _campaign(project.id, firmware.id, status="queued", error_message=None)
    started.id = created.id

    with (
        patch(
            "app.ai.tools.fuzzing.FuzzingService.create_campaign",
            new=AsyncMock(return_value=created),
        ),
        patch(
            "app.ai.tools.fuzzing.FuzzingService.start_campaign",
            new=AsyncMock(return_value=started),
        ),
    ):
        result = await _handle_start_campaign(
            {
                "binary_path": "/usr/sbin/httpd",
                "timeout_per_exec": 50000,
                "memory_limit": 4096,
                "dictionary": 'token_0="GET"',
                "seed_corpus": ["QUFB"],
                "arguments": "@@",
                "environment": {"FOO": "bar"},
                "harness_script": "#!/bin/sh\necho hi\n",
                "desock": True,
            },
            ctx,
        )

    assert "Fuzzing campaign started successfully." in result
    assert str(started.id) in result
    assert "check_fuzzing_status" in result


@pytest.mark.asyncio
async def test_start_campaign_reports_error_message_on_campaign(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    created = _campaign(project.id, firmware.id, status="error", error_message="boom")
    with (
        patch(
            "app.ai.tools.fuzzing.FuzzingService.create_campaign",
            new=AsyncMock(return_value=created),
        ),
        patch(
            "app.ai.tools.fuzzing.FuzzingService.start_campaign",
            new=AsyncMock(return_value=created),
        ),
    ):
        result = await _handle_start_campaign({"binary_path": "/bin/x"}, ctx)
    assert "Error: boom" in result


# ---------------------------------------------------------------------------
# _handle_check_status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_status_by_id_value_error(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.get_campaign_status",
        new=AsyncMock(side_effect=ValueError("not found")),
    ):
        result = await _handle_check_status({"campaign_id": str(uuid.uuid4())}, ctx)
    assert result == "Error: not found"


@pytest.mark.asyncio
async def test_check_status_by_id_with_stats_and_crashes(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    campaign = _campaign(
        project.id,
        firmware.id,
        stats={
            "execs_per_sec": 120,
            "total_execs": 5000,
            "corpus_count": 30,
            "saved_crashes": 2,
            "saved_hangs": 1,
            "stability": "98.5%",
            "bitmap_cvg": "12.3%",
        },
        crashes_count=1,
        error_message="minor warning",
    )
    crash = FuzzingCrash(
        id=uuid.uuid4(),
        campaign_id=campaign.id,
        crash_filename="id:000000",
        signal="SIGSEGV",
        exploitability="exploitable",
    )
    with (
        patch(
            "app.ai.tools.fuzzing.FuzzingService.get_campaign_status",
            new=AsyncMock(return_value=campaign),
        ),
        patch(
            "app.ai.tools.fuzzing.FuzzingService.get_crashes",
            new=AsyncMock(return_value=[crash]),
        ),
    ):
        result = await _handle_check_status(
            {"campaign_id": str(campaign.id)}, ctx
        )
    assert "Execs/sec: 120" in result
    assert "Crashes (1):" in result
    assert "SIGSEGV" in result
    assert "[exploitable]" in result
    assert "Error: minor warning" in result


@pytest.mark.asyncio
async def test_check_status_list_empty(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.list_campaigns",
        new=AsyncMock(return_value=[]),
    ):
        result = await _handle_check_status({}, ctx)
    assert result == "No fuzzing campaigns found for this project."


@pytest.mark.asyncio
async def test_check_status_list_all(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    c1 = _campaign(project.id, firmware.id, status="running", crashes_count=3)
    c2 = _campaign(project.id, firmware.id, status="totally-custom-status", crashes_count=0)
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.list_campaigns",
        new=AsyncMock(return_value=[c1, c2]),
    ):
        result = await _handle_check_status({}, ctx)
    assert "[RUNNING]" in result
    assert "3 crashes" in result
    assert "[totally-custom-status]" in result


# ---------------------------------------------------------------------------
# _handle_stop_campaign
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stop_campaign_requires_campaign_id(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_stop_campaign({}, ctx)
    assert result == "Error: campaign_id is required."


@pytest.mark.asyncio
async def test_stop_campaign_value_error(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.stop_campaign",
        new=AsyncMock(side_effect=ValueError("not found")),
    ):
        result = await _handle_stop_campaign({"campaign_id": str(uuid.uuid4())}, ctx)
    assert result == "Error: not found"


@pytest.mark.asyncio
async def test_stop_campaign_happy_path(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    campaign = _campaign(
        project.id,
        firmware.id,
        status="stopped",
        stats={"total_execs": 999, "saved_crashes": 4},
        crashes_count=4,
    )
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.stop_campaign",
        new=AsyncMock(return_value=campaign),
    ):
        result = await _handle_stop_campaign({"campaign_id": str(campaign.id)}, ctx)
    assert f"Campaign {campaign.id} stopped." in result
    assert "Total execs: 999" in result
    assert "Final crash count: 4" in result


# ---------------------------------------------------------------------------
# _handle_triage_crash
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_triage_crash_requires_ids(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_triage_crash({"campaign_id": str(uuid.uuid4())}, ctx)
    assert result == "Error: campaign_id and crash_id are required."


@pytest.mark.asyncio
async def test_triage_crash_value_error(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.triage_crash",
        new=AsyncMock(side_effect=ValueError("crash not found")),
    ):
        result = await _handle_triage_crash(
            {"campaign_id": str(uuid.uuid4()), "crash_id": str(uuid.uuid4())}, ctx
        )
    assert result == "Error: crash not found"


@pytest.mark.asyncio
async def test_triage_crash_exploitable_happy_path(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    crash = FuzzingCrash(
        id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        crash_filename="id:000001",
        signal="SIGSEGV",
        exploitability="exploitable",
        crash_size=128,
        stack_trace="#0 0xdeadbeef in strcpy ()",
    )
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.triage_crash",
        new=AsyncMock(return_value=crash),
    ):
        result = await _handle_triage_crash(
            {"campaign_id": str(uuid.uuid4()), "crash_id": str(crash.id)}, ctx
        )
    assert "Crash triage: id:000001" in result
    assert "Stack trace:" in result
    assert "appears exploitable" in result


@pytest.mark.asyncio
async def test_triage_crash_unknown_exploitability_no_recommendation(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    crash = FuzzingCrash(
        id=uuid.uuid4(),
        campaign_id=uuid.uuid4(),
        crash_filename="id:000002",
        signal=None,
        exploitability=None,
        crash_size=None,
        stack_trace=None,
    )
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.triage_crash",
        new=AsyncMock(return_value=crash),
    ):
        result = await _handle_triage_crash(
            {"campaign_id": str(uuid.uuid4()), "crash_id": str(crash.id)}, ctx
        )
    assert "Signal: unknown" in result
    assert "Exploitability: unknown" in result
    assert "appears exploitable" not in result


# ---------------------------------------------------------------------------
# _handle_diagnose_campaign
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_diagnose_campaign_requires_campaign_id(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_diagnose_campaign({}, ctx)
    assert result == "Error: campaign_id is required."


@pytest.mark.asyncio
async def test_diagnose_campaign_value_error(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.get_campaign_status",
        new=AsyncMock(side_effect=ValueError("not found")),
    ):
        result = await _handle_diagnose_campaign({"campaign_id": str(uuid.uuid4())}, ctx)
    assert result == "Error: not found"


@pytest.mark.asyncio
async def test_diagnose_campaign_error_status_and_stopped(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    campaign = _campaign(
        project.id, firmware.id, status="error", error_message="crashed on boot"
    )
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.get_campaign_status",
        new=AsyncMock(return_value=campaign),
    ):
        result = await _handle_diagnose_campaign({"campaign_id": str(campaign.id)}, ctx)
    assert "ERROR: crashed on boot" in result
    assert "ISSUES FOUND:" in result
    assert "Campaign is in error state" in result


@pytest.mark.asyncio
async def test_diagnose_campaign_no_container_found(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    campaign = _campaign(
        project.id, firmware.id, status="running", container_id="abc123",
        stats={"total_execs": 0},
    )

    import docker.errors

    fake_client = MagicMock()
    fake_client.containers.get.side_effect = docker.errors.NotFound("gone")
    with (
        patch(
            "app.ai.tools.fuzzing.FuzzingService.get_campaign_status",
            new=AsyncMock(return_value=campaign),
        ),
        patch("app.ai.tools.fuzzing.get_docker_client", return_value=fake_client),
    ):
        result = await _handle_diagnose_campaign({"campaign_id": str(campaign.id)}, ctx)
    assert "Container: NOT FOUND" in result
    assert "Container no longer exists" in result
    assert "Zero executions" in result


@pytest.mark.asyncio
async def test_diagnose_campaign_running_with_afl_log_and_low_coverage_network_hint(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    campaign = _campaign(
        project.id,
        firmware.id,
        status="running",
        container_id="abc123",
        config={"desock": False},
        stats={
            "total_execs": 500,
            "execs_per_sec": 10,
            "bitmap_cvg": "1.2%",
            "saved_crashes": 0,
            "saved_hangs": 20,
            "corpus_count": 2,
        },
    )

    def _exec_run(cmd):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
        result = MagicMock()
        if "afl.log" in cmd_str:
            result.exit_code = 0
            result.output = b"No instrumentation detected\ncan't find shared lib\n"
        elif "afl-fuzz" in cmd_str:
            result.exit_code = 0
        else:
            result.exit_code = 1
        return result

    fake_container = MagicMock()
    fake_container.exec_run.side_effect = _exec_run
    fake_client = MagicMock()
    fake_client.containers.get.return_value = fake_container

    network_analysis = {"recommended_strategy": "network"}
    with (
        patch(
            "app.ai.tools.fuzzing.FuzzingService.get_campaign_status",
            new=AsyncMock(return_value=campaign),
        ),
        patch("app.ai.tools.fuzzing.get_docker_client", return_value=fake_client),
        patch(
            "app.ai.tools.fuzzing.FuzzingService.analyze_target",
            new=AsyncMock(return_value=network_analysis),
        ),
    ):
        result = await _handle_diagnose_campaign({"campaign_id": str(campaign.id)}, ctx)

    assert "AFL++ process: running" in result
    assert "Very low coverage" in result
    assert "NETWORK DAEMON but desock is disabled" in result
    assert "High hang count" in result
    assert "AFL++ aborted" not in result
    assert "No instrumentation" in result
    assert "Binary or dependency not found" in result
    assert "RECOMMENDATIONS:" in result


@pytest.mark.asyncio
async def test_diagnose_campaign_healthy_no_issues(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    campaign = _campaign(
        project.id,
        firmware.id,
        status="running",
        container_id=None,
        stats={
            "total_execs": 50000,
            "execs_per_sec": 800,
            "bitmap_cvg": "45.0%",
            "saved_crashes": 3,
            "saved_hangs": 1,
            "corpus_count": 400,
        },
    )
    with patch(
        "app.ai.tools.fuzzing.FuzzingService.get_campaign_status",
        new=AsyncMock(return_value=campaign),
    ):
        result = await _handle_diagnose_campaign({"campaign_id": str(campaign.id)}, ctx)
    assert "No issues detected — campaign appears healthy." in result
