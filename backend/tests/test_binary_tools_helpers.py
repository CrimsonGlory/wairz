"""Tests for the binary-tool helpers added for the MCP field-findings fixes:
broad library search, export resolution with precise diagnostics, import/PLT
stub detection, and the cold-cache async-routing gate."""

import os
import types
from uuid import UUID

import pytest

from app.ai.tools import binary

FW = UUID("12345678-1234-5678-1234-567812345678")


class _FakeDB:
    async def commit(self):
        pass


def _ctx(real_root="/root"):
    return types.SimpleNamespace(
        firmware_id=FW,
        db=_FakeDB(),
        real_root_for=lambda _p: real_root,
    )


# --- _locate_libs: standard dirs + nonstandard rootfs walk -------------------


def test_locate_libs_standard_and_nonstandard(tmp_path):
    root = tmp_path
    (root / "usr" / "lib").mkdir(parents=True)
    (root / "usr" / "lib" / "libc.so.0").write_bytes(b"\x7fELF")
    (root / "opt" / "vendor").mkdir(parents=True)
    (root / "opt" / "vendor" / "libsml.so").write_bytes(b"\x7fELF")  # nonstandard

    located = binary._locate_libs(str(root), ["libc.so.0", "libsml.so", "libgone.so"])
    assert located["libc.so.0"].endswith("/usr/lib/libc.so.0")
    assert located["libsml.so"].endswith("/opt/vendor/libsml.so")  # found via walk
    assert "libgone.so" not in located  # genuinely missing


# --- _resolve_export_library: bucketing + first match ------------------------


def test_resolve_export_library_buckets(monkeypatch):
    # libsml.so present + exports the symbol; libfoo.so present but doesn't;
    # libgone.so missing on disk.
    monkeypatch.setattr(binary, "_locate_libs", lambda root, names: {
        "libsml.so": "/root/opt/libsml.so",
        "libfoo.so": "/root/lib/libfoo.so",
    })
    states = {"/root/opt/libsml.so": "found", "/root/lib/libfoo.so": "absent"}
    monkeypatch.setattr(binary, "_dynsym_func_state", lambda p, fn: states[p])

    found, report = binary._resolve_export_library(
        "/root", ["libfoo.so", "libsml.so", "libgone.so"], "pingTest",
    )
    assert found == "/root/opt/libsml.so"
    assert report["with_symbol"] == ["libsml.so"]
    assert report["found_no_symbol"] == ["libfoo.so"]
    assert report["missing_on_disk"] == ["libgone.so"]


def test_resolve_export_library_not_found(monkeypatch):
    monkeypatch.setattr(binary, "_locate_libs", lambda root, names: {})
    found, report = binary._resolve_export_library("/root", ["libgone.so"], "x")
    assert found is None
    assert report["missing_on_disk"] == ["libgone.so"]


# --- _stub_resolution_hint: thunk / import → hint; real func → None ----------


class _FakeCache:
    def __init__(self, functions, imports):
        self._functions = functions
        self._imports = imports

    async def get_functions(self, *a, **k):
        return self._functions

    async def get_imports(self, *a, **k):
        return self._imports


async def test_stub_hint_for_thunk(monkeypatch):
    monkeypatch.setattr(binary, "get_analysis_cache",
                        lambda: _FakeCache([{"name": "pingTest", "is_thunk": True}], []))
    out = await binary._stub_resolution_hint("/r/sbin/httpd", "/sbin/httpd", "pingTest", _ctx())
    assert out is not None
    assert "resolve_import" in out and "pingTest" in out and "thunk" in out.lower()


async def test_stub_hint_for_import(monkeypatch):
    monkeypatch.setattr(binary, "get_analysis_cache",
                        lambda: _FakeCache([{"name": "main", "is_thunk": False}],
                                           [{"name": "pingTest", "library": "libsml.so"}]))
    out = await binary._stub_resolution_hint("/r/sbin/httpd", "/sbin/httpd", "pingTest", _ctx())
    assert out is not None and "resolve_import" in out


async def test_no_hint_for_real_function(monkeypatch):
    monkeypatch.setattr(binary, "get_analysis_cache",
                        lambda: _FakeCache([{"name": "do_work", "is_thunk": False}],
                                           [{"name": "strcpy", "library": "libc.so"}]))
    out = await binary._stub_resolution_hint("/r/bin/x", "/bin/x", "do_work", _ctx())
    assert out is None


# --- _ensure_analyzed_or_route: local no-op; cloud complete; cloud cold -------


def _settings(backend):
    return types.SimpleNamespace(compute_backend=backend)


async def test_gate_local_is_noop(monkeypatch):
    monkeypatch.setattr(binary, "get_settings", lambda: _settings("local"))
    assert await binary._ensure_analyzed_or_route("/r/bin/x", _ctx()) is None


async def test_gate_cloud_complete_proceeds(monkeypatch):
    monkeypatch.setattr(binary, "get_settings", lambda: _settings("aws_batch"))

    class C:
        async def get_binary_sha256(self, p): return "abc"
        async def _is_analysis_complete(self, *a): return True

    monkeypatch.setattr(binary, "get_analysis_cache", lambda: C())
    assert await binary._ensure_analyzed_or_route("/r/bin/x", _ctx()) is None


async def test_gate_cloud_cold_dispatches(monkeypatch):
    monkeypatch.setattr(binary, "get_settings", lambda: _settings("aws_batch"))
    dispatched = {}

    class C:
        async def get_binary_sha256(self, p): return "abc"
        async def _is_analysis_complete(self, *a): return False
        async def get_run_status(self, *a): return None
        async def mark_run_started(self, *a, **k): dispatched["marked"] = True

    monkeypatch.setattr(binary, "get_analysis_cache", lambda: C())
    monkeypatch.setattr(binary, "get_dispatcher", lambda: types.SimpleNamespace(
        dispatch_analysis=lambda *a: types.SimpleNamespace(pid=None, ref="job-xyz")))

    out = await binary._ensure_analyzed_or_route("/r/sbin/httpd", _ctx())
    assert out is not None
    assert out.startswith("analyzing") and "job-xyz" in out
    assert "check_binary_analysis_status" in out
    assert dispatched.get("marked")


# --- hexdump_data ------------------------------------------------------------


def test_format_hexdump():
    out = binary._format_hexdump(b"\x7fELF\x01\x02hello", 0)
    assert out.startswith("00000000  7f 45 4c 46 01 02 68 65 6c 6c 6f")
    assert out.endswith("|.ELF..hello|")


async def test_hexdump_data_reads_file(tmp_path):
    f = tmp_path / "blob.bin"
    f.write_bytes(b"ABCD" * 10)
    ctx = types.SimpleNamespace(resolve_path=lambda p: str(f))
    out = await binary._handle_hexdump_data(
        {"binary_path": "/blob.bin", "offset": 0, "length": 8}, ctx)
    assert "Hex dump of blob.bin" in out and "41 42 43 44" in out


async def test_hexdump_data_offset_past_eof(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"AB")
    ctx = types.SimpleNamespace(resolve_path=lambda p: str(f))
    out = await binary._handle_hexdump_data({"binary_path": "/x.bin", "offset": 100}, ctx)
    assert "No bytes at offset 100" in out


# --- decompile_function cloud routing (cache hit vs async) -------------------


def _cloud_ctx():
    return types.SimpleNamespace(
        firmware_id=FW, db=_FakeDB(),
        real_root_for=lambda p: "/r", resolve_path=lambda p: "/r/bin/x",
    )


async def test_decompile_cloud_cache_hit_returns_code(monkeypatch):
    monkeypatch.setattr(binary, "get_settings", lambda: _settings("aws_batch"))

    class C:
        async def get_binary_sha256(self, p): return "abc"
        async def _is_analysis_complete(self, *a): return True
        async def get_functions(self, *a, **k): return [{"name": "main", "is_thunk": False}]
        async def get_imports(self, *a, **k): return []
        async def _get_cached(self, fw, sha, op, db):
            return {"decompiled_code": "int main(){return 0;}"} if op == "decompile:main" else None

    monkeypatch.setattr(binary, "get_analysis_cache", lambda: C())
    out = await binary._handle_decompile_function(
        {"binary_path": "/bin/x", "function_name": "main"}, _cloud_ctx())
    assert "int main(){return 0;}" in out


async def test_decompile_cloud_cache_miss_routes_async(monkeypatch):
    monkeypatch.setattr(binary, "get_settings", lambda: _settings("aws_batch"))

    class C:
        async def get_binary_sha256(self, p): return "abc"
        async def _is_analysis_complete(self, *a): return True
        async def get_functions(self, *a, **k): return [{"name": "main", "is_thunk": False}]
        async def get_imports(self, *a, **k): return []
        async def _get_cached(self, *a): return None  # miss

    monkeypatch.setattr(binary, "get_analysis_cache", lambda: C())

    async def fake_start(inp, ctx):
        return "started - decompiling, poll check_function_decompile_status."
    monkeypatch.setattr(binary, "_handle_start_function_decompile", fake_start)

    out = await binary._handle_decompile_function(
        {"binary_path": "/bin/x", "function_name": "main"}, _cloud_ctx())
    assert "started" in out and "check_function_decompile_status" in out
