"""Service-layer tests for ``app.services.document_service``.

Phase 2 Wave 8 file 1 of 4 — backfills service-layer tests for the
document upload + note + content service (317 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

The service is a filesystem-as-DB layer: every Document row has a
companion file at ``settings.storage_root/projects/<project_id>/
documents/<doc_id>_<filename>``. Tests must verify BOTH the DB row
and the on-disk file persist together (atomic create / atomic delete).

Rule #30 distribution: ``pypdf.PdfReader`` is LAZY-imported inside
``read_text_content`` at line 300 of document_service.py — the import
is gated behind the ``.pdf`` filename check so non-PDF document
uploads don't pay the ~50ms pypdf import cost. Patches MUST hit the
SOURCE module via ``sys.modules`` injection (matches Wave 7 selinux
+ report patterns); ``patch("app.services.document_service.pypdf...",
...)`` is a SILENT NO-OP because the consumer module never bound the
name at module scope.

Coverage targets:

* ``upload`` — happy path persists Document + file; size cap; count cap.
* ``list_by_project`` — order_by created_at desc; limit/offset.
* ``get`` / ``update_description`` — happy + missing-id paths.
* ``delete`` — removes both row + on-disk file (atomic).
* ``create_note`` — title sanitization (slashes), Untitled fallback,
  full Document persistence.
* ``create_document`` — extension allowlist; updates existing in-place
  when filename matches; respects MAX_DOCUMENTS_PER_PROJECT only on
  NEW creates.
* ``update_content`` — re-hashes + re-writes; returns None for missing.
* ``read_text_content`` — text formats decoded directly; PDFs go
  through pypdf; missing file returns sentinel; pypdf exceptions caught.
* **Rule #30 SOURCE-patch class** ``TestRule30PypdfSourcePatch`` —
  proves pypdf is NOT a consumer-module attribute and the sys.modules
  injection is the canonical patch shape; hasattr-sentinel against
  future top-level promotion (matches Wave 7 selinux discipline).
* **Rule #35b live canary** — real upload via UploadFile fixture →
  SELECT Document row → assert original_filename / content_type /
  file_size / sha256 all persisted; PDF text-extraction with mocked
  PdfReader returning a real text block.
"""
from __future__ import annotations

import hashlib
import io
import os
import sys
import uuid
from datetime import UTC
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import UploadFile
from sqlalchemy import select
from starlette.datastructures import Headers

from app.models.document import Document
from app.models.project import Project
from app.services import document_service as docsvc_mod
from app.services.document_service import DocumentService
from tests._live_db import make_live_db

# ===========================================================================
# Helpers / fixtures
# ===========================================================================


def _make_upload_file(filename: str, body: bytes, content_type: str) -> UploadFile:
    """Build a Starlette/FastAPI UploadFile from a bytes body."""
    headers = Headers({"content-type": content_type})
    return UploadFile(
        filename=filename,
        file=io.BytesIO(body),
        headers=headers,
    )


@pytest.fixture
def isolated_storage(tmp_path: Path, monkeypatch):
    """Point the ``get_settings().storage_root`` at a per-test tmp dir.

    document_service builds storage paths from settings.storage_root —
    we monkeypatch the cached settings object the service module sees
    so the on-disk artefacts land under the test's tmp_path.
    """
    fake_settings = MagicMock()
    fake_settings.storage_root = str(tmp_path)
    monkeypatch.setattr(docsvc_mod, "get_settings", lambda: fake_settings)
    return tmp_path


# ===========================================================================
# upload — file upload + size + count caps
# ===========================================================================


class TestUpload:
    @pytest.mark.asyncio
    async def test_persists_document_and_writes_file(
        self, isolated_storage: Path,
    ):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="doc-up", status="ready")
            db.add(project)
            await db.flush()

            body = b"hello world"
            upload = _make_upload_file("notes.txt", body, "text/plain")
            service = DocumentService(db)
            doc = await service.upload(pid, upload, description="Test")

            await db.commit()

            # DB row persisted: re-SELECT to confirm.
            row = (await db.execute(
                select(Document).where(Document.id == doc.id)
            )).scalar_one()
            assert row.project_id == pid
            assert row.original_filename == "notes.txt"
            assert row.content_type == "text/plain"
            assert row.file_size == len(body)
            assert row.sha256 == hashlib.sha256(body).hexdigest()
            assert row.description == "Test"
            assert os.path.exists(row.storage_path)  # noqa: ASYNC240 — test assertion: verify document service persisted to disk; sync stat acceptable
            with open(row.storage_path, "rb") as fh:  # noqa: ASYNC230 — test assertion: read-back content to verify document service write; sync open acceptable
                assert fh.read() == body

    @pytest.mark.asyncio
    async def test_exceeds_size_limit_raises(self, isolated_storage: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="size-cap", status="ready")
            db.add(project)
            await db.flush()

            # 11 MB exceeds the 10 MB cap.
            body = b"x" * (11 * 1024 * 1024)
            upload = _make_upload_file("big.bin", body, "application/octet-stream")
            service = DocumentService(db)
            with pytest.raises(ValueError, match="exceeds maximum size"):
                await service.upload(pid, upload)

    @pytest.mark.asyncio
    async def test_exceeds_count_limit_raises(self, isolated_storage: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="count-cap", status="ready")
            db.add(project)
            await db.flush()

            # Pre-fill to MAX. Use create_note to skip the actual upload path.
            service = DocumentService(db)
            for i in range(20):
                await service.create_note(pid, f"note{i}", "x")
            await db.commit()

            upload = _make_upload_file("over.txt", b"y", "text/plain")
            with pytest.raises(ValueError, match="Maximum of 20 documents"):
                await service.upload(pid, upload)

    @pytest.mark.asyncio
    async def test_default_filename_when_missing(self, isolated_storage: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="defname", status="ready")
            db.add(project)
            await db.flush()

            upload = UploadFile(
                filename=None,
                file=io.BytesIO(b"data"),
                headers=Headers({}),
            )
            service = DocumentService(db)
            doc = await service.upload(pid, upload)
            assert doc.original_filename == "document"
            assert doc.content_type == "application/octet-stream"


# ===========================================================================
# list_by_project / get / update_description / delete
# ===========================================================================


class TestListGetUpdateDelete:
    @pytest.mark.asyncio
    async def test_list_orders_by_created_desc(self, isolated_storage: Path):
        from datetime import datetime, timedelta
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="list", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            d1 = await service.create_note(pid, "first", "")
            d2 = await service.create_note(pid, "second", "")
            d3 = await service.create_note(pid, "third", "")
            # SQLite's func.now() has 1-second resolution and may collide
            # across rapid inserts; explicitly stamp distinct timestamps so
            # the DESC-order assertion below is deterministic regardless
            # of dialect resolution.
            now = datetime.now(UTC)
            d1.created_at = now - timedelta(seconds=2)
            d2.created_at = now - timedelta(seconds=1)
            d3.created_at = now
            await db.commit()

            ordered = await service.list_by_project(pid)
            assert {d.id for d in ordered} == {d1.id, d2.id, d3.id}
            # created_at desc: most recent first. d3 stamped at `now`.
            assert ordered[0].original_filename == "third.md"
            assert ordered[-1].original_filename == "first.md"

    @pytest.mark.asyncio
    async def test_list_respects_limit_and_offset(self, isolated_storage: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="paged", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            for i in range(5):
                await service.create_note(pid, f"note{i}", "")
            await db.commit()

            page1 = await service.list_by_project(pid, limit=2, offset=0)
            page2 = await service.list_by_project(pid, limit=2, offset=2)
            assert len(page1) == 2
            assert len(page2) == 2
            assert {d.id for d in page1}.isdisjoint({d.id for d in page2})

    @pytest.mark.asyncio
    async def test_get_returns_row_or_none(self, isolated_storage: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="get", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            doc = await service.create_note(pid, "x", "")
            await db.commit()

            assert (await service.get(doc.id)).id == doc.id
            assert await service.get(uuid.uuid4()) is None

    @pytest.mark.asyncio
    async def test_update_description_persists(self, isolated_storage: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="upd", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            doc = await service.create_note(pid, "x", "")
            await db.commit()

            updated = await service.update_description(doc.id, "now annotated")
            await db.commit()
            assert updated.description == "now annotated"

            row = (await db.execute(
                select(Document).where(Document.id == doc.id)
            )).scalar_one()
            assert row.description == "now annotated"

    @pytest.mark.asyncio
    async def test_update_description_missing_returns_none(
        self, isolated_storage: Path,
    ):
        async with make_live_db() as db:
            service = DocumentService(db)
            assert await service.update_description(uuid.uuid4(), "x") is None

    @pytest.mark.asyncio
    async def test_delete_removes_row_and_file(self, isolated_storage: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="del", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            doc = await service.create_note(pid, "doomed", "content")
            await db.commit()
            storage_path = doc.storage_path
            assert os.path.exists(storage_path)  # noqa: ASYNC240 — test assertion: verify document service persisted to disk; sync stat acceptable

            ok = await service.delete(doc.id)
            await db.commit()
            assert ok is True
            assert not os.path.exists(storage_path), (  # noqa: ASYNC240 — test assertion: verify document service persisted to disk; sync stat acceptable
                "delete must remove the on-disk file atomically with the row"
            )
            # Row gone too.
            row = (await db.execute(
                select(Document).where(Document.id == doc.id)
            )).scalar_one_or_none()
            assert row is None

    @pytest.mark.asyncio
    async def test_delete_missing_returns_false(self, isolated_storage: Path):
        async with make_live_db() as db:
            service = DocumentService(db)
            assert await service.delete(uuid.uuid4()) is False

    @pytest.mark.asyncio
    async def test_delete_tolerates_missing_file_on_disk(
        self, isolated_storage: Path,
    ):
        """If the on-disk file was already removed (e.g. manual cleanup),
        delete must still drop the DB row rather than raising."""
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="orphan", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            doc = await service.create_note(pid, "lonely", "")
            await db.commit()
            os.remove(doc.storage_path)
            ok = await service.delete(doc.id)
            assert ok is True


# ===========================================================================
# create_note — title sanitization + persistence
# ===========================================================================


class TestCreateNote:
    @pytest.mark.asyncio
    async def test_persists_note_with_markdown_content_type(
        self, isolated_storage: Path,
    ):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="note", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            doc = await service.create_note(pid, "My Notes", "# Hello\nworld")
            await db.commit()

            assert doc.original_filename == "My Notes.md"
            assert doc.content_type == "text/markdown"
            assert doc.file_size == len(b"# Hello\nworld")
            assert doc.sha256 == hashlib.sha256(b"# Hello\nworld").hexdigest()
            with open(doc.storage_path) as fh:  # noqa: ASYNC230 — test assertion: read-back content to verify document service write; sync open acceptable
                assert fh.read() == "# Hello\nworld"

    @pytest.mark.asyncio
    async def test_title_with_slashes_sanitized(self, isolated_storage: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="san", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            doc = await service.create_note(pid, "../etc/passwd", "x")
            await db.commit()
            # Slashes replaced with underscores.
            assert "/" not in doc.original_filename
            assert "\\" not in doc.original_filename
            # Storage path lives strictly under the project's documents dir.
            doc_dir = os.path.join(
                str(isolated_storage), "projects", str(pid), "documents",
            )
            assert os.path.commonpath([doc.storage_path, doc_dir]) == doc_dir

    @pytest.mark.asyncio
    async def test_empty_title_becomes_untitled(self, isolated_storage: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="untitled", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            doc = await service.create_note(pid, "   ", "")
            assert doc.original_filename == "Untitled.md"

    @pytest.mark.asyncio
    async def test_count_cap_enforced(self, isolated_storage: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="cap", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            for i in range(20):
                await service.create_note(pid, f"n{i}", "")
            with pytest.raises(ValueError, match="Maximum of 20 documents"):
                await service.create_note(pid, "over", "")


# ===========================================================================
# create_document — allowlist + update-in-place semantics
# ===========================================================================


class TestCreateDocument:
    @pytest.mark.asyncio
    async def test_creates_new_document_with_allowed_extension(
        self, isolated_storage: Path,
    ):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="cd", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            doc = await service.create_document(
                pid, "config.yaml", "key: value", description="a yaml",
            )
            await db.commit()

            assert doc.original_filename == "config.yaml"
            # yaml mimetype varies across stdlib versions
            # (text/yaml / application/yaml / application/x-yaml / text/plain).
            assert doc.content_type in {
                "text/yaml", "application/yaml",
                "application/x-yaml", "text/plain",
            }
            assert doc.description == "a yaml"
            with open(doc.storage_path) as fh:  # noqa: ASYNC230 — test assertion: read-back content to verify document service write; sync open acceptable
                assert fh.read() == "key: value"

    @pytest.mark.asyncio
    async def test_disallowed_extension_raises(self, isolated_storage: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="bad", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            with pytest.raises(ValueError, match="not allowed"):
                await service.create_document(pid, "evil.exe", "x86 bytes")

    @pytest.mark.asyncio
    async def test_existing_filename_updates_in_place(
        self, isolated_storage: Path,
    ):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="reuse", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            first = await service.create_document(pid, "doc.md", "v1")
            await db.commit()
            first_id = first.id
            first_path = first.storage_path

            second = await service.create_document(pid, "doc.md", "v2 longer")
            await db.commit()

            # Same DB row reused — id unchanged.
            assert second.id == first_id
            # Storage path unchanged.
            assert second.storage_path == first_path
            # Content updated.
            with open(second.storage_path) as fh:  # noqa: ASYNC230 — test assertion: read-back content to verify document service write; sync open acceptable
                assert fh.read() == "v2 longer"
            assert second.sha256 == hashlib.sha256(b"v2 longer").hexdigest()
            assert second.file_size == len(b"v2 longer")

    @pytest.mark.asyncio
    async def test_update_in_place_does_not_consume_count_cap(
        self, isolated_storage: Path,
    ):
        """Update-in-place must NOT enforce the count cap — only NEW
        creates do. A regression that flipped the order of the
        existing-row check vs the count check would silently break
        repeat saves of CLAUDE.md / SCRATCHPAD.md once the project hit
        20 docs."""
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="atcap", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            # Fill to MAX with notes (different filenames).
            for i in range(20):
                await service.create_note(pid, f"n{i}", "x")
            # Now overwrite the first one — must succeed.
            await service.create_document(pid, "n0.md", "updated content")

    @pytest.mark.asyncio
    async def test_new_create_at_count_cap_raises(self, isolated_storage: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="cap2", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            for i in range(20):
                await service.create_note(pid, f"n{i}", "")
            with pytest.raises(ValueError, match="Maximum of 20 documents"):
                await service.create_document(pid, "new.md", "content")


# ===========================================================================
# update_content — re-hash + re-write
# ===========================================================================


class TestUpdateContent:
    @pytest.mark.asyncio
    async def test_rewrites_file_and_updates_hash(self, isolated_storage: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="upd", status="ready")
            db.add(project)
            await db.flush()

            service = DocumentService(db)
            doc = await service.create_note(pid, "draft", "v1")
            await db.commit()
            old_sha = doc.sha256

            new = await service.update_content(doc.id, "v2 longer text")
            await db.commit()
            assert new.sha256 != old_sha
            assert new.file_size == len(b"v2 longer text")
            with open(new.storage_path) as fh:  # noqa: ASYNC230 — test assertion: read-back content to verify document service write; sync open acceptable
                assert fh.read() == "v2 longer text"

    @pytest.mark.asyncio
    async def test_missing_id_returns_none(self, isolated_storage: Path):
        async with make_live_db() as db:
            service = DocumentService(db)
            assert await service.update_content(uuid.uuid4(), "x") is None


# ===========================================================================
# read_text_content — text + PDF paths
# ===========================================================================


class TestReadTextContent:
    def test_text_file_returned_directly(self, tmp_path: Path):
        path = tmp_path / "doc.md"
        path.write_text("# Hello\nworld")

        doc = MagicMock()
        doc.storage_path = str(path)
        doc.original_filename = "doc.md"

        result = DocumentService.read_text_content(doc)
        assert result == "# Hello\nworld"

    def test_missing_file_returns_sentinel(self, tmp_path: Path):
        doc = MagicMock()
        doc.storage_path = str(tmp_path / "nope.txt")
        doc.original_filename = "nope.txt"

        result = DocumentService.read_text_content(doc)
        assert "[Error: file not found on disk]" in result

    def test_pdf_extracts_text_via_pypdf_source_patch(self, tmp_path: Path):
        """Rule #30: pypdf.PdfReader is lazy-imported inside
        read_text_content. Patch via sys.modules — the consumer module
        never bound `pypdf` at module scope."""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\nfake bytes")

        # Build a fake pypdf module.
        fake_pypdf = MagicMock()

        class _FakePage:
            def __init__(self, text: str):
                self._text = text

            def extract_text(self) -> str:
                return self._text

        class _FakeReader:
            def __init__(self, path: str):
                # Verify pypdf was passed the on-disk path.
                assert path == str(pdf_path)
                self.pages = [_FakePage("Page 1 content"), _FakePage("Page 2 content")]

        fake_pypdf.PdfReader = _FakeReader

        doc = MagicMock()
        doc.storage_path = str(pdf_path)
        doc.original_filename = "test.pdf"

        with patch.dict(sys.modules, {"pypdf": fake_pypdf}):
            result = DocumentService.read_text_content(doc)

        assert "Page 1 content" in result
        assert "Page 2 content" in result
        # Pages joined with double-newline.
        assert "Page 1 content\n\nPage 2 content" == result

    def test_pdf_no_extractable_text_returns_sentinel(self, tmp_path: Path):
        pdf_path = tmp_path / "blank.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\n")

        fake_pypdf = MagicMock()

        class _BlankPage:
            def extract_text(self) -> str:
                return ""

        class _BlankReader:
            def __init__(self, path: str):
                self.pages = [_BlankPage(), _BlankPage()]

        fake_pypdf.PdfReader = _BlankReader

        doc = MagicMock()
        doc.storage_path = str(pdf_path)
        doc.original_filename = "blank.pdf"

        with patch.dict(sys.modules, {"pypdf": fake_pypdf}):
            result = DocumentService.read_text_content(doc)
        assert "[No extractable text in PDF]" in result

    def test_pdf_pypdf_exception_returns_sentinel(self, tmp_path: Path):
        pdf_path = tmp_path / "broken.pdf"
        pdf_path.write_bytes(b"not a real pdf")

        fake_pypdf = MagicMock()

        class _RaisingReader:
            def __init__(self, path: str):
                raise ValueError("malformed PDF")

        fake_pypdf.PdfReader = _RaisingReader

        doc = MagicMock()
        doc.storage_path = str(pdf_path)
        doc.original_filename = "broken.pdf"

        with patch.dict(sys.modules, {"pypdf": fake_pypdf}):
            result = DocumentService.read_text_content(doc)
        assert "[Error extracting PDF text:" in result
        assert "malformed PDF" in result

    def test_uppercase_pdf_extension_also_routes_to_pypdf(self, tmp_path: Path):
        """``.PDF`` (uppercase) must also dispatch to pypdf — the lower()
        normalization on the filename is the only branch."""
        pdf_path = tmp_path / "CAPS.PDF"
        pdf_path.write_bytes(b"%PDF-1.4\n")

        fake_pypdf = MagicMock()

        class _FakeReader:
            def __init__(self, path: str):
                self.pages = [MagicMock(extract_text=lambda: "uppercase ext")]

        fake_pypdf.PdfReader = _FakeReader

        doc = MagicMock()
        doc.storage_path = str(pdf_path)
        doc.original_filename = "CAPS.PDF"

        with patch.dict(sys.modules, {"pypdf": fake_pypdf}):
            result = DocumentService.read_text_content(doc)
        assert "uppercase ext" in result


# ===========================================================================
# Rule #30 SOURCE-patch class — explicit discipline canary
# ===========================================================================


class TestRule30PypdfSourcePatch:
    """Rule #30 source-patch discipline: ``pypdf`` is lazy-imported
    INSIDE ``read_text_content`` at line 300. Patches MUST hit the
    SOURCE module via ``sys.modules`` injection.

    Mock targets that would be a SILENT NO-OP:
    * ``patch("app.services.document_service.pypdf.PdfReader", ...)`` —
      AttributeError because the consumer never bound the name.
    * ``patch.object(docsvc_mod, "pypdf", ...)`` — same.

    The CORRECT discipline (this class):
    * ``patch.dict(sys.modules, {"pypdf": fake_module})`` so the
      ``from pypdf import PdfReader`` inside the function body
      resolves to the fake.
    """

    def test_consumer_module_has_no_pypdf_attribute(self):
        """Sanity: confirms ``docsvc_mod.pypdf`` does NOT exist as a
        module-scope attribute. A future refactor that promotes the
        import to top-level (so the cold-import cost lands at app
        boot) would break the sys.modules-injection patches; this
        sentinel fails LOUDLY in that case so tests are migrated to
        the inverse-Rule-30 consumer-patch shape."""
        assert not hasattr(docsvc_mod, "pypdf"), (
            "If pypdf is now top-level, switch tests to "
            "patch.object(docsvc_mod, 'pypdf', ...) per Rule #30 "
            "inverse case."
        )
        assert not hasattr(docsvc_mod, "PdfReader"), (
            "PdfReader name leaked to module scope — same migration "
            "required."
        )


# ===========================================================================
# Rule #35b LIVE-CANARY — full upload + PDF round-trip
# ===========================================================================


class TestUploadLiveCanary:
    """Rule #35b live canary: a real UploadFile fixture round-trips
    through the actual ORM, the on-disk write, and a SELECT against
    the persisted Document row. Mock-only tests cannot fail on:

    * a regression where ``self.db.add(document)`` is replaced with
      ``await self.db.add(...)`` (a coroutine that's never awaited and
      silently never persists);
    * a regression where one of the explicit Document constructor kwargs
      drifts from the model field (e.g. ``filename=`` instead of
      ``original_filename=``) — pydantic schemas would still coerce
      the response, but the persisted row would have NULL for the
      expected column;
    * a regression where the storage_path isn't actually written to
      (e.g. a refactor that builds the path but skips the
      ``with open(...) as f: f.write(...)`` sequence).
    """

    @pytest.mark.asyncio
    async def test_upload_persists_every_field_to_db_and_disk(
        self, isolated_storage: Path,
    ):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="canary", status="ready")
            db.add(project)
            await db.flush()

            body = b"# canary content\nline 2\nline 3\n"
            upload = _make_upload_file(
                "report.md", body, "text/markdown",
            )
            service = DocumentService(db)
            doc = await service.upload(
                pid, upload, description="live canary upload",
            )
            await db.commit()

            # SELECT the persisted row — every constructor kwarg lands.
            row = (await db.execute(
                select(Document).where(Document.id == doc.id)
            )).scalar_one()
            assert row.project_id == pid
            assert row.original_filename == "report.md"
            assert row.content_type == "text/markdown"
            assert row.file_size == len(body)
            assert row.sha256 == hashlib.sha256(body).hexdigest()
            assert row.description == "live canary upload"
            assert row.created_at is not None

            # On-disk file actually contains the uploaded bytes.
            assert os.path.exists(row.storage_path)  # noqa: ASYNC240 — test assertion: verify document service persisted to disk; sync stat acceptable
            with open(row.storage_path, "rb") as fh:  # noqa: ASYNC230 — test assertion: read-back content to verify document service write; sync open acceptable
                assert fh.read() == body

            # Storage path is contained under the project documents dir
            # (no traversal escape).
            project_docs = os.path.join(
                str(isolated_storage), "projects", str(pid), "documents",
            )
            assert os.path.commonpath([row.storage_path, project_docs]) == project_docs

    @pytest.mark.asyncio
    async def test_pdf_extraction_round_trips_via_real_db_row(
        self, isolated_storage: Path,
    ):
        """Combine the live-DB canary with the pypdf SOURCE-patch:
        upload a fake PDF blob, persist the Document row, then call
        ``read_text_content`` against the persisted row. The mocked
        PdfReader returns a controlled string; the test verifies
        the value flows from disk → pypdf → return value."""
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="pdf-canary", status="ready")
            db.add(project)
            await db.flush()

            pdf_body = b"%PDF-1.4\n%fake pdf content\n"
            upload = _make_upload_file(
                "report.pdf", pdf_body, "application/pdf",
            )
            service = DocumentService(db)
            doc = await service.upload(pid, upload)
            await db.commit()

            # Re-fetch the persisted row (proving disk + DB are in sync).
            row = (await db.execute(
                select(Document).where(Document.id == doc.id)
            )).scalar_one()
            assert row.original_filename == "report.pdf"
            assert row.content_type == "application/pdf"

            # Mock pypdf.PdfReader.
            captured_path: list[str] = []
            fake_pypdf = MagicMock()

            class _ExtractedReader:
                def __init__(self, path: str):
                    captured_path.append(path)
                    self.pages = [
                        MagicMock(extract_text=lambda: "Section 1: Findings"),
                        MagicMock(extract_text=lambda: "Section 2: Recommendations"),
                    ]

            fake_pypdf.PdfReader = _ExtractedReader

            with patch.dict(sys.modules, {"pypdf": fake_pypdf}):
                text = DocumentService.read_text_content(row)

            # PdfReader was passed the on-disk path of the persisted row.
            assert captured_path == [row.storage_path]
            assert "Section 1: Findings" in text
            assert "Section 2: Recommendations" in text
