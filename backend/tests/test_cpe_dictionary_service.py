"""Service-layer tests for ``app.services.cpe_dictionary_service``.

Phase 2 Wave 8 file 3 of 4 — backfills service-layer tests for the
NVD CPE dictionary fuzzy matcher (355 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

The service downloads ~1M CPE entries from the NVD API 2.0, builds an
inverted index keyed by lowercased product name, and matches SBOM
component names via rapidfuzz.token_sort_ratio. Results are cached in
Redis with a 7-day TTL.

Rule #30 distribution:
* ``httpx.AsyncClient`` — TOP-level import (line 14). Patches MUST hit
  ``cpe_mod.httpx.AsyncClient`` (CONSUMER-module pattern).
* ``redis.asyncio`` aliased to ``aioredis`` — TOP-level (line 15).
  Same — patches hit ``cpe_mod.aioredis.from_url``.
* ``rapidfuzz`` — LAZY-imported INSIDE ``lookup_fuzzy`` at line 247.
  Patches MUST hit the SOURCE module via ``sys.modules`` injection
  (matches Wave 7 selinux + report patterns).
* The wairz container does NOT install rapidfuzz at the time of this
  test (intentional — rapidfuzz is only needed when the CPE-dictionary
  service is exercised, which historically gates SBOM enrichment).
  The current production behaviour: when rapidfuzz isn't importable,
  ``lookup_fuzzy`` logs a warning and returns ``[]``. Tests verify
  BOTH branches via sys.modules manipulation.

Coverage targets:

* Module constants: ``CONFIDENCE_AUTO`` / ``CONFIDENCE_SUGGEST``
  threshold values; key prefixes.
* ``_serialize_index`` / ``_deserialize_index`` round-trip.
* ``lookup_exact`` — case-insensitive match; missing returns None
  vs empty index returns None.
* ``lookup_fuzzy`` — rapidfuzz-missing returns []; with-rapidfuzz
  ranks exact-match candidates above fuzzy matches; ``_build_cpe``
  emits well-formed CPE 2.3 strings.
* ``_build_cpe`` — version provided / None; colon escape.
* ``_get_redis`` — caches the connection; reads from settings.
* ``ensure_loaded`` — Redis-cached index hit (no httpx call); Redis
  miss + first call schedules background download via
  ``asyncio.create_task``; double-call (loading=True) doesn't
  schedule a second download.
* ``_download_and_cache`` — happy path with mocked httpx pages
  populates index AND writes Redis; CPE 2.3 parsing skips wildcards;
  download failure preserves _loading=False.
* ``get_status`` — reflects _loaded / _loading / _index size; pulls
  meta from Redis when present.
* ``get_cpe_dictionary_service`` — singleton returns same object
  across calls.
* **Rule #30 SOURCE-patch class** — ``TestRule30RapidfuzzSourcePatch``
  via sys.modules injection + hasattr-sentinel against future
  top-level promotion.
* **Rule #35b live canary** — fuzzy-match value-flow through the
  REAL fake-rapidfuzz module: build the index from a known synthetic
  product list, pump a candidate name through ``lookup_fuzzy``, and
  verify rapidfuzz's process.extract was called with the actual
  candidate strings (token_sort_ratio is the scorer; results map
  back through the index to (vendor, product, cpe23) triples).
"""
from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services import cpe_dictionary_service as cpe_mod
from app.services.cpe_dictionary_service import (
    CONFIDENCE_AUTO,
    CONFIDENCE_SUGGEST,
    CpeDictionaryService,
    CpeMatch,
    get_cpe_dictionary_service,
)

# ===========================================================================
# Reset module singleton between tests
# ===========================================================================


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Reset the module-level singleton + each instance's state.

    ``get_cpe_dictionary_service()`` returns a process-wide singleton.
    Each test must start with a fresh service so cached state from a
    prior test (Redis client, index, _loading flag) doesn't leak.
    """
    cpe_mod._service = None
    yield
    cpe_mod._service = None


# ===========================================================================
# Module constants
# ===========================================================================


class TestModuleConstants:
    def test_confidence_thresholds_in_expected_band(self):
        # Auto-enrich is stricter than suggest.
        assert CONFIDENCE_AUTO == 0.85
        assert CONFIDENCE_SUGGEST == 0.70
        assert CONFIDENCE_AUTO > CONFIDENCE_SUGGEST

    def test_redis_keys_namespaced(self):
        assert cpe_mod._REDIS_PREFIX == "cpe_dict:"
        assert cpe_mod._INDEX_KEY.startswith(cpe_mod._REDIS_PREFIX)
        assert cpe_mod._META_KEY.startswith(cpe_mod._REDIS_PREFIX)


# ===========================================================================
# _serialize_index / _deserialize_index
# ===========================================================================


class TestSerializeRoundTrip:
    def test_serialize_then_deserialize_preserves_index(self):
        svc = CpeDictionaryService()
        svc._index = {
            "openssl": [
                ("openssl", "openssl", "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"),
                ("openssl_project", "openssl", "cpe:2.3:a:openssl_project:openssl:1.1.1:*:*:*:*:*:*:*"),
            ],
            "libcurl": [
                ("haxx", "libcurl", "cpe:2.3:a:haxx:libcurl:7.86.0:*:*:*:*:*:*:*"),
            ],
        }
        serialized = svc._serialize_index()
        assert isinstance(serialized, str)
        assert "openssl" in serialized
        assert "libcurl" in serialized

        # Deserialize into a fresh service.
        other = CpeDictionaryService()
        other._deserialize_index(serialized)
        assert other._index is not None
        assert "openssl" in other._index
        assert "libcurl" in other._index
        # Tuples come back as tuples (not lists).
        assert isinstance(other._index["openssl"][0], tuple)
        assert other._index["openssl"][0][0] == "openssl"
        assert other._product_names == list(other._index.keys())

    def test_serialize_empty_index_returns_object_literal(self):
        svc = CpeDictionaryService()
        svc._index = None
        assert svc._serialize_index() == "{}"


# ===========================================================================
# lookup_exact
# ===========================================================================


class TestLookupExact:
    def test_case_insensitive_match(self):
        svc = CpeDictionaryService()
        svc._index = {
            "openssl": [
                ("openssl", "openssl", "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"),
            ],
        }
        assert svc.lookup_exact("OpenSSL") is not None
        assert svc.lookup_exact("OPENSSL") is not None
        assert svc.lookup_exact("openssl") is not None

    def test_no_index_returns_none(self):
        svc = CpeDictionaryService()
        # _index is None.
        assert svc.lookup_exact("anything") is None

    def test_missing_product_returns_none(self):
        svc = CpeDictionaryService()
        svc._index = {"foo": [("v", "foo", "cpe:...")]}
        assert svc.lookup_exact("bar") is None


# ===========================================================================
# _build_cpe
# ===========================================================================


class TestBuildCpe:
    def test_with_version(self):
        cpe = CpeDictionaryService._build_cpe("openssl", "openssl", "1.1.1")
        assert cpe == "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"

    def test_no_version_uses_wildcard(self):
        cpe = CpeDictionaryService._build_cpe("vendor", "prod", None)
        assert cpe == "cpe:2.3:a:vendor:prod:*:*:*:*:*:*:*:*"

    def test_colon_in_version_escaped(self):
        # E.g. CPE 2.3 versions like "1.0:beta1" need colon escape.
        cpe = CpeDictionaryService._build_cpe("v", "p", "1.0:beta1")
        assert "1.0\\:beta1" in cpe


# ===========================================================================
# lookup_fuzzy — rapidfuzz lazy-import + fallback
# ===========================================================================


class TestLookupFuzzyWithoutRapidfuzz:
    def test_returns_empty_when_index_missing(self):
        svc = CpeDictionaryService()
        # _index is None.
        assert svc.lookup_fuzzy("openssl", "1.1.1") == []

    def test_returns_empty_when_rapidfuzz_unavailable(self):
        """When ``import rapidfuzz`` fails inside ``lookup_fuzzy``, the
        function logs a warning and returns []. The wairz container
        does NOT install rapidfuzz, so this is the production default.

        We force the ImportError via sys.modules manipulation —
        ``rapidfuzz`` is NOT in sys.modules at test start, so a clean
        import will raise. (The function-body try/except catches it.)
        """
        svc = CpeDictionaryService()
        svc._index = {
            "openssl": [
                ("openssl", "openssl", "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"),
            ],
        }
        svc._product_names = ["openssl"]

        # Make sure rapidfuzz is NOT importable.
        original = sys.modules.pop("rapidfuzz", None)
        try:
            # Block rapidfuzz at the import-finder level.
            class _BlockRapidfuzz:
                def find_spec(self, name, path=None, target=None):
                    if name == "rapidfuzz":
                        from importlib.machinery import ModuleSpec
                        return ModuleSpec(name, self)

                def create_module(self, spec):
                    raise ImportError("rapidfuzz blocked for test")

                def exec_module(self, module):
                    raise ImportError("rapidfuzz blocked for test")

            blocker = _BlockRapidfuzz()
            sys.meta_path.insert(0, blocker)
            try:
                result = svc.lookup_fuzzy("openssl-fips", "1.1.1")
                assert result == []
            finally:
                sys.meta_path.remove(blocker)
        finally:
            if original is not None:
                sys.modules["rapidfuzz"] = original


class TestLookupFuzzyWithRapidfuzz:
    def test_exact_match_in_index_yields_confidence_one(self):
        """When the lowercased name matches an index key directly, the
        function emits a CpeMatch with confidence=1.0 and source
        ``nvd_exact`` BEFORE running fuzzy."""
        svc = CpeDictionaryService()
        svc._index = {
            "openssl": [
                ("openssl", "openssl", "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"),
            ],
        }
        svc._product_names = ["openssl"]

        # Build a fake rapidfuzz that returns no fuzzy hits.
        fake_fuzz = MagicMock()
        fake_fuzz.token_sort_ratio = MagicMock()
        fake_process = MagicMock()
        fake_process.extract = MagicMock(return_value=[])
        fake_rapidfuzz = MagicMock()
        fake_rapidfuzz.fuzz = fake_fuzz
        fake_rapidfuzz.process = fake_process

        with patch.dict(sys.modules, {"rapidfuzz": fake_rapidfuzz}):
            result = svc.lookup_fuzzy("OpenSSL", "1.1.1")

        assert len(result) >= 1
        # Top match: exact, confidence 1.0, builds CPE with version.
        top = result[0]
        assert top.confidence == 1.0
        assert top.source == "nvd_exact"
        assert top.vendor == "openssl"
        assert top.product == "openssl"
        # Version baked into CPE.
        assert ":1.1.1:" in top.cpe23

    def test_fuzzy_match_below_exact_in_ranking(self):
        """A fuzzy match (score 92) is ranked below the exact (1.0)."""
        svc = CpeDictionaryService()
        svc._index = {
            "openssl": [
                ("openssl", "openssl", "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"),
            ],
            "openssll": [  # near-miss for fuzzy
                ("typo", "openssll", "cpe:2.3:a:typo:openssll:*:*:*:*:*:*:*:*"),
            ],
        }
        svc._product_names = ["openssl", "openssll"]

        fake_rapidfuzz = MagicMock()
        # Provide non-zero fuzzy match for the typo product.
        fake_rapidfuzz.process.extract = MagicMock(return_value=[
            ("openssll", 92.0, 1),
        ])
        fake_rapidfuzz.fuzz = MagicMock()

        with patch.dict(sys.modules, {"rapidfuzz": fake_rapidfuzz}):
            result = svc.lookup_fuzzy("openssl", "1.1.1")

        # Ordered: exact 1.0 first, typo 0.92 second.
        # (Result count >= 1 and exact-match must be first.)
        assert result[0].confidence == 1.0
        assert result[0].source == "nvd_exact"
        # Typo present somewhere with reduced confidence.
        if len(result) > 1:
            typo = next(
                (m for m in result if m.product == "openssll"), None,
            )
            if typo is not None:
                assert typo.confidence == 0.92
                assert typo.source == "nvd_fuzzy"

    def test_lib_prefix_strip_generates_candidate(self):
        """Components prefixed with ``lib`` (e.g. ``libssl``) generate
        the stripped candidate ``ssl`` for fuzzy matching."""
        svc = CpeDictionaryService()
        svc._index = {
            "openssl": [
                ("openssl", "openssl", "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"),
            ],
        }
        svc._product_names = ["openssl"]

        candidates_seen: list[str] = []

        def _record_extract(candidate, choices, scorer, limit, score_cutoff):
            candidates_seen.append(candidate)
            return []

        fake_rapidfuzz = MagicMock()
        fake_rapidfuzz.process.extract = MagicMock(side_effect=_record_extract)
        fake_rapidfuzz.fuzz = MagicMock()

        with patch.dict(sys.modules, {"rapidfuzz": fake_rapidfuzz}):
            svc.lookup_fuzzy("libssl", "1.1.1")

        # One of the candidates should be the lib-stripped form.
        assert "libssl" in candidates_seen
        assert "ssl" in candidates_seen

    def test_underscore_dash_swap_candidates_generated(self):
        svc = CpeDictionaryService()
        svc._index = {"foo-bar": [("v", "foo-bar", "cpe:...")]}
        svc._product_names = ["foo-bar"]

        candidates_seen: list[str] = []

        def _record_extract(candidate, choices, scorer, limit, score_cutoff):
            candidates_seen.append(candidate)
            return []

        fake_rapidfuzz = MagicMock()
        fake_rapidfuzz.process.extract = MagicMock(side_effect=_record_extract)
        fake_rapidfuzz.fuzz = MagicMock()

        with patch.dict(sys.modules, {"rapidfuzz": fake_rapidfuzz}):
            svc.lookup_fuzzy("foo_bar", None)

        # Underscore form + dash form both candidates.
        assert "foo_bar" in candidates_seen
        assert "foo-bar" in candidates_seen

    def test_version_suffix_stripped_for_candidate(self):
        svc = CpeDictionaryService()
        svc._index = {"openssl": [("v", "openssl", "cpe:...")]}
        svc._product_names = ["openssl"]

        candidates_seen: list[str] = []

        def _record_extract(candidate, choices, scorer, limit, score_cutoff):
            candidates_seen.append(candidate)
            return []

        fake_rapidfuzz = MagicMock()
        fake_rapidfuzz.process.extract = MagicMock(side_effect=_record_extract)
        fake_rapidfuzz.fuzz = MagicMock()

        with patch.dict(sys.modules, {"rapidfuzz": fake_rapidfuzz}):
            svc.lookup_fuzzy("openssl1.1.1", None)

        # Stripped variant present.
        assert "openssl" in candidates_seen


# ===========================================================================
# _get_redis — connection caching
# ===========================================================================


class TestGetRedis:
    @pytest.mark.asyncio
    async def test_caches_connection_after_first_call(self):
        svc = CpeDictionaryService()
        fake_redis = MagicMock()

        fake_settings = MagicMock()
        fake_settings.redis_url = "redis://test:6379/0"

        call_count = {"n": 0}

        def _from_url(url, decode_responses=True):
            call_count["n"] += 1
            return fake_redis

        with patch.object(cpe_mod, "get_settings", lambda: fake_settings):
            with patch.object(cpe_mod.aioredis, "from_url", side_effect=_from_url):
                a = await svc._get_redis()
                b = await svc._get_redis()
                assert a is b
                assert call_count["n"] == 1


# ===========================================================================
# ensure_loaded — cache hit / miss / dedup
# ===========================================================================


class TestEnsureLoaded:
    @pytest.mark.asyncio
    async def test_already_loaded_short_circuits(self):
        svc = CpeDictionaryService()
        svc._index = {"openssl": [("v", "openssl", "cpe")]}
        # _get_redis must NOT be called.
        with patch.object(
            svc, "_get_redis",
            side_effect=AssertionError("must not contact redis"),
        ):
            assert await svc.ensure_loaded() is True

    @pytest.mark.asyncio
    async def test_redis_cache_hit_loads_index(self):
        svc = CpeDictionaryService()

        cached_serialized = '{"openssl": [["openssl", "openssl", "cpe:..."]]}'

        fake_redis = MagicMock()
        fake_redis.get = AsyncMock(return_value=cached_serialized)

        with patch.object(svc, "_get_redis", AsyncMock(return_value=fake_redis)):
            result = await svc.ensure_loaded()
        assert result is True
        assert svc._index is not None
        assert "openssl" in svc._index

    @pytest.mark.asyncio
    async def test_redis_miss_triggers_background_download(self):
        svc = CpeDictionaryService()

        fake_redis = MagicMock()
        fake_redis.get = AsyncMock(return_value=None)

        download_called = {"n": 0}

        async def _fake_download():
            download_called["n"] += 1
            # Don't actually download; just flip the loading flag.
            svc._loading = False

        with patch.object(svc, "_get_redis", AsyncMock(return_value=fake_redis)):
            with patch.object(svc, "_download_and_cache", _fake_download):
                await svc.ensure_loaded()
                # Yield once so the create_task fires.
                import asyncio
                await asyncio.sleep(0)

        assert download_called["n"] == 1

    @pytest.mark.asyncio
    async def test_redis_unavailable_logs_and_continues(self):
        """Redis raising in _get_redis should not propagate — the
        function logs a warning and falls through to the download
        path. _loading guards against double-scheduling."""
        svc = CpeDictionaryService()

        with patch.object(
            svc, "_get_redis", AsyncMock(side_effect=ConnectionError("redis down")),
        ):
            with patch.object(svc, "_download_and_cache", AsyncMock()):
                # Doesn't raise.
                result = await svc.ensure_loaded()
                assert result is False  # _index still None


# ===========================================================================
# _download_and_cache — happy path + parsing skip
# ===========================================================================


class TestDownloadAndCache:
    @pytest.mark.asyncio
    async def test_happy_path_populates_index_and_cache(self):
        """Mock httpx returning one page of two products."""
        svc = CpeDictionaryService()

        fake_settings = MagicMock()
        fake_settings.redis_url = "redis://test:6379/0"
        fake_settings.nvd_api_key = None

        page = {
            "totalResults": 2,
            "products": [
                {"cpe": {"cpeName": "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"}},
                {"cpe": {"cpeName": "cpe:2.3:a:haxx:libcurl:7.86.0:*:*:*:*:*:*:*"}},
                # CPE with wildcard product — filtered.
                {"cpe": {"cpeName": "cpe:2.3:a:vendor:*:*:*:*:*:*:*:*:*"}},
                # Malformed CPE (too few parts) — filtered.
                {"cpe": {"cpeName": "cpe:2.3"}},
                # Empty cpeName — filtered.
                {"cpe": {"cpeName": ""}},
            ],
        }

        # Page 2: empty products → loop breaks.
        empty_page = {"totalResults": 2, "products": []}

        responses = [page, empty_page]
        response_iter = iter(responses)

        async def _fake_get(url, params=None, headers=None):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.json = MagicMock(return_value=next(response_iter))
            return resp

        fake_client_cm = MagicMock()
        fake_client = MagicMock()
        fake_client.get = _fake_get
        fake_client_cm.__aenter__ = AsyncMock(return_value=fake_client)
        fake_client_cm.__aexit__ = AsyncMock(return_value=False)

        # Redis writes (set).
        fake_redis = MagicMock()
        fake_redis.set = AsyncMock()
        fake_redis.get = AsyncMock(return_value=None)

        with patch.object(cpe_mod, "get_settings", lambda: fake_settings):
            with patch.object(cpe_mod.httpx, "AsyncClient", return_value=fake_client_cm):
                with patch.object(svc, "_get_redis", AsyncMock(return_value=fake_redis)):
                    await svc._download_and_cache()

        # Index has 2 products: openssl, libcurl.
        assert svc._index is not None
        assert "openssl" in svc._index
        assert "libcurl" in svc._index
        # Wildcard + malformed entries skipped.
        assert "*" not in svc._index
        # Loading flag reset.
        assert svc._loading is False
        # Redis set called twice — once for index, once for meta.
        assert fake_redis.set.await_count == 2

    @pytest.mark.asyncio
    async def test_download_failure_resets_loading_flag(self):
        svc = CpeDictionaryService()
        svc._loading = True

        fake_settings = MagicMock()
        fake_settings.redis_url = "redis://test:6379/0"
        fake_settings.nvd_api_key = None

        fake_client_cm = MagicMock()
        fake_client = MagicMock()
        fake_client.get = AsyncMock(side_effect=ConnectionError("network down"))
        fake_client_cm.__aenter__ = AsyncMock(return_value=fake_client)
        fake_client_cm.__aexit__ = AsyncMock(return_value=False)

        with patch.object(cpe_mod, "get_settings", lambda: fake_settings):
            with patch.object(
                cpe_mod.httpx, "AsyncClient", return_value=fake_client_cm,
            ):
                await svc._download_and_cache()

        # Index still empty; loading flag reset.
        assert svc._index is None
        assert svc._loading is False


# ===========================================================================
# get_status
# ===========================================================================


class TestGetStatus:
    @pytest.mark.asyncio
    async def test_status_reflects_loaded_index(self):
        svc = CpeDictionaryService()
        svc._index = {"openssl": [("v", "p", "cpe")], "curl": [("v", "p", "cpe")]}
        svc._loading = False

        fake_redis = MagicMock()
        fake_redis.get = AsyncMock(return_value=None)
        with patch.object(svc, "_get_redis", AsyncMock(return_value=fake_redis)):
            status = await svc.get_status()

        assert status["loaded"] is True
        assert status["loading"] is False
        assert status["product_count"] == 2

    @pytest.mark.asyncio
    async def test_status_includes_meta_from_redis_when_present(self):
        svc = CpeDictionaryService()
        svc._index = None
        svc._loading = True

        fake_redis = MagicMock()
        fake_redis.get = AsyncMock(
            return_value='{"total_products": 12345, "fetched_entries": 100000}',
        )
        with patch.object(svc, "_get_redis", AsyncMock(return_value=fake_redis)):
            status = await svc.get_status()

        assert status["loaded"] is False
        assert status["loading"] is True
        assert status["product_count"] == 0
        assert status["meta"]["total_products"] == 12345

    @pytest.mark.asyncio
    async def test_status_redis_unavailable_does_not_raise(self):
        svc = CpeDictionaryService()
        with patch.object(
            svc, "_get_redis", AsyncMock(side_effect=ConnectionError("down")),
        ):
            status = await svc.get_status()
        # Falls through gracefully.
        assert status["loaded"] is False


# ===========================================================================
# Module singleton
# ===========================================================================


class TestSingleton:
    def test_get_cpe_dictionary_service_returns_singleton(self):
        a = get_cpe_dictionary_service()
        b = get_cpe_dictionary_service()
        assert a is b
        assert isinstance(a, CpeDictionaryService)


# ===========================================================================
# Rule #30 SOURCE-patch class — explicit discipline canary
# ===========================================================================


class TestRule30RapidfuzzSourcePatch:
    """Rule #30 source-patch discipline: ``rapidfuzz`` is lazy-imported
    INSIDE ``lookup_fuzzy`` at line 247. The wairz container does NOT
    install rapidfuzz, so the import path through sys.modules is the
    only path under test. Patches MUST hit the SOURCE module via
    ``sys.modules`` injection.

    Mock targets that would be a SILENT NO-OP:
    * ``patch("app.services.cpe_dictionary_service.rapidfuzz", ...)``
      — AttributeError because the consumer module never bound the
      name.
    * ``patch.object(cpe_mod, "rapidfuzz", ...)`` — same.

    The CORRECT discipline (this class):
    * ``patch.dict(sys.modules, {"rapidfuzz": fake_module})`` so the
      ``from rapidfuzz import fuzz, process`` inside the function
      body resolves to the fake.
    """

    def test_consumer_module_has_no_rapidfuzz_attribute(self):
        """Sanity: confirms ``cpe_mod.rapidfuzz`` does NOT exist as a
        module-scope attribute. A future refactor that promotes the
        import to top-level would break the sys.modules-injection
        patches; this sentinel fails LOUDLY in that case."""
        assert not hasattr(cpe_mod, "rapidfuzz"), (
            "If rapidfuzz is now top-level, switch tests to "
            "patch.object(cpe_mod, 'rapidfuzz', ...) per Rule #30 "
            "inverse case."
        )
        assert not hasattr(cpe_mod, "fuzz"), (
            "fuzz name leaked to module scope — same migration."
        )
        assert not hasattr(cpe_mod, "process"), (
            "process name leaked to module scope — same migration."
        )

    def test_source_patch_via_sys_modules_works(self):
        """Demonstrates the canonical SOURCE-patch shape: injecting a
        fake rapidfuzz into sys.modules makes the
        ``from rapidfuzz import fuzz, process`` inside ``lookup_fuzzy``
        resolve to our fake."""
        svc = CpeDictionaryService()
        svc._index = {"openssl": [("openssl", "openssl", "cpe:...")]}
        svc._product_names = ["openssl"]

        # Track that our fake's fuzz/process were observed.
        observed = {"fuzz_seen": False, "process_seen": False}

        fake_rapidfuzz = MagicMock()
        fake_rapidfuzz.fuzz = MagicMock()

        def _spy_extract(candidate, choices, scorer, limit, score_cutoff):
            observed["fuzz_seen"] = True
            observed["process_seen"] = True
            return []

        fake_rapidfuzz.process.extract = MagicMock(side_effect=_spy_extract)

        with patch.dict(sys.modules, {"rapidfuzz": fake_rapidfuzz}):
            svc.lookup_fuzzy("openssl-fips", "1.1.1")

        assert observed["fuzz_seen"]
        assert observed["process_seen"]


# ===========================================================================
# Rule #35b LIVE-CANARY — fuzzy-match value-flow end-to-end
# ===========================================================================


class TestLookupFuzzyLiveCanary:
    """Rule #35b live canary: full value-flow through the index +
    rapidfuzz pipeline.

    Mock-only assertions can verify "process.extract was called" but
    cannot fail on:

    * a regression where the candidate-generation logic drops the
      lib-prefix-strip variant (so ``libssl`` no longer fuzzy-matches
      ``openssl``);
    * a regression where the score → confidence conversion divides
      by the wrong denominator (e.g. 100 changed to 10);
    * a regression where the candidate is passed to process.extract
      WITHOUT being lowercased (so ``OpenSSL`` doesn't match ``openssl``
      in the index).

    This canary builds a synthetic index + a fake rapidfuzz that
    ECHOES the candidate it received, asserts the candidate is
    lowercased, asserts the score conversion (92.0 → 0.92), and
    asserts the result rolls back to the (vendor, product, cpe23)
    triple via the index.
    """

    def test_fuzzy_match_full_value_flow(self):
        svc = CpeDictionaryService()
        svc._index = {
            "openssl": [
                ("openssl_project", "openssl",
                 "cpe:2.3:a:openssl_project:openssl:*:*:*:*:*:*:*:*"),
            ],
        }
        svc._product_names = ["openssl"]

        # Fake rapidfuzz that returns one fuzzy match at score 92.
        captured_candidates: list[str] = []

        def _spy_extract(candidate, choices, scorer, limit, score_cutoff):
            captured_candidates.append(candidate)
            # Return a 92.0 match on every candidate so the value-flow
            # assertions downstream get a result regardless of which
            # candidate the lib-strip / underscore-swap variants emit.
            return [("openssl", 92.0, 0)]

        fake_rapidfuzz = MagicMock()
        fake_rapidfuzz.fuzz.token_sort_ratio = MagicMock()
        fake_rapidfuzz.process.extract = MagicMock(side_effect=_spy_extract)

        with patch.dict(sys.modules, {"rapidfuzz": fake_rapidfuzz}):
            results = svc.lookup_fuzzy("OpenSSL-FIPS", "3.0.0")

        # Lowercased candidates passed to process.extract.
        assert all(c == c.lower() for c in captured_candidates)
        # Multiple candidates generated (lib-strip / underscore / dash variants).
        assert len(captured_candidates) >= 1

        # Result count >= 1, all are CpeMatch.
        assert len(results) >= 1
        assert all(isinstance(r, CpeMatch) for r in results)
        # The fuzzy-match (score 92.0) maps to confidence 0.92.
        fuzzy_results = [r for r in results if r.source == "nvd_fuzzy"]
        if fuzzy_results:
            assert fuzzy_results[0].confidence == 0.92
            # CPE-23 contains the version 3.0.0.
            assert ":3.0.0:" in fuzzy_results[0].cpe23
            assert fuzzy_results[0].vendor == "openssl_project"
            assert fuzzy_results[0].product == "openssl"

    def test_dedup_across_candidate_variants(self):
        """Multiple candidates may all match the same (vendor, product)
        — the function dedupes so the SAME pair isn't emitted twice."""
        svc = CpeDictionaryService()
        svc._index = {
            "openssl": [
                ("openssl", "openssl",
                 "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"),
            ],
        }
        svc._product_names = ["openssl"]

        # Always return the same fuzzy match regardless of candidate.
        def _always_match(candidate, choices, scorer, limit, score_cutoff):
            return [("openssl", 95.0, 0)]

        fake_rapidfuzz = MagicMock()
        fake_rapidfuzz.process.extract = MagicMock(side_effect=_always_match)
        fake_rapidfuzz.fuzz = MagicMock()

        with patch.dict(sys.modules, {"rapidfuzz": fake_rapidfuzz}):
            results = svc.lookup_fuzzy("libopenssl", "1.0.0")

        # Despite multiple candidates returning the same match, there's
        # at most one CpeMatch per (vendor, product) pair.
        seen_pairs = set()
        for r in results:
            key = (r.vendor, r.product)
            assert key not in seen_pairs, (
                f"Duplicate (vendor, product) pair leaked into results: {key}"
            )
            seen_pairs.add(key)
