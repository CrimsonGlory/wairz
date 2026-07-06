"""CPE Dictionary Service — NVD CPE dictionary fuzzy matching via rapidfuzz.

Downloads CPE entries from the NVD CPE API 2.0, builds an inverted index
keyed by product name, and provides fuzzy matching for SBOM enrichment.
Results are cached in Redis with a 7-day TTL.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass

import httpx
import redis.asyncio as aioredis

from app.config import get_settings

logger = logging.getLogger(__name__)

# Redis key prefixes
_REDIS_PREFIX = "cpe_dict:"
_INDEX_KEY = f"{_REDIS_PREFIX}index"
_META_KEY = f"{_REDIS_PREFIX}meta"
_DICT_TTL = 7 * 24 * 3600  # 7 days

# NVD API
_NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
_PAGE_SIZE = 10000  # max allowed by NVD API
_REQUEST_DELAY = 0.6  # seconds between requests (NVD rate limit without key)
_REQUEST_DELAY_WITH_KEY = 0.1  # with API key

# Matching thresholds
CONFIDENCE_AUTO = 0.85  # Auto-enrich at this confidence
CONFIDENCE_SUGGEST = 0.70  # Flag as "suggested" above this


@dataclass
class CpeMatch:
    """A fuzzy match result from the CPE dictionary."""

    cpe23: str
    vendor: str
    product: str
    confidence: float
    source: str = "nvd_dictionary"


class CpeDictionaryService:
    """Manages the NVD CPE dictionary with Redis-backed caching."""

    def __init__(self) -> None:
        self._redis: aioredis.Redis | None = None
        self._index: dict[str, list[tuple[str, str, str]]] | None = None
        self._product_names: list[str] | None = None
        self._loading = False

    async def _get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            settings = get_settings()
            self._redis = aioredis.from_url(
                settings.redis_url, decode_responses=True
            )
        return self._redis

    async def ensure_loaded(self) -> bool:
        """Ensure the CPE index is loaded. Returns True if ready."""
        if self._index is not None:
            return True

        # Try loading from Redis cache first
        try:
            redis = await self._get_redis()
            cached = await redis.get(_INDEX_KEY)
            if cached:
                self._deserialize_index(cached)
                logger.info(
                    "CPE dictionary loaded from Redis cache (%d products)",
                    len(self._index or {}),
                )
                return True
        except Exception:
            logger.warning("Redis unavailable for CPE dictionary cache")

        # Try downloading from NVD (non-blocking, background)
        if not self._loading:
            self._loading = True
            asyncio.create_task(self._download_and_cache())

        return self._index is not None

    async def _download_and_cache(self) -> None:
        """Download CPE dictionary from NVD API and cache in Redis."""
        settings = get_settings()
        delay = (
            _REQUEST_DELAY_WITH_KEY if settings.nvd_api_key else _REQUEST_DELAY
        )
        headers: dict[str, str] = {}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        index: dict[str, list[tuple[str, str, str]]] = {}
        start_index = 0
        total = None
        fetched = 0

        logger.info("Downloading NVD CPE dictionary...")
        t0 = time.monotonic()

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                while True:
                    params = {
                        "resultsPerPage": _PAGE_SIZE,
                        "startIndex": start_index,
                    }
                    resp = await client.get(
                        _NVD_CPE_API, params=params, headers=headers
                    )
                    resp.raise_for_status()
                    data = resp.json()

                    if total is None:
                        total = data.get("totalResults", 0)
                        logger.info("NVD CPE dictionary: %d total entries", total)

                    products = data.get("products", [])
                    if not products:
                        break

                    for product in products:
                        cpe = product.get("cpe", {})
                        cpe23 = cpe.get("cpeName", "")
                        if not cpe23:
                            continue

                        # Parse CPE 2.3: cpe:2.3:part:vendor:product:version:...
                        parts = cpe23.split(":")
                        if len(parts) < 6:
                            continue

                        vendor = parts[3]
                        product_name = parts[4]

                        if product_name == "*" or vendor == "*":
                            continue

                        key = product_name.lower()
                        if key not in index:
                            index[key] = []
                        # Store unique vendor:product pairs (deduplicate versions)
                        entry = (vendor, product_name, cpe23)
                        if not any(
                            e[0] == vendor and e[1] == product_name
                            for e in index[key]
                        ):
                            index[key].append(entry)

                    fetched += len(products)
                    start_index += _PAGE_SIZE

                    if start_index >= (total or 0):
                        break

                    await asyncio.sleep(delay)

        except Exception as e:
            logger.warning("NVD CPE dictionary download failed: %s", e)
            if not index:
                self._loading = False
                return

        elapsed = time.monotonic() - t0
        logger.info(
            "CPE dictionary downloaded: %d products, %d unique product names in %.1fs",
            fetched,
            len(index),
            elapsed,
        )

        self._index = index
        self._product_names = list(index.keys())

        # Cache to Redis
        try:
            redis = await self._get_redis()
            serialized = self._serialize_index()
            await redis.set(_INDEX_KEY, serialized, ex=_DICT_TTL)
            await redis.set(
                _META_KEY,
                json.dumps(
                    {
                        "total_products": len(index),
                        "fetched_entries": fetched,
                        "download_time": round(elapsed, 1),
                        "timestamp": int(time.time()),
                    }
                ),
                ex=_DICT_TTL,
            )
            logger.info("CPE dictionary cached to Redis (TTL: %dd)", _DICT_TTL // 86400)
        except Exception:
            logger.warning("Failed to cache CPE dictionary to Redis")

        self._loading = False

    def _serialize_index(self) -> str:
        """Serialize index for Redis storage."""
        if not self._index:
            return "{}"
        # Compact: {product: [[vendor, product, cpe23], ...]}
        compact: dict[str, list[list[str]]] = {}
        for key, entries in self._index.items():
            compact[key] = [list(e) for e in entries]
        return json.dumps(compact)

    def _deserialize_index(self, data: str) -> None:
        """Deserialize index from Redis."""
        compact = json.loads(data)
        self._index = {}
        for key, entries in compact.items():
            self._index[key] = [tuple(e) for e in entries]  # type: ignore[misc]
        self._product_names = list(self._index.keys())

    def lookup_fuzzy(
        self,
        name: str,
        version: str | None = None,
        limit: int = 5,
        threshold: float = CONFIDENCE_SUGGEST,
    ) -> list[CpeMatch]:
        """Fuzzy match a component name against the CPE dictionary.

        Uses rapidfuzz token_sort_ratio for fuzzy string matching.
        Returns matches sorted by confidence (descending).
        """
        if not self._index or not self._product_names:
            return []

        try:
            from rapidfuzz import fuzz, process
        except ImportError:
            logger.warning("rapidfuzz not installed — fuzzy CPE matching disabled")
            return []

        name_lower = name.lower().strip()

        # Generate candidate names (same normalization as sbom_service)
        candidates = [name_lower]
        if name_lower.startswith("lib"):
            candidates.append(name_lower[3:])
        candidates.append(name_lower.replace("-", "_"))
        candidates.append(name_lower.replace("_", "-"))
        # Strip version suffix
        import re

        stripped = re.sub(r"[\d.]+$", "", name_lower).rstrip("-_")
        if stripped and stripped != name_lower:
            candidates.append(stripped)

        best_matches: list[CpeMatch] = []
        seen_products: set[str] = set()

        for candidate in candidates:
            # First try exact match in dictionary
            exact = self._index.get(candidate)
            if exact:
                for vendor, product, cpe23 in exact:
                    prod_key = f"{vendor}:{product}"
                    if prod_key not in seen_products:
                        seen_products.add(prod_key)
                        # Build version-specific CPE
                        cpe_versioned = self._build_cpe(vendor, product, version)
                        best_matches.append(
                            CpeMatch(
                                cpe23=cpe_versioned,
                                vendor=vendor,
                                product=product,
                                confidence=1.0,
                                source="nvd_exact",
                            )
                        )

            # Fuzzy match
            results = process.extract(
                candidate,
                self._product_names,
                scorer=fuzz.token_sort_ratio,
                limit=limit,
                score_cutoff=threshold * 100,
            )

            for match_name, score, _ in results:
                entries = self._index.get(match_name, [])
                for vendor, product, cpe23 in entries:
                    prod_key = f"{vendor}:{product}"
                    if prod_key not in seen_products:
                        seen_products.add(prod_key)
                        confidence = score / 100.0
                        cpe_versioned = self._build_cpe(vendor, product, version)
                        best_matches.append(
                            CpeMatch(
                                cpe23=cpe_versioned,
                                vendor=vendor,
                                product=product,
                                confidence=confidence,
                                source="nvd_fuzzy",
                            )
                        )

        # Sort by confidence descending, limit results
        best_matches.sort(key=lambda m: m.confidence, reverse=True)
        return best_matches[:limit]

    @staticmethod
    def _build_cpe(vendor: str, product: str, version: str | None) -> str:
        """Build a CPE 2.3 string."""
        ver = version or "*"
        # Escape special chars in version
        ver = ver.replace(":", "\\:")
        return f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"

    async def get_status(self) -> dict:
        """Return dictionary status info."""
        status: dict = {
            "loaded": self._index is not None,
            "loading": self._loading,
            "product_count": len(self._index) if self._index else 0,
        }
        try:
            redis = await self._get_redis()
            meta_raw = await redis.get(_META_KEY)
            if meta_raw:
                status["meta"] = json.loads(meta_raw)
        except Exception:
            pass
        return status


# Module-level singleton
_service: CpeDictionaryService | None = None


def get_cpe_dictionary_service() -> CpeDictionaryService:
    """Get or create the singleton CPE dictionary service."""
    global _service
    if _service is None:
        _service = CpeDictionaryService()
    return _service
