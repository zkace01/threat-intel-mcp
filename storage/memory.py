"""In-memory storage backend — the default for the MVP.

Not thread-safe beyond asyncio's single-threaded event loop assumptions, and
not persisted across restarts. That's fine for a portfolio project; swap in
a SQLite/Postgres-backed `StorageBackend` implementation later without
changing anything in `core/`.
"""
from __future__ import annotations

import time

from models.indicator import NormalizedResult
from storage.base import StorageBackend

DEFAULT_TTL_SECONDS = 3600


class InMemoryStorage(StorageBackend):
    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self._ttl_seconds = ttl_seconds
        self._data: dict[str, tuple[float, NormalizedResult]] = {}

    async def save_lookup(self, key: str, result: NormalizedResult) -> None:
        self._data[key] = (time.monotonic(), result)

    async def get_cached(self, key: str) -> NormalizedResult | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        saved_at, result = entry
        if time.monotonic() - saved_at > self._ttl_seconds:
            del self._data[key]
            return None
        return result
