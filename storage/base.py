"""Abstract storage backend.

Deliberately minimal for the MVP: `core/` only needs to cache a lookup and
retrieve it. Anything more (querying by date range, aggregations, etc.) gets
added to this interface when a real use case for it shows up — not before.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from models.indicator import NormalizedResult


class StorageBackend(ABC):
    @abstractmethod
    async def save_lookup(self, key: str, result: NormalizedResult) -> None:
        """Persist a lookup result under `key` (e.g. f"{source}:{indicator}")."""

    @abstractmethod
    async def get_cached(self, key: str) -> NormalizedResult | None:
        """Return a previously saved result, or None if not present/expired."""
