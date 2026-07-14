import pytest

from models.indicator import Indicator, IndicatorType, LookupSource, NormalizedResult
from storage.memory import InMemoryStorage


def _make_result() -> NormalizedResult:
    return NormalizedResult(
        indicator=Indicator(value="8.8.8.8", type=IndicatorType.IP),
        source=LookupSource.ABUSEIPDB,
        malicious=False,
        confidence_score=0,
    )


@pytest.mark.asyncio
async def test_save_and_get_cached():
    storage = InMemoryStorage()
    result = _make_result()

    await storage.save_lookup("key1", result)
    cached = await storage.get_cached("key1")

    assert cached is not None
    assert cached.indicator.value == "8.8.8.8"


@pytest.mark.asyncio
async def test_missing_key_returns_none():
    storage = InMemoryStorage()
    assert await storage.get_cached("missing") is None


@pytest.mark.asyncio
async def test_expired_entry_returns_none():
    storage = InMemoryStorage(ttl_seconds=0)
    await storage.save_lookup("key1", _make_result())

    assert await storage.get_cached("key1") is None
