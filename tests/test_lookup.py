import pytest

from core.exceptions import InvalidIndicatorError
from core.lookup import lookup_indicator
from models.indicator import Indicator, IndicatorType
from storage.memory import InMemoryStorage


class FakeAbuseIPDBClient:
    """Duck-typed stand-in for AbuseIPDBClient — no real network call.

    Tracks how many times it was called so tests can assert caching
    actually avoids a second lookup.
    """

    def __init__(self, abuse_confidence_score: int = 0, total_reports: int = 0):
        self.abuse_confidence_score = abuse_confidence_score
        self.total_reports = total_reports
        self.call_count = 0

    async def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        self.call_count += 1
        return {
            "data": {
                "ipAddress": ip,
                "abuseConfidenceScore": self.abuse_confidence_score,
                "totalReports": self.total_reports,
            }
        }


@pytest.mark.asyncio
async def test_malicious_ip_above_threshold():
    client = FakeAbuseIPDBClient(abuse_confidence_score=80, total_reports=5)
    storage = InMemoryStorage()
    indicator = Indicator(value="1.2.3.4", type=IndicatorType.IP)

    result = await lookup_indicator(indicator, abuseipdb_client=client, storage=storage)

    assert result.malicious is True
    assert result.confidence_score == 80


@pytest.mark.asyncio
async def test_clean_ip_below_threshold():
    client = FakeAbuseIPDBClient(abuse_confidence_score=10)
    storage = InMemoryStorage()
    indicator = Indicator(value="8.8.8.8", type=IndicatorType.IP)

    result = await lookup_indicator(indicator, abuseipdb_client=client, storage=storage)

    assert result.malicious is False


@pytest.mark.asyncio
async def test_second_lookup_hits_cache_not_client():
    client = FakeAbuseIPDBClient(abuse_confidence_score=50)
    storage = InMemoryStorage()
    indicator = Indicator(value="1.2.3.4", type=IndicatorType.IP)

    await lookup_indicator(indicator, abuseipdb_client=client, storage=storage)
    await lookup_indicator(indicator, abuseipdb_client=client, storage=storage)

    assert client.call_count == 1


@pytest.mark.asyncio
async def test_unsupported_indicator_type_raises():
    client = FakeAbuseIPDBClient()
    storage = InMemoryStorage()
    indicator = Indicator(value="example.com", type=IndicatorType.DOMAIN)

    with pytest.raises(InvalidIndicatorError):
        await lookup_indicator(indicator, abuseipdb_client=client, storage=storage)
