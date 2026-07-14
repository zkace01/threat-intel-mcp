"""Protocol-agnostic enrichment logic.

Neither the MCP adapter nor the (future) XSOAR integration should contain
business logic — they should only translate their protocol's request into a
call to `lookup_indicator`, and its response back into their protocol's
response shape. This module is where AbuseIPDB's response shape actually
gets interpreted.
"""
from __future__ import annotations

from clients.abuseipdb import AbuseIPDBClient
from core.exceptions import InvalidIndicatorError
from models.indicator import Indicator, IndicatorType, LookupSource, NormalizedResult
from storage.base import StorageBackend

# AbuseIPDB's own documented threshold for "should be treated as malicious".
# Made explicit here (not buried in a magic number) since it's a judgment
# call worth being able to tune later.
MALICIOUS_CONFIDENCE_THRESHOLD = 50


def _cache_key(indicator: Indicator, source: LookupSource) -> str:
    return f"{source.value}:{indicator.type.value}:{indicator.value}"


async def lookup_indicator(
    indicator: Indicator,
    *,
    abuseipdb_client: AbuseIPDBClient,
    storage: StorageBackend,
) -> NormalizedResult:
    """Look up a single indicator, using cache when available.

    Currently only supports IP indicators against AbuseIPDB — domain/hash
    support and additional sources (MISP) are added in later steps, behind
    this same function signature so callers don't change.
    """
    if indicator.type != IndicatorType.IP:
        raise InvalidIndicatorError(
            f"Indicator type '{indicator.type.value}' is not supported yet"
        )

    key = _cache_key(indicator, LookupSource.ABUSEIPDB)
    cached = await storage.get_cached(key)
    if cached is not None:
        return cached

    raw = await abuseipdb_client.check_ip(indicator.value)
    data = raw.get("data", {})

    result = NormalizedResult(
        indicator=indicator,
        source=LookupSource.ABUSEIPDB,
        malicious=data.get("abuseConfidenceScore", 0) >= MALICIOUS_CONFIDENCE_THRESHOLD,
        confidence_score=data.get("abuseConfidenceScore", 0),
        reports_count=data.get("totalReports", 0),
        last_reported_at=data.get("lastReportedAt"),
        raw=data,
    )

    await storage.save_lookup(key, result)
    return result
