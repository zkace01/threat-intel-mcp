"""Thin client for the AbuseIPDB API.

Security/robustness choices worth noting:
- API key is only ever read from the constructor argument (injected from
  config at startup) — never read from env directly here, so this class
  stays testable without monkeypatching os.environ.
- Explicit timeout on every request: an external API hanging must not hang
  the MCP server.
- httpx errors are caught and re-raised as our own SourceUnavailableError,
  so callers never need to know this client is built on httpx.
- The API key is never included in logs or in raised exception messages.
"""
from __future__ import annotations

import httpx

from core.exceptions import SourceUnavailableError

ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
REQUEST_TIMEOUT_SECONDS = 5.0


class AbuseIPDBClient:
    def __init__(self, api_key: str, base_url: str = ABUSEIPDB_BASE_URL) -> None:
        if not api_key:
            raise ValueError("AbuseIPDB API key must not be empty")
        self._api_key = api_key
        self._base_url = base_url

    async def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        """Return the raw AbuseIPDB response for a single IP check.

        Raises SourceUnavailableError on network failure, timeout, or a
        non-2xx response — callers decide what "unavailable" means for them
        (retry, fall back to cache, surface an error to the user).
        """
        headers = {"Key": self._api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": str(max_age_days)}

        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
                response = await client.get(
                    f"{self._base_url}/check", headers=headers, params=params
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as exc:
            raise SourceUnavailableError(
                f"AbuseIPDB returned HTTP {exc.response.status_code}"
            ) from exc
        except httpx.HTTPError as exc:
            raise SourceUnavailableError("AbuseIPDB request failed") from exc
