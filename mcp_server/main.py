"""MCP adapter.

This module is intentionally thin: it defines one tool, validates its input
into an `Indicator`, calls `core.lookup_indicator`, and returns the result.
No enrichment/business logic belongs here.

Transport note: this runs over stdio for now (the standard way to plug into
Claude Desktop and similar local MCP clients), so `MCP_SERVER_API_KEY` is
currently unused — auth matters once this moves to Streamable HTTP for
remote access, which is a later step, not before it's actually needed.

SDK note (as of mid-2026): built against `mcp.server.fastmcp.FastMCP`
(bundled in the official `mcp` SDK, currently in maintenance mode). The SDK
has a v2 beta that renames this class to `MCPServer` — pin `mcp` with an
upper bound (e.g. `mcp[cli]>=1.18,<2`) until that stabilizes, to avoid an
import break.
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from clients.abuseipdb import AbuseIPDBClient
from core.config import load_settings
from core.exceptions import ThreatIntelError
from core.lookup import lookup_indicator
from models.indicator import Indicator, IndicatorType
from storage.memory import InMemoryStorage

settings = load_settings()
abuseipdb_client = AbuseIPDBClient(api_key=settings.abuseipdb_api_key)
storage = InMemoryStorage(ttl_seconds=settings.storage_cache_ttl_seconds)

mcp = FastMCP("threat-intel-mcp")


@mcp.tool()
async def check_ip(ip_address: str) -> dict:
    """Look up an IP address against AbuseIPDB and return a normalized
    verdict: whether it's considered malicious, its confidence score, and
    how many reports back that verdict.
    """
    try:
        indicator = Indicator(value=ip_address, type=IndicatorType.IP)
    except ValueError as exc:
        return {"error": str(exc)}

    try:
        result = await lookup_indicator(
            indicator, abuseipdb_client=abuseipdb_client, storage=storage
        )
    except ThreatIntelError as exc:
        return {"error": str(exc)}

    return result.model_dump(mode="json", exclude={"raw"})


if __name__ == "__main__":
    mcp.run()
