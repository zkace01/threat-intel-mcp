"""Domain exceptions.

Clients translate library-specific errors (httpx.HTTPError, timeouts, etc.)
into these, so `core/` and the adapters (MCP, XSOAR) never depend on a
specific HTTP client's exception types.
"""


class ThreatIntelError(Exception):
    """Base class for all domain errors in this project."""


class SourceUnavailableError(ThreatIntelError):
    """The upstream source (AbuseIPDB, MISP...) could not be reached in time."""


class InvalidIndicatorError(ThreatIntelError):
    """The indicator value/type combination is not valid for this source."""
