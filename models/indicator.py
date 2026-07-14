"""Data contracts shared across clients, core and adapters.

Keeping these in one place (independent of any client or transport) is what
lets `core/` stay protocol-agnostic: MCP and XSOAR both talk in terms of
these models, never in terms of a specific source's raw response shape.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"


class Indicator(BaseModel):
    """A single threat intel indicator submitted for lookup."""

    type: IndicatorType
    value: str = Field(..., min_length=1, max_length=512)

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str, info) -> str:
        value = value.strip()
        # Fail closed: an indicator that doesn't match its declared type is
        # rejected here, not passed downstream to an external API call.
        indicator_type = info.data.get("type")
        if indicator_type == IndicatorType.IP:
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError(f"'{value}' is not a valid IP address") from exc
        return value


class LookupSource(str, Enum):
    ABUSEIPDB = "abuseipdb"
    MISP = "misp"


class NormalizedResult(BaseModel):
    """Provider-agnostic result of looking up a single indicator.

    This is the shape both the MCP tool and the XSOAR integration return —
    STIX normalization (added in a later step) will wrap this, not replace it.
    """

    indicator: Indicator
    source: LookupSource
    malicious: bool
    confidence_score: int = Field(ge=0, le=100)
    reports_count: int = Field(ge=0, default=0)
    last_reported_at: datetime | None = None
    raw: dict = Field(default_factory=dict, repr=False)
    retrieved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
