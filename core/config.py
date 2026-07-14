"""Centralized configuration.

All secrets come from environment variables (loaded from `.env` in local
dev, never committed). Nothing in this codebase should read `os.environ`
directly outside this module — that keeps secret-handling auditable in one
place.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    abuseipdb_api_key: str
    mcp_server_api_key: str
    storage_cache_ttl_seconds: int = 3600


def load_settings() -> Settings:
    return Settings()
