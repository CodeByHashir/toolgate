"""Secrets and environment settings.

Read through pydantic-settings, which is already a dependency, rather than
adding a dotenv package or hand-rolling a parser.

The API key is never logged, never written to a chain record, and never
committed -- `.env` is gitignored.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from llmshield_mcp.config import REPO_ROOT


class Settings(BaseSettings):
    """Environment settings, sourced from the process environment or `.env`."""

    model_config = SettingsConfigDict(
        env_file=REPO_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    anthropic_api_key: str = Field(
        default="",
        description="Anthropic API key used by the reference agent.",
    )

    def require_anthropic_api_key(self) -> str:
        if not self.anthropic_api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Add it to .env at the repository root "
                "or export it in the environment."
            )
        return self.anthropic_api_key
