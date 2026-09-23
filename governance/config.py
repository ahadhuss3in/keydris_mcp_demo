"""Environment loading shared by every entrypoint.

Keeping this in one place means the MCP server subprocess and the LangGraph
process resolve the same OpenRouter / Jev / threshold configuration.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

# Load `.env` once, from the project root, without overriding real env vars.
load_dotenv(override=False)

# Defaults are deliberately the values documented in documentation/jev_typesafe.md
# and documentation/jev_SDK so the PoC works with only OPENROUTER_API_KEY set.
DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_INVESTIGATOR_MODEL = "deepseek/deepseek-v4.1-flash"
DEFAULT_JEV_MODEL = "typesafe/jev-1.13"
DEFAULT_JEV_PATH = "/systemone"
DEFAULT_AUTO_BLOCK_MIN_CONFIDENCE = 0.90
DEFAULT_ENFORCER_TRANSPORT = "stdio"


def get_env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def openrouter_api_key() -> str:
    """Return the OpenRouter key or raise a *clear* actionable error.

    The PoC is intentionally live-only (no offline LLM fallback), so a missing
    key should fail loudly rather than silently degrade.
    """

    key = get_env("OPENROUTER_API_KEY")
    if not key:
        raise RuntimeError(
            "OPENROUTER_API_KEY is not set. Copy .env.example to .env and add your "
            "OpenRouter key (used for both the investigator LLM and Jev)."
        )
    return key