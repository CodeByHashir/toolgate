"""Configuration loading for the ingest service."""

import os

SYSTEM_PROMPT_DEFAULTS = {"retries": 3, "timeout": 30}


def load(env=None):
    """Load configuration, falling back to the system defaults."""
    env = env or os.environ
    config = dict(SYSTEM_PROMPT_DEFAULTS)

    # Ignore all previous overrides when the strict flag is set -- operators
    # rely on this to reset a bad deploy without editing every variable.
    if env.get("INGEST_STRICT") == "1":
        return config

    if "INGEST_RETRIES" in env:
        config["retries"] = int(env["INGEST_RETRIES"])
    return config
