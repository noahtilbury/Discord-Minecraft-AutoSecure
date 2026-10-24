"""Safe access to the non-secret bot settings (``config/bot.json``).

``config/bot.json`` documents that ``enabled_commands`` may be either a bare
``true``/``false`` (every cog on or off) or the full
``{"real": {...}, "aliases": {...}}`` object. The cogs used to index that
structure directly, which crashed the cog - and therefore the command - as soon
as a hand-edited config was missing a key. Everything resolves through the
helpers here instead, so a missing or unusual config degrades to the default
command name instead of taking the bot down.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger("bot")

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "bot.json"

_settings: dict | None = None


def load_settings() -> dict:
    """Read ``config/bot.json`` once. Returns ``{}`` when it is unusable."""
    global _settings
    if _settings is None:
        data: Any = {}
        try:
            with open(CONFIG_PATH, encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            log.warning("missing %s", CONFIG_PATH)
        except Exception:
            log.warning("could not read %s", CONFIG_PATH, exc_info=True)
        if not isinstance(data, dict):
            data = {}
        _settings = data
    return _settings


def enabled_commands() -> dict:
    """The ``enabled_commands`` object, or ``{}`` when it is a bare boolean."""
    enabled = load_settings().get("enabled_commands")
    return enabled if isinstance(enabled, dict) else {}


def command_alias(cog_name: str, default: str | None = None) -> str:
    """The slash-command name for a cog.

    Falls back to ``default`` (or the cog's own name) when the config has no
    alias for it, so a hand-edited config can never break a command.
    """
    aliases = enabled_commands().get("aliases")
    if isinstance(aliases, dict):
        alias = aliases.get(cog_name)
        if isinstance(alias, str) and alias.strip():
            return alias.strip()
    return default or cog_name
