"""Helpers for answering Discord interactions safely.

Two Discord errors show up regularly in this project:

* **10062 / 404 Unknown interaction** - the interaction token expired.  The
  securing pipeline can run for minutes, so by the time the result card is
  written the original interaction is long gone.  Nothing can be sent for that
  interaction any more; the caller has to fall back to another route (a DM).
* **Already acknowledged** - the interaction was already answered.  A button
  that is pressed twice, or a callback that answers in two places, raises this
  and leaves the user staring at a failed button.

Both are normal in a long flow, so every interaction answer in the project
goes through the helpers below: they answer when they can and report ``False``
when Discord refuses, instead of raising out of the button callback (which
would show the user "This interaction failed").
"""

from __future__ import annotations

import logging

import discord

log = logging.getLogger("bot")

# Discord error codes.
UNKNOWN_INTERACTION = 10062
ALREADY_ACKNOWLEDGED = 40060


def describe(exc: BaseException) -> str:
    """Short, log-friendly description of an interaction error."""
    status = getattr(exc, "status", None)
    code = getattr(exc, "code", None)
    return f"{exc.__class__.__name__}(status={status}, code={code}): {exc}"


def is_expired(exc: BaseException) -> bool:
    """True for an expired / unknown interaction (404, code 10062)."""
    if isinstance(exc, discord.NotFound):
        return True
    if getattr(exc, "code", None) == UNKNOWN_INTERACTION:
        return True
    return getattr(exc, "status", None) == 404


def is_already_acknowledged(exc: BaseException) -> bool:
    """True when the interaction was already answered."""
    if isinstance(exc, discord.InteractionResponded):
        return True
    if getattr(exc, "code", None) == ALREADY_ACKNOWLEDGED:
        return True
    text = str(exc).lower()
    return "already been acknowledged" in text or "already acknowledged" in text


def _is_expected(exc: BaseException) -> bool:
    return is_expired(exc) or is_already_acknowledged(exc)


def _log_skipped(what: str, interaction, exc: BaseException) -> None:
    log.info(
        "%s skipped for interaction %s - %s",
        what,
        getattr(interaction, "id", "?"),
        describe(exc),
    )


async def respond(
    interaction: discord.Interaction,
    content: str | None = None,
    *,
    embed: discord.Embed | None = None,
    view=None,
    ephemeral: bool = True,
    **extra,
) -> bool:
    """Answer an interaction. Returns False when Discord refused the answer."""
    try:
        await interaction.response.send_message(
            content=content, embed=embed, view=view, ephemeral=ephemeral, **extra
        )
        return True
    except discord.InteractionResponded as exc:
        _log_skipped("response", interaction, exc)
        return False
    except discord.HTTPException as exc:
        if _is_expected(exc):
            _log_skipped("response", interaction, exc)
            return False
        raise


async def defer(interaction: discord.Interaction, *, ephemeral: bool = True) -> bool:
    """Acknowledge an interaction without answering it yet."""
    try:
        await interaction.response.defer(ephemeral=ephemeral)
        return True
    except discord.InteractionResponded as exc:
        _log_skipped("defer", interaction, exc)
        return False
    except discord.HTTPException as exc:
        if _is_expected(exc):
            _log_skipped("defer", interaction, exc)
            return False
        raise


async def edit(interaction: discord.Interaction, **kwargs) -> bool:
    """Edit the message the interaction belongs to."""
    try:
        await interaction.response.edit_message(**kwargs)
        return True
    except discord.InteractionResponded as exc:
        _log_skipped("edit", interaction, exc)
        return False
    except discord.HTTPException as exc:
        if _is_expected(exc):
            _log_skipped("edit", interaction, exc)
            return False
        raise


async def edit_original(interaction: discord.Interaction, **kwargs) -> bool:
    """Edit the original response of an interaction."""
    try:
        await interaction.edit_original_response(**kwargs)
        return True
    except discord.InteractionResponded as exc:
        _log_skipped("edit original", interaction, exc)
        return False
    except discord.HTTPException as exc:
        if _is_expected(exc):
            _log_skipped("edit original", interaction, exc)
            return False
        raise


async def followup(
    interaction: discord.Interaction, content: str | None = None, **kwargs
) -> bool:
    """Send a follow-up message for an interaction."""
    try:
        await interaction.followup.send(content, **kwargs)
        return True
    except discord.InteractionResponded as exc:
        _log_skipped("followup", interaction, exc)
        return False
    except discord.HTTPException as exc:
        if _is_expected(exc):
            _log_skipped("followup", interaction, exc)
            return False
        raise


async def followup_message(
    interaction: discord.Interaction, content: str | None = None, **kwargs
):
    """Send a follow-up message and return it (``None`` when Discord refused)."""
    try:
        return await interaction.followup.send(content, **kwargs)
    except discord.InteractionResponded as exc:
        _log_skipped("followup", interaction, exc)
        return None
    except discord.HTTPException as exc:
        if _is_expected(exc):
            _log_skipped("followup", interaction, exc)
            return None
        raise


async def send_modal(interaction: discord.Interaction, modal) -> bool:
    """Open a modal from an interaction."""
    try:
        await interaction.response.send_modal(modal)
        return True
    except discord.InteractionResponded as exc:
        _log_skipped("modal", interaction, exc)
        return False
    except discord.HTTPException as exc:
        if _is_expected(exc):
            _log_skipped("modal", interaction, exc)
            return False
        raise
