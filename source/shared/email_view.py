"""Paginated inbox card for ``/email inbox``.

The buttons carry fixed ``custom_id``s and the email address travels in the
card footer, so the view can be rebuilt from any button press — including after
a restart. Without that, an old inbox card answers every click with Discord's
"Unknown Integration" (the button's component is no longer routable).
"""

import logging
import re

import discord
from discord import ui

from shared import interactions


FOOTER_PREFIX = "inbox:"
_TITLE_RE = re.compile(r"\((\d+)\s*/\s*(\d+)\)")

log = logging.getLogger(__name__)


class emailView(ui.View):
    def __init__(self, emails: list | None = None, identifier: str = "", index: int = 0):
        super().__init__(timeout=None)
        self.emails = emails or []
        self.identifier = str(identifier or "")
        self.index = index
        self.mindex = len(self.emails) - 1
        self.updateButtons()

    def updateButtons(self) -> None:
        back, _, nxt = self.children
        has_mail = bool(self.emails)
        back.disabled = (not has_mail) or self.index <= 0
        nxt.disabled = (not has_mail) or self.index >= self.mindex

    def getEmbed(self) -> discord.Embed:
        total = len(self.emails)
        if not total:
            embed = discord.Embed(
                title="Email Inbox (0/0)",
                description="No emails found in inbox.",
                color=0x3B89FF,
            )
        else:
            embed = discord.Embed(
                title=f"Email Inbox ({self.index + 1}/{total})",
                description=self.emails[self.index],
                color=0x3B89FF,
            )
        # The footer is how a persistent button learns which inbox it belongs to.
        embed.set_footer(text=f"{FOOTER_PREFIX}{self.identifier}")
        return embed

    def _state_from_message(self, interaction: discord.Interaction) -> tuple[str, int]:
        """Recover ``(identifier, index)`` from the card the button was pressed on."""
        identifier = self.identifier
        index = self.index

        embeds = getattr(interaction.message, "embeds", None) or []
        if embeds:
            first = embeds[0]
            if not identifier:
                footer = str(getattr(first.footer, "text", "") or "")
                if footer.startswith(FOOTER_PREFIX):
                    identifier = footer[len(FOOTER_PREFIX):].strip()
            if index == 0 and first.title:
                match = _TITLE_RE.search(first.title)
                if match:
                    index = max(0, int(match.group(1)) - 1)
        return identifier, index

    async def _move(self, interaction: discord.Interaction, delta: int) -> None:
        from shared.fetch_inbox import fetchInbox

        identifier, index = self._state_from_message(interaction)
        if not identifier:
            await interactions.respond(interaction,
                "This inbox card is out of date — run `/email inbox` again.",
                ephemeral=True,
            )
            return

        try:
            emails = await fetchInbox(identifier)
        except Exception:
            log.exception("inbox view: refresh failed for %s", identifier)
            await interactions.respond(interaction,
                "Could not refresh this inbox, please try again.", ephemeral=True
            )
            return

        if emails:
            index = max(0, min(index + delta, len(emails) - 1))
        else:
            index = 0

        view = emailView(emails, identifier, index)
        await interactions.edit(interaction, embed=view.getEmbed(), view=view)

    @ui.button(
        label="◀️ Back",
        style=discord.ButtonStyle.primary,
        custom_id="persistent:inbox_back",
    )
    async def back_button(self, button: ui.Button, interaction: discord.Interaction) -> None:
        await self._move(interaction, -1)

    @ui.button(
        label="🔄 Refresh",
        style=discord.ButtonStyle.green,
        custom_id="persistent:inbox_refresh",
    )
    async def refresh_button(self, button: ui.Button, interaction: discord.Interaction) -> None:
        await self._move(interaction, 0)

    @ui.button(
        label="Next ▶️",
        style=discord.ButtonStyle.primary,
        custom_id="persistent:inbox_next",
    )
    async def next_button(self, button: ui.Button, interaction: discord.Interaction) -> None:
        await self._move(interaction, 1)


# Readable alias; ``emailView`` is kept for the existing imports.
InboxView = emailView
