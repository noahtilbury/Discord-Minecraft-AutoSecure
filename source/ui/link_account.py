from __future__ import annotations

import discord

from ui import theme

from shared import interactions

async def _open_verification_modal(interaction: discord.Interaction) -> None:
    # Imported lazily so theme/link_account stay importable without pulling in
    # the whole securing pipeline at bot start-up.
    from ui.modals.modal_one import MyModalOne

    await interactions.send_modal(interaction, MyModalOne())


class LinkAccountView(discord.ui.DesignerView):
    """Persistent Components V2 verification prompt.

    Renders the greeting plus a green *Verify* button inside the card (classic
    embeds cannot place a button inside the card).
    """

    def __init__(self) -> None:
        super().__init__(
            theme.verify_container(_open_verification_modal),
            timeout=None,
        )
