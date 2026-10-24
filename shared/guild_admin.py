"""Owner-only guild management primitives.

Everything here works with the guild objects the bot already receives through
Discord's authorised API access (``bot.guilds``) plus normal REST calls the bot
is allowed to make (member lookups, invite listing and invite creation). No
token, web session or privileged endpoint is used.

Security model:

* ownership is always checked against the bot's configured ``owners`` list
  (``bot.admins``), never against a value supplied by a user;
* the mutating actions (leave, create invite) re-check ownership themselves so
  they stay safe even if a UI check is bypassed;
* a guild is only ever resolved from ``bot.guilds``, so the bot can never act
  on a server it is not already in.

The module is intentionally dependency-free apart from py-cord so the offline
tests can exercise it with small fake guilds.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import discord

log = logging.getLogger("bot")

PAGE_SIZE = 10
MEMBER_FETCH_CONCURRENCY = 5
ACCESS_CACHE_SECONDS = 60.0
UNKNOWN_ACCESS_CACHE_SECONDS = 15.0
CREATED_INVITE_MAX_AGE = 24 * 60 * 60


class GuildActionError(Exception):
    """A guild-management action Discord could not complete.

    The message is written for the bot owner and is safe to show in Discord;
    technical details stay in the log.
    """


@dataclass(frozen=True)
class GuildSummary:
    """Everything the dashboard needs about one guild."""

    guild_id: int
    name: str
    member_count: int | None
    owner_is_member: bool | None
    available: bool


@dataclass(frozen=True)
class GuildPage:
    """One page of a (possibly filtered) guild list."""

    query: str
    page: int
    pages: int
    total: int
    per_page: int
    summaries: tuple[GuildSummary, ...]


@dataclass(frozen=True)
class InviteAvailability:
    """Result of a non-mutating invite lookup.

    ``url`` is only ever populated from an invite that Discord returned. When
    it is empty, ``note`` explains the limitation and ``can_create`` says
    whether the "Create invite" action is offered.
    """

    url: str | None
    source: str | None
    can_create: bool
    channel_name: str | None
    manage_guild: bool
    create_permission: bool
    note: str


@dataclass(frozen=True)
class CreatedInvite:
    url: str
    code: str
    expires_at: datetime | None
    channel_name: str | None


@dataclass(frozen=True)
class LeaveResult:
    guild_id: int
    name: str
    left: bool
    already_left: bool


# ---------------------------------------------------------------------------
# Small, defensive accessors
# ---------------------------------------------------------------------------


def _safe_id(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def parse_guild_id(value) -> int | None:
    """Return a positive guild ID, or ``None`` for unusable input."""
    guild_id = _safe_id(value)
    return guild_id if guild_id > 0 else None


def is_owner(bot, user_id) -> bool:
    """True when ``user_id`` is one of the configured bot owners.

    An empty owner list denies everyone, matching the rest of the project's
    admin checks. IDs may be stored as strings in a hand-edited config.
    """
    user_id = parse_guild_id(user_id)
    if user_id is None:
        return False
    owners = getattr(bot, "admins", None) or []
    try:
        iterator = iter(owners)
    except TypeError:
        return False
    for value in iterator:
        if _safe_id(value) == user_id:
            return True
    return False


def bot_member(guild):
    """The bot's own member object for ``guild``, or ``None`` if unavailable."""
    try:
        return guild.me
    except Exception:  # pragma: no cover - depends on a live gateway state
        return None


def guild_available(guild) -> bool:
    """Whether Discord currently gives the bot usable data for this guild."""
    try:
        if bool(getattr(guild, "unavailable", False)):
            return False
    except Exception:  # pragma: no cover - defensive
        return False
    return bot_member(guild) is not None


def guild_display_name(guild) -> str:
    """A single-line, code-block-safe name for embeds and select options."""
    guild_id = _safe_id(getattr(guild, "id", None))
    try:
        raw = getattr(guild, "name", None)
    except Exception:  # pragma: no cover - defensive
        raw = None
    text = " ".join(str(raw or "").replace("`", "'").split())
    if not text:
        return f"Server {guild_id or '?'}"
    if len(text) > 80:
        text = text[:79].rstrip() + "\u2026"
    return text


def guild_member_count(guild) -> int | None:
    """Discord's approximate member count, or ``None`` when it is not cached."""
    try:
        count = getattr(guild, "member_count", None)
    except Exception:  # pragma: no cover - defensive
        return None
    if isinstance(count, bool) or not isinstance(count, int):
        return None
    return count if count >= 0 else None


def summary_from_guild(guild, owner_is_member: bool | None) -> GuildSummary:
    return GuildSummary(
        guild_id=_safe_id(getattr(guild, "id", None)),
        name=guild_display_name(guild),
        member_count=guild_member_count(guild),
        owner_is_member=owner_is_member,
        available=guild_available(guild),
    )


# ---------------------------------------------------------------------------
# Filtering and pagination
# ---------------------------------------------------------------------------


def filter_guilds(guilds, query: str = "") -> list:
    """Case-insensitive server-name/ID search, sorted by name."""
    needle = str(query or "").strip().casefold()
    matched = []
    for guild in guilds or []:
        name = guild_display_name(guild)
        guild_id = str(_safe_id(getattr(guild, "id", None)))
        if not needle or needle in name.casefold() or needle in guild_id:
            matched.append(guild)
    matched.sort(key=lambda guild: (guild_display_name(guild).casefold(), _safe_id(getattr(guild, "id", None))))
    return matched


def page_count(total: int, per_page: int = PAGE_SIZE) -> int:
    if per_page < 1:
        per_page = PAGE_SIZE
    return max(1, (max(0, int(total)) + per_page - 1) // per_page)


def clamp_page(page: int, total: int, per_page: int = PAGE_SIZE) -> int:
    try:
        page = int(page)
    except (TypeError, ValueError):
        page = 0
    return min(max(0, page), page_count(total, per_page) - 1)


def page_slice(items, page: int, per_page: int = PAGE_SIZE):
    """``(items_on_page, clamped_page_number)``."""
    if per_page < 1:
        per_page = PAGE_SIZE
    items = list(items)
    page = clamp_page(page, len(items), per_page)
    return items[page * per_page : (page + 1) * per_page], page


# ---------------------------------------------------------------------------
# Owner membership in a guild
# ---------------------------------------------------------------------------


async def owner_membership(guild, owner_id) -> bool | None:
    """Whether the bot owner is personally in ``guild``.

    ``None`` means Discord refused or failed the lookup; it is never reported
    as "not a member". The member cache is checked first, then one normal
    ``fetch_member`` call (404 = genuinely not a member).
    """
    if not guild_available(guild):
        return None
    owner_id = parse_guild_id(owner_id)
    if owner_id is None:
        return None

    # The guild owner is always a member; this avoids a needless lookup when
    # the owner happens to own the server.
    try:
        if getattr(guild, "owner_id", None) == owner_id:
            return True
    except Exception:  # pragma: no cover - defensive
        pass

    try:
        if guild.get_member(owner_id) is not None:
            return True
    except Exception:  # pragma: no cover - cache lookup should not fail
        log.warning("member cache lookup failed for guild %s", _safe_id(getattr(guild, "id", None)), exc_info=True)

    try:
        await guild.fetch_member(owner_id)
        return True
    except discord.NotFound:
        return False
    except discord.Forbidden:
        log.info(
            "Discord refused the owner-membership lookup for guild %s",
            _safe_id(getattr(guild, "id", None)),
        )
        return None
    except discord.HTTPException as exc:
        log.warning(
            "owner-membership lookup failed for guild %s (HTTP %s)",
            _safe_id(getattr(guild, "id", None)),
            getattr(exc, "status", "?"),
        )
        return None
    except asyncio.TimeoutError:
        log.warning("owner-membership lookup timed out for guild %s", _safe_id(getattr(guild, "id", None)))
        return None
    except Exception:
        log.warning(
            "owner-membership lookup crashed for guild %s",
            _safe_id(getattr(guild, "id", None)),
            exc_info=True,
        )
        return None


class GuildDirectory:
    """A cached, paginated view of ``bot.guilds`` for the dashboard."""

    def __init__(self, bot, *, per_page: int = PAGE_SIZE, cache_seconds: float = ACCESS_CACHE_SECONDS):
        self.bot = bot
        self.per_page = per_page if per_page > 0 else PAGE_SIZE
        self.cache_seconds = cache_seconds
        # Keyed by (guild, owner): two configured owners can have different
        # membership in the same guild, so a guild-only cache would leak one
        # owner's answer into the other's dashboard.
        self._access_cache: dict[tuple[int, int], tuple[float, bool | None]] = {}

    def guilds(self) -> list:
        try:
            guilds = getattr(self.bot, "guilds", None) or []
        except Exception:  # pragma: no cover - defensive
            log.warning("could not read bot.guilds", exc_info=True)
            return []
        return list(guilds)

    def matching(self, query: str = "") -> list:
        return filter_guilds(self.guilds(), query)

    def invalidate(self, guild_id) -> None:
        guild_id = _safe_id(guild_id)
        for key in [key for key in self._access_cache if key[0] == guild_id]:
            self._access_cache.pop(key, None)

    def clear(self) -> None:
        self._access_cache.clear()

    async def _access(self, guild, owner_id, *, force: bool) -> bool | None:
        guild_id = _safe_id(getattr(guild, "id", None))
        owner_key = parse_guild_id(owner_id) or 0
        cache_key = (guild_id, owner_key)
        now = time.monotonic()
        if not force:
            cached = self._access_cache.get(cache_key)
            if cached is not None and cached[0] > now:
                return cached[1]

        value = await owner_membership(guild, owner_id)
        ttl = self.cache_seconds if value is not None else min(UNKNOWN_ACCESS_CACHE_SECONDS, self.cache_seconds)
        self._access_cache[cache_key] = (now + ttl, value)
        return value

    async def summary(self, guild, *, owner_id, force: bool = False) -> GuildSummary:
        access = await self._access(guild, owner_id, force=force)
        return summary_from_guild(guild, access)

    async def page(self, query: str = "", page: int = 0, *, owner_id, force: bool = False) -> GuildPage:
        matching = self.matching(query)
        total = len(matching)
        pages = page_count(total, self.per_page)
        page = clamp_page(page, total, self.per_page)
        slice_ = matching[page * self.per_page : (page + 1) * self.per_page]

        semaphore = asyncio.Semaphore(MEMBER_FETCH_CONCURRENCY)

        async def build(guild):
            async with semaphore:
                try:
                    return await self.summary(guild, owner_id=owner_id, force=force)
                except Exception:
                    log.warning(
                        "could not build summaries for guild %s",
                        _safe_id(getattr(guild, "id", None)),
                        exc_info=True,
                    )
                    return summary_from_guild(guild, None)

        summaries = await asyncio.gather(*(build(guild) for guild in slice_))
        return GuildPage(
            query=str(query or ""),
            page=page,
            pages=pages,
            total=total,
            per_page=self.per_page,
            summaries=tuple(summaries),
        )


# ---------------------------------------------------------------------------
# Invites
# ---------------------------------------------------------------------------


def _invite_url(invite) -> str | None:
    """Return a real Discord invite URL, never one built from a guess."""
    url = getattr(invite, "url", None)
    if isinstance(url, str) and url.startswith(
        ("https://discord.gg/", "https://discord.com/invite/", "https://discordapp.com/invite/")
    ):
        return url
    code = getattr(invite, "code", None)
    if isinstance(code, str) and code.strip():
        return f"https://discord.gg/{code.strip()}"
    return None


def _invite_is_valid(invite, now: datetime) -> bool:
    if bool(getattr(invite, "revoked", False)):
        return False
    expires_at = getattr(invite, "expires_at", None)
    if expires_at is not None:
        try:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= now:
                return False
        except (AttributeError, TypeError, ValueError):
            return False

    try:
        max_uses = int(getattr(invite, "max_uses", 0) or 0)
        uses = int(getattr(invite, "uses", 0) or 0)
    except (TypeError, ValueError):
        return False
    if max_uses > 0 and uses >= max_uses:
        return False
    return _invite_url(invite) is not None


def _invite_rank(invite) -> tuple[bool, bool]:
    """Prefer never-expiring, unlimited invites over temporary/limited ones."""
    return (getattr(invite, "expires_at", None) is not None, bool(getattr(invite, "max_uses", 0)))


def invite_channel(guild):
    """First visible text channel where the bot may create an invite."""
    me = bot_member(guild)
    if me is None:
        return None
    try:
        channels = list(getattr(guild, "text_channels", None) or [])
    except Exception:  # pragma: no cover - defensive
        return None
    channels.sort(key=lambda channel: (getattr(channel, "position", 0), str(getattr(channel, "name", ""))))
    for channel in channels:
        try:
            permissions = channel.permissions_for(me)
        except Exception:  # pragma: no cover - unusual channel state
            continue
        if bool(getattr(permissions, "view_channel", False)) and bool(
            getattr(permissions, "create_instant_invite", False)
        ):
            return channel
    return None


def channel_display_name(channel) -> str | None:
    if channel is None:
        return None
    try:
        name = str(getattr(channel, "name", "") or "").strip()
    except Exception:  # pragma: no cover - defensive
        name = ""
    return f"#{name}" if name else "a text channel"


async def invite_availability(guild) -> InviteAvailability:
    """Look for an existing invite without creating anything.

    Existing invite listing needs Manage Server; creating a new invite needs
    Create Invite in a visible text channel. Both are checked from the bot's
    own permissions, never from the owner's roles.
    """
    me = bot_member(guild)
    if me is None or bool(getattr(guild, "unavailable", False)):
        return InviteAvailability(
            url=None,
            source=None,
            can_create=False,
            channel_name=None,
            manage_guild=False,
            create_permission=False,
            note=(
                "This server is currently unavailable to the bot, so Discord has not given it "
                "the details needed to find or create an invite."
            ),
        )

    manage_guild = bool(getattr(getattr(me, "guild_permissions", None), "manage_guild", False))
    create_channel = invite_channel(guild)
    channel_name = channel_display_name(create_channel)
    invites_disabled = bool(getattr(guild, "invites_disabled", False))
    can_create = create_channel is not None and not invites_disabled

    if invites_disabled:
        return InviteAvailability(
            url=None,
            source=None,
            can_create=False,
            channel_name=channel_name,
            manage_guild=manage_guild,
            create_permission=False,
            note="Invites are disabled in this server, so no invite link can be provided.",
        )

    reasons: list[str] = []
    if manage_guild:
        features = set(getattr(guild, "features", None) or [])
        if "VANITY_URL" in features:
            try:
                vanity = await guild.vanity_invite()
            except discord.Forbidden:
                reasons.append("Discord refused the vanity invite lookup.")
            except discord.HTTPException as exc:
                reasons.append(f"Discord could not return the vanity invite (HTTP {getattr(exc, 'status', '?')}).")
            except asyncio.TimeoutError:
                reasons.append("The vanity invite lookup timed out.")
            except Exception:
                log.warning("vanity invite lookup failed for guild %s", _safe_id(getattr(guild, "id", None)), exc_info=True)
                reasons.append("The vanity invite lookup failed.")
            else:
                if vanity is not None:
                    url = _invite_url(vanity)
                    if url:
                        return InviteAvailability(
                            url=url,
                            source="vanity",
                            can_create=can_create,
                            channel_name=channel_name,
                            manage_guild=True,
                            create_permission=can_create,
                            note="This is the server's existing vanity invite.",
                        )

        try:
            invites = await guild.invites()
        except discord.Forbidden:
            reasons.append("Discord refused the existing-invite lookup.")
        except discord.HTTPException as exc:
            reasons.append(f"Discord could not list existing invites (HTTP {getattr(exc, 'status', '?')}).")
        except asyncio.TimeoutError:
            reasons.append("Listing existing invites timed out.")
        except Exception:
            log.warning("invite lookup failed for guild %s", _safe_id(getattr(guild, "id", None)), exc_info=True)
            reasons.append("The existing-invite lookup failed.")
        else:
            now = discord.utils.utcnow()
            valid = [invite for invite in (invites or []) if _invite_is_valid(invite, now)]
            valid.sort(key=_invite_rank)
            for invite in valid:
                url = _invite_url(invite)
                if url:
                    return InviteAvailability(
                        url=url,
                        source="existing",
                        can_create=can_create,
                        channel_name=channel_name,
                        manage_guild=True,
                        create_permission=can_create,
                        note="This is an existing invite for the server.",
                    )
            if invites is not None:
                reasons.append("No unexpired, unused existing invite is visible to the bot.")
    else:
        reasons.append("The bot needs Manage Server to list existing invites.")

    if can_create:
        reasons.append(f"The bot can create a new invite in {channel_name}.")
    else:
        reasons.append(
            "The bot cannot create an invite because it lacks Create Invite permission in a "
            "visible text channel."
        )

    return InviteAvailability(
        url=None,
        source=None,
        can_create=can_create,
        channel_name=channel_name,
        manage_guild=manage_guild,
        create_permission=can_create,
        note=" ".join(reasons).strip(),
    )


async def create_invite(bot, guild_id, actor_id) -> CreatedInvite:
    """Create a short-lived invite after re-checking owner authorisation."""
    if not is_owner(bot, actor_id):
        raise GuildActionError("Only the bot owner can create invites.")
    guild_id = parse_guild_id(guild_id)
    if guild_id is None:
        raise GuildActionError("That server ID is not valid.")
    try:
        guild = bot.get_guild(guild_id)
    except Exception:  # pragma: no cover - defensive
        log.warning("could not resolve guild %s", guild_id, exc_info=True)
        guild = None
    if guild is None:
        raise GuildActionError("The bot is no longer in that server, so no invite can be created.")
    if bool(getattr(guild, "unavailable", False)):
        raise GuildActionError("Discord has marked that server as unavailable. Try again later.")
    if bool(getattr(guild, "invites_disabled", False)):
        raise GuildActionError("Invites are disabled in that server.")

    channel = invite_channel(guild)
    if channel is None:
        raise GuildActionError(
            "The bot cannot create an invite: it lacks Create Invite permission in a visible text channel."
        )

    try:
        invite = await channel.create_invite(
            max_age=CREATED_INVITE_MAX_AGE,
            max_uses=0,
            temporary=False,
            unique=True,
            reason=f"Bot owner guild manager (user {parse_guild_id(actor_id)})",
        )
    except discord.Forbidden as exc:
        log.warning("invite creation forbidden in guild %s", guild_id)
        raise GuildActionError(
            "Discord refused to create an invite. The bot may have lost Create Invite or channel access."
        ) from exc
    except discord.HTTPException as exc:
        log.warning("invite creation failed in guild %s (HTTP %s)", guild_id, getattr(exc, "status", "?"))
        raise GuildActionError(
            f"Discord could not create an invite (HTTP {getattr(exc, 'status', '?')}). Try again later."
        ) from exc
    except asyncio.TimeoutError as exc:
        raise GuildActionError("Creating the invite timed out. Try again.") from exc
    except Exception as exc:
        log.warning("invite creation crashed in guild %s", guild_id, exc_info=True)
        raise GuildActionError("An unexpected error stopped the invite from being created.") from exc

    url = _invite_url(invite)
    if not url:
        raise GuildActionError("Discord created an invite but did not return a usable link.")
    log.info("owner %s created an invite in guild %s", parse_guild_id(actor_id), guild_id)
    return CreatedInvite(
        url=url,
        code=str(getattr(invite, "code", "") or ""),
        expires_at=getattr(invite, "expires_at", None),
        channel_name=channel_display_name(channel),
    )


# ---------------------------------------------------------------------------
# Leaving
# ---------------------------------------------------------------------------


async def leave_guild(bot, guild_id, actor_id) -> LeaveResult:
    """Make the bot leave a guild after re-checking owner authorisation.

    Owner membership in the target guild is deliberately irrelevant: the bot
    acts on its own membership, so the owner never has to join a server to
    remove the bot from it.
    """
    if not is_owner(bot, actor_id):
        raise GuildActionError("Only the bot owner can make the bot leave servers.")
    guild_id = parse_guild_id(guild_id)
    if guild_id is None:
        raise GuildActionError("That server ID is not valid.")

    try:
        guild = bot.get_guild(guild_id)
    except Exception:  # pragma: no cover - defensive
        log.warning("could not resolve guild %s", guild_id, exc_info=True)
        guild = None

    if guild is None:
        return LeaveResult(
            guild_id=guild_id,
            name=f"Server {guild_id}",
            left=False,
            already_left=True,
        )

    name = guild_display_name(guild)
    try:
        await guild.leave()
    except discord.NotFound:
        return LeaveResult(guild_id=guild_id, name=name, left=False, already_left=True)
    except discord.Forbidden as exc:
        log.warning("leaving guild %s was refused", guild_id)
        raise GuildActionError(
            "Discord refused to remove the bot from that server. It may already have left; "
            "refresh the server list to check."
        ) from exc
    except discord.HTTPException as exc:
        log.warning("leaving guild %s failed (HTTP %s)", guild_id, getattr(exc, "status", "?"))
        raise GuildActionError(
            f"Discord could not remove the bot from that server (HTTP {getattr(exc, 'status', '?')}). "
            "Try again later."
        ) from exc
    except asyncio.TimeoutError as exc:
        raise GuildActionError("The request to leave that server timed out. Try again.") from exc
    except Exception as exc:
        log.warning("leaving guild %s crashed", guild_id, exc_info=True)
        raise GuildActionError("An unexpected error stopped the bot from leaving that server.") from exc

    log.info("owner %s made the bot leave guild %s (%s)", parse_guild_id(actor_id), name, guild_id)
    return LeaveResult(guild_id=guild_id, name=name, left=True, already_left=False)
