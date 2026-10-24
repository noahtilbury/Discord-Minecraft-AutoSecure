"""Offline checks for the owner-only guild management feature.

No Discord connection, token or real guild is used. Fake guilds implement the
small py-cord surface the feature relies on, so the tests cover:

* configured-owner authorisation;
* name/ID search and pagination;
* owner-membership lookups and their failure modes;
* existing invite selection, permission limitations and invite creation;
* leaving a guild, including already-left and refused cases;
* the dashboard/detail embeds and view construction.

Run:  ./.venv/Scripts/python.exe tests/test_guilds.py
"""

import asyncio
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

import discord

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from cogs import guilds as guilds_cog  # noqa: E402
from shared import guild_admin as ga  # noqa: E402

logging.getLogger("bot").setLevel(logging.CRITICAL)

OWNER = 1171237589391511632
OTHER = 42
BOT_ID = 999


def check(condition, label):
    if not condition:
        raise AssertionError(label)
    print(f"[ok] {label}")


class FakeResponse:
    def __init__(self, status=404):
        self.status = status
        self.reason = "Not Found" if status == 404 else "Forbidden"
        self.headers = {}


def http_error(cls, status=404, code=10007):
    return cls(FakeResponse(status), {"code": code, "message": "test error"})


class FakeMember:
    def __init__(self, user_id, permissions=None):
        self.id = user_id
        self.guild_permissions = permissions or discord.Permissions.none()


class FakeInvite:
    def __init__(self, code, *, expires_at=None, max_uses=0, uses=0):
        self.code = code
        self.url = f"https://discord.gg/{code}"
        self.expires_at = expires_at
        self.max_uses = max_uses
        self.uses = uses


class FakeChannel:
    def __init__(self, name, *, position=0, can_view=True, can_create=True):
        self.name = name
        self.position = position
        self._permissions = discord.Permissions(
            view_channel=can_view,
            create_instant_invite=can_create,
        )
        self.create_calls = []
        self.invite_result = FakeInvite("created-by-test")
        self.create_error = None

    def permissions_for(self, member):
        return self._permissions

    async def create_invite(self, **kwargs):
        self.create_calls.append(kwargs)
        if self.create_error is not None:
            raise self.create_error
        return self.invite_result


class FakeGuild:
    def __init__(
        self,
        guild_id,
        name,
        *,
        member_count=1234,
        owner_id=OWNER,
        owner_is_member=True,
        unavailable=False,
        manage_guild=True,
        can_create=True,
        features=(),
        invites=None,
        invites_error=None,
        vanity=None,
        invites_disabled=False,
        leave_error=None,
        fetch_error=None,
    ):
        self.id = guild_id
        self.name = name
        self.member_count = member_count
        self.unavailable = unavailable
        self.features = set(features)
        self.invites_disabled = invites_disabled
        self._owner_id = owner_id
        self._cached_members = {BOT_ID}
        self._remote_members = {BOT_ID}
        if owner_is_member:
            self._cached_members.add(owner_id)
            self._remote_members.add(owner_id)
        self._me = FakeMember(
            BOT_ID,
            discord.Permissions(manage_guild=manage_guild),
        )
        self.text_channels = [FakeChannel("general", can_create=can_create)] if can_create else []
        self._invites = list(invites or [])
        self._invites_error = invites_error
        self._vanity = vanity
        self._leave_error = leave_error
        self._fetch_error = fetch_error
        self.leave_calls = 0
        self.fetch_calls = 0

    @property
    def me(self):
        return self._me

    def get_member(self, user_id):
        if user_id in self._cached_members:
            return FakeMember(user_id)
        return None

    async def fetch_member(self, user_id):
        self.fetch_calls += 1
        if self._fetch_error is not None:
            raise self._fetch_error
        if user_id in self._remote_members:
            return FakeMember(user_id)
        raise http_error(discord.NotFound)

    async def invites(self):
        if self._invites_error is not None:
            raise self._invites_error
        return list(self._invites)

    async def vanity_invite(self):
        return self._vanity

    async def leave(self):
        self.leave_calls += 1
        if self._leave_error is not None:
            raise self._leave_error


class FakeBot:
    def __init__(self, guilds=(), owners=()):
        self.guilds = list(guilds)
        self.admins = list(owners or ())

    def get_guild(self, guild_id):
        for guild in self.guilds:
            if int(guild.id) == int(guild_id):
                return guild
        return None


class FakeInteractionResponse:
    def __init__(self):
        self.done = False
        self.deferred = None
        self.sent = []
        self.edited = []
        self.original_edits = []

    def is_done(self):
        return self.done

    async def defer(self, *, ephemeral=False, invisible=True):
        self.deferred = {"ephemeral": ephemeral, "invisible": invisible}
        self.done = True

    async def send_message(self, content=None, *, embed=None, view=None, ephemeral=False, **extra):
        self.sent.append(
            {"content": content, "embed": embed, "view": view, "ephemeral": ephemeral, **extra}
        )
        self.done = True

    async def edit_message(self, **kwargs):
        self.edited.append(kwargs)
        self.done = True


class FakeFollowup:
    def __init__(self):
        self.sent = []

    async def send(self, content=None, **kwargs):
        self.sent.append({"content": content, **kwargs})
        return object()


class FakeInteraction:
    def __init__(self, user_id):
        self.user = FakeMember(user_id)
        self.id = 987654321
        self.guild_id = None
        self.message = None
        self.response = FakeInteractionResponse()
        self.followup = FakeFollowup()

    async def edit_original_response(self, **kwargs):
        self.response.original_edits.append(kwargs)
        return object()


def make_summary(guild_id=123, name="Test Server", members=1234, access=False, available=True):
    return ga.GuildSummary(
        guild_id=guild_id,
        name=name,
        member_count=members,
        owner_is_member=access,
        available=available,
    )


def make_page(summaries):
    return ga.GuildPage(
        query="",
        page=0,
        pages=2,
        total=len(summaries) + 4,
        per_page=10,
        summaries=tuple(summaries),
    )


def test_owner_auth():
    bot = FakeBot(owners=[OWNER, str(OTHER), 0])
    check(ga.is_owner(bot, OWNER), "configured integer owner is authorised")
    check(ga.is_owner(bot, str(OWNER)), "string form of an owner ID is authorised")
    check(ga.is_owner(bot, OTHER), "additional configured owner is authorised")
    check(not ga.is_owner(bot, 123456789), "unconfigured user is denied")
    check(not ga.is_owner(bot, 0), "placeholder owner 0 never authorises a user")
    check(not ga.is_owner(FakeBot(owners=[]), OWNER), "empty owner list denies everyone")
    check(not ga.is_owner(FakeBot(owners=None), OWNER), "missing owner list denies everyone")


def test_search_and_pagination():
    guilds = [
        FakeGuild(10, "Zulu"),
        FakeGuild(20, "alpha"),
        FakeGuild(30, "Beta Test"),
    ]
    check([g.name for g in ga.filter_guilds(guilds, "")] == ["alpha", "Beta Test", "Zulu"], "empty search sorts all guilds by name")
    check([g.name for g in ga.filter_guilds(guilds, "beta")] == ["Beta Test"], "name search is case-insensitive")
    check([g.name for g in ga.filter_guilds(guilds, "20")] == ["alpha"], "search matches a guild ID")
    check(ga.filter_guilds(guilds, "missing") == [], "missing search returns an empty list")

    check(ga.page_count(0) == 1, "zero results still have one page")
    check(ga.page_count(10) == 1, "ten results fit on one page")
    check(ga.page_count(11) == 2, "eleven results need two pages")
    check(ga.page_count(25) == 3, "twenty-five results need three pages")
    check(ga.clamp_page(99, 25) == 2, "page number is clamped to the last page")
    check(ga.clamp_page(-1, 25) == 0, "negative page number is clamped to zero")

    items, page = ga.page_slice(list(range(25)), 2, 10)
    check(items == list(range(20, 25)) and page == 2, "page slice returns the correct final page")


async def test_owner_membership():
    cached = FakeGuild(1, "Cached", owner_is_member=True)
    check(await ga.owner_membership(cached, OWNER) is True, "cached owner membership is a member")
    check(cached.fetch_calls == 0, "cached membership avoids an API call")

    remote = FakeGuild(2, "Remote", owner_is_member=True)
    remote._cached_members.clear()
    check(await ga.owner_membership(remote, OWNER) is True, "owner found through fetch_member is a member")
    check(remote.fetch_calls == 1, "uncached membership uses one member lookup")

    absent = FakeGuild(3, "Absent", owner_is_member=False)
    check(await ga.owner_membership(absent, OWNER) is False, "404 member lookup means not a member")

    forbidden = FakeGuild(4, "Forbidden", fetch_error=http_error(discord.Forbidden, 403, 50001))
    forbidden._cached_members.clear()
    check(await ga.owner_membership(forbidden, OWNER) is None, "refused member lookup is unknown, not 'not a member'")

    failed = FakeGuild(5, "Failed", fetch_error=http_error(discord.HTTPException, 500, 0))
    failed._cached_members.clear()
    check(await ga.owner_membership(failed, OWNER) is None, "API failure leaves membership unknown")

    unavailable = FakeGuild(6, "Unavailable", unavailable=True)
    check(await ga.owner_membership(unavailable, OWNER) is None, "unavailable guild membership is unknown")
    check(unavailable.fetch_calls == 0, "unavailable guilds are not queried")

    guilds = [FakeGuild(100 + i, f"Guild {i:02d}") for i in range(12)]
    directory = ga.GuildDirectory(FakeBot(guilds), per_page=10)
    first = await directory.page("", 0, owner_id=OWNER)
    second = await directory.page("", 1, owner_id=OWNER)
    check(first.total == 12 and first.pages == 2 and len(first.summaries) == 10, "first page lists ten of twelve guilds")
    check(second.total == 12 and second.page == 1 and len(second.summaries) == 2, "second page lists the remaining guilds")
    check(all(summary.member_count == 1234 for summary in first.summaries), "member counts are included when available")

    shared_guild = FakeGuild(200, "Shared", owner_id=OWNER, owner_is_member=True)
    shared_directory = ga.GuildDirectory(FakeBot([shared_guild], owners=[OWNER, OTHER]))
    first_owner = await shared_directory.page("", 0, owner_id=OWNER)
    second_owner = await shared_directory.page("", 0, owner_id=OTHER)
    check(first_owner.summaries[0].owner_is_member is True, "owner membership is reported for the first owner")
    check(second_owner.summaries[0].owner_is_member is False, "membership cache is not shared between configured owners")


async def test_invite_availability():
    vanity_guild = FakeGuild(
        10,
        "Vanity",
        features=("VANITY_URL",),
        vanity=FakeInvite("vanity-code"),
    )
    vanity = await ga.invite_availability(vanity_guild)
    check(vanity.url == "https://discord.gg/vanity-code" and vanity.source == "vanity", "vanity invite is returned when available")

    valid = FakeInvite("valid")
    expired = FakeInvite("expired", expires_at=datetime.now(timezone.utc) - timedelta(hours=1))
    maxed = FakeInvite("maxed", max_uses=5, uses=5)
    invites_guild = FakeGuild(11, "Invites", invites=[expired, maxed, valid])
    existing = await ga.invite_availability(invites_guild)
    check(existing.url == "https://discord.gg/valid" and existing.source == "existing", "only an unexpired, unused invite is shown")

    no_manage = FakeGuild(12, "No Manage", manage_guild=False, can_create=True)
    create_only = await ga.invite_availability(no_manage)
    check(create_only.url is None, "no URL is invented without an invite lookup")
    check(create_only.can_create is True and create_only.channel_name == "#general", "create permission is detected without Manage Server")
    check("Manage Server" in create_only.note and "can create" in create_only.note, "create-only limitation is explained")

    no_permissions = FakeGuild(13, "No Permissions", manage_guild=False, can_create=False)
    blocked = await ga.invite_availability(no_permissions)
    check(blocked.url is None and blocked.can_create is False, "no invite is offered without either permission")
    check("cannot create" in blocked.note, "missing Create Invite permission is explained")

    disabled = FakeGuild(14, "Disabled", invites_disabled=True, can_create=True)
    disabled_result = await ga.invite_availability(disabled)
    check(disabled_result.url is None and disabled_result.can_create is False, "disabled invites never show a link")

    lookup_failure = FakeGuild(
        15,
        "Lookup Failure",
        invites_error=http_error(discord.Forbidden, 403, 50001),
        can_create=True,
    )
    failed = await ga.invite_availability(lookup_failure)
    check(failed.url is None and failed.can_create is True, "invite lookup failure still offers legitimate creation")
    check("refused" in failed.note, "invite lookup refusal is reported")

    unavailable = await ga.invite_availability(FakeGuild(16, "Unavailable", unavailable=True))
    check(unavailable.url is None and not unavailable.can_create, "unavailable guild offers no invite")
    check("unavailable" in unavailable.note, "unavailable guild explains the missing data")


async def test_create_invite():
    channel_guild = FakeGuild(20, "Create", can_create=True)
    channel = channel_guild.text_channels[0]
    bot = FakeBot([channel_guild], owners=[OWNER])

    try:
        await ga.create_invite(bot, 20, OTHER)
    except ga.GuildActionError:
        check(channel.create_calls == [], "non-owner cannot create an invite")
    else:
        raise AssertionError("non-owner invite creation should fail")

    created = await ga.create_invite(bot, 20, OWNER)
    check(created.url == "https://discord.gg/created-by-test", "created invite returns Discord's real URL")
    check(created.channel_name == "#general", "created invite reports its channel")
    check(len(channel.create_calls) == 1, "one invite is created")
    call = channel.create_calls[0]
    check(call["max_age"] == ga.CREATED_INVITE_MAX_AGE, "created invite has the configured short lifetime")
    check(call["max_uses"] == 0 and call["temporary"] is False, "created invite is not user-limited or temporary-membership")
    check(str(OWNER) in call["reason"], "audit reason identifies the owner")

    try:
        await ga.create_invite(bot, 999, OWNER)
    except ga.GuildActionError:
        check(True, "missing guild cannot create an invite")
    else:
        raise AssertionError("missing guild invite creation should fail")

    no_channel = FakeGuild(21, "No Channel", can_create=False)
    try:
        await ga.create_invite(FakeBot([no_channel], owners=[OWNER]), 21, OWNER)
    except ga.GuildActionError:
        check(True, "guild without Create Invite permission is refused")
    else:
        raise AssertionError("permissionless invite creation should fail")

    failing = FakeGuild(22, "Failing", can_create=True)
    failing.text_channels[0].create_error = http_error(discord.Forbidden, 403, 50013)
    try:
        await ga.create_invite(FakeBot([failing], owners=[OWNER]), 22, OWNER)
    except ga.GuildActionError:
        check(True, "Discord refusal during invite creation is reported safely")
    else:
        raise AssertionError("failed invite creation should raise a user-facing error")

    disabled = FakeGuild(23, "Disabled", invites_disabled=True)
    try:
        await ga.create_invite(FakeBot([disabled], owners=[OWNER]), 23, OWNER)
    except ga.GuildActionError:
        check(True, "guild with invites disabled refuses creation")
    else:
        raise AssertionError("disabled invites should refuse creation")


async def test_leave_guild():
    guild = FakeGuild(30, "Leave Me")
    bot = FakeBot([guild], owners=[OWNER])

    try:
        await ga.leave_guild(bot, 30, OTHER)
    except ga.GuildActionError:
        check(guild.leave_calls == 0, "non-owner cannot make the bot leave")
    else:
        raise AssertionError("non-owner leave should fail")

    result = await ga.leave_guild(bot, 30, OWNER)
    check(result.left is True and result.already_left is False, "owner can make the bot leave")
    check(guild.leave_calls == 1, "the guild leave endpoint is called once")

    missing = await ga.leave_guild(FakeBot([], owners=[OWNER]), 30, OWNER)
    check(missing.already_left is True and missing.left is False, "server absent from bot.guilds is reported as already left")
    check(missing.name == "Server 30", "already-left result has a readable fallback name")

    gone = FakeGuild(31, "Gone", leave_error=http_error(discord.NotFound, 404, 10004))
    gone_result = await ga.leave_guild(FakeBot([gone], owners=[OWNER]), 31, OWNER)
    check(gone_result.already_left is True, "Discord 404 while leaving is treated as already left")

    refused = FakeGuild(32, "Refused", leave_error=http_error(discord.Forbidden, 403, 50001))
    try:
        await ga.leave_guild(FakeBot([refused], owners=[OWNER]), 32, OWNER)
    except ga.GuildActionError:
        check(True, "Discord refusal while leaving is reported safely")
    else:
        raise AssertionError("refused leave should raise a user-facing error")

    unavailable = FakeGuild(33, "Unavailable", unavailable=True)
    unavailable_result = await ga.leave_guild(FakeBot([unavailable], owners=[OWNER]), 33, OWNER)
    check(unavailable_result.left is True and unavailable.leave_calls == 1, "unavailable guild can still be left by id")

    try:
        await ga.leave_guild(FakeBot([], owners=[OWNER]), "not-an-id", OWNER)
    except ga.GuildActionError:
        check(True, "invalid guild id is rejected without crashing")
    else:
        raise AssertionError("invalid guild id should raise a user-facing error")


def test_embeds():
    summaries = [
        make_summary(101, "Alpha", 1234, True, True),
        make_summary(102, "Beta", None, False, False),
    ]
    page = make_page(summaries)
    embed = guilds_cog.build_list_embed(page)
    check("Alpha" in embed.description and "`101`" in embed.description, "list shows server name and ID")
    check("Members: 1,234" in embed.description and "Members: unknown" in embed.description, "list shows member counts when available")
    check("You: Member" in embed.description and "You: Not a member" in embed.description, "list shows personal access")
    check("Unavailable to the bot" in embed.description, "list marks unavailable guilds")
    check("Page 1/2" in embed.footer.text, "list footer shows pagination")

    query_page = ga.GuildPage("alpha", 0, 1, 0, 10, ())
    query_embed = guilds_cog.build_list_embed(query_page)
    check("No server matches" in query_embed.description, "empty filtered list has a clear message")

    url_availability = ga.InviteAvailability(
        "https://discord.gg/real-code", "existing", False, None, True, False, "existing"
    )
    detail = guilds_cog.build_detail_embed(summaries[0], url_availability)
    check("https://discord.gg/real-code" in detail.fields[-1].value, "detail shows a real invite URL")

    blocked = ga.InviteAvailability(
        None, None, False, None, False, False,
        "The bot needs Manage Server to list existing invites. The bot cannot create an invite because it lacks Create Invite permission in a visible text channel.",
    )
    blocked_detail = guilds_cog.build_detail_embed(
        make_summary(103, "No Invite", 10, False, True), blocked
    )
    invite_value = blocked_detail.fields[-1].value
    check("You are not a member" in invite_value, "detail explains owner is not a member")
    check("no invite can be provided" in invite_value.lower(), "detail clearly explains the invite limitation")

    notice = guilds_cog.build_notice_embed("Title", "Description")
    check(notice.title == "Title" and notice.description == "Description", "notice embed carries the given text")


async def test_views():
    bot = FakeBot([], owners=[OWNER])
    cog = guilds_cog.GuildManagement(bot)
    page = make_page([make_summary(101, "Alpha", 10, True, True)])
    dashboard = guilds_cog.GuildDashboard(cog, OWNER, page)
    labels = [getattr(child, "label", None) for child in dashboard.children]
    check(dashboard.owner_id == OWNER, "dashboard is tied to the invoking owner")
    check(len(dashboard.children) == 6, "dashboard has a server select and five navigation buttons")
    check(all(label in labels for label in ("First", "Previous", "Search", "Next", "Last")), "dashboard exposes all navigation actions")
    select = next(child for child in dashboard.children if isinstance(child, discord.ui.Select))
    check(select.options[0].value == "101", "dashboard select uses guild IDs")
    check(select.options[0].description.startswith("ID 101"), "dashboard select describes the guild")

    availability = ga.InviteAvailability(
        "https://discord.gg/real-code", "existing", False, None, True, False, "existing"
    )
    empty_page = ga.GuildPage("missing", 0, 1, 0, 10, ())
    empty_dashboard = guilds_cog.GuildDashboard(cog, OWNER, empty_page)
    check(
        len(empty_dashboard.children) == 5
        and not any(isinstance(child, discord.ui.Select) for child in empty_dashboard.children),
        "empty search omits the select but keeps navigation",
    )
    check(len(dashboard.to_components()) == 2, "dashboard serialises into select and navigation rows")

    detail = guilds_cog.GuildDetailView(
        cog,
        OWNER,
        make_summary(101, "Alpha"),
        availability,
        query="",
        page=0,
    )
    detail_labels = [getattr(child, "label", None) for child in detail.children]
    check("Create invite" not in detail_labels, "existing invite hides the create button")
    check("Leave server" in detail_labels and "Back to servers" in detail_labels, "detail exposes leave and back")

    create_available = ga.InviteAvailability(
        None, None, True, "#general", False, True, "The bot can create a new invite in #general."
    )
    detail_create = guilds_cog.GuildDetailView(
        cog,
        OWNER,
        make_summary(104, "Create Me"),
        create_available,
        query="",
        page=0,
    )
    create_labels = [getattr(child, "label", None) for child in detail_create.children]
    check("Create invite" in create_labels, "detail offers invite creation when permitted")

    confirm = guilds_cog.GuildLeaveConfirmView(
        cog, OWNER, make_summary(101, "Alpha"), query="", page=0
    )
    confirm_labels = [getattr(child, "label", None) for child in confirm.children]
    check("Confirm leave" in confirm_labels and "Cancel" in confirm_labels, "leave confirmation requires an explicit action")

    result_view = guilds_cog.GuildResultView(cog, OWNER, query="", page=0)
    check([getattr(child, "label", None) for child in result_view.children] == ["Back to servers"], "result view offers a way back")

    modal = guilds_cog.GuildSearchModal(cog, OWNER, "alpha")
    check(modal.title == "Search bot servers", "search modal has a clear title")
    check(modal.query_input.value == "alpha", "search modal pre-fills the current query")

    class FakeCtx:
        author = FakeMember(OWNER)

    check(cog._command_authorized(FakeCtx()) is True, "command authorisation accepts the configured owner")

    class BadCtx:
        author = FakeMember(OTHER)

    check(cog._command_authorized(BadCtx()) is False, "command authorisation rejects other users")

    class FakeInteraction:
        user = FakeMember(OWNER)

    class BadInteraction:
        user = FakeMember(OTHER)

    check(cog._interaction_authorized(FakeInteraction(), OWNER) is True, "interaction authorisation accepts the exact owner")
    check(cog._interaction_authorized(BadInteraction(), OWNER) is False, "interaction authorisation rejects other users")
    check(cog._interaction_authorized(FakeInteraction(), OTHER) is False, "interaction authorisation rejects a different owner id")

    check(
        guilds_cog.GuildManagement.guilds.name == guilds_cog.name,
        "command group is registered under the configured alias",
    )
    check(
        "list" in [command.name for command in guilds_cog.GuildManagement.guilds.subcommands],
        "guild list subcommand is registered",
    )


async def test_cog_flows():
    manage_guild = FakeGuild(
        301,
        "Manage Me",
        invites=[FakeInvite("existing-code")],
        can_create=True,
    )
    bot = FakeBot([manage_guild], owners=[OWNER])
    cog = guilds_cog.GuildManagement(bot)

    interaction = FakeInteraction(OWNER)
    await cog.show_list(interaction, owner_id=OWNER, query="", page=0)
    check(interaction.response.deferred is not None, "owner page navigation is deferred")
    check(len(interaction.response.original_edits) == 1, "owner page navigation edits the dashboard")
    page_edit = interaction.response.original_edits[-1]
    check(isinstance(page_edit["view"], guilds_cog.GuildDashboard), "page navigation sends a dashboard view")
    check("Manage Me" in page_edit["embed"].description, "page navigation shows the guild")

    denied = FakeInteraction(OTHER)
    await cog.show_list(denied, owner_id=OWNER, query="", page=0)
    check(denied.response.deferred is None, "non-owner page navigation is not acknowledged as a dashboard")
    check(len(denied.response.sent) == 1, "non-owner page navigation gets one denial")
    check("permission" in denied.response.sent[0]["content"].lower(), "non-owner denial explains the restriction")

    detail_interaction = FakeInteraction(OWNER)
    await cog.show_detail(
        detail_interaction,
        owner_id=OWNER,
        guild_id=manage_guild.id,
        query="",
        page=0,
    )
    detail_edit = detail_interaction.response.original_edits[-1]
    check(isinstance(detail_edit["view"], guilds_cog.GuildDetailView), "detail sends a management view")
    check("https://discord.gg/existing-code" in str(detail_edit["embed"].to_dict()), "detail shows a real existing invite")

    missing_interaction = FakeInteraction(OWNER)
    await cog.show_detail(
        missing_interaction,
        owner_id=OWNER,
        guild_id=999999,
        query="",
        page=0,
    )
    missing_edit = missing_interaction.response.original_edits[-1]
    check("already left" in missing_edit["embed"].title.lower(), "detail for a missing guild is handled as already left")

    leave_interaction = FakeInteraction(OWNER)
    await cog.leave_guild_and_report(
        leave_interaction,
        owner_id=OWNER,
        guild_id=manage_guild.id,
        query="",
        page=0,
    )
    leave_edit = leave_interaction.response.original_edits[-1]
    check(manage_guild.leave_calls == 1, "leave flow calls the guild leave endpoint")
    check(leave_edit["embed"].title == "Left server", "leave flow reports success")

    already_bot = FakeBot([], owners=[OWNER])
    already_cog = guilds_cog.GuildManagement(already_bot)
    already_interaction = FakeInteraction(OWNER)
    await already_cog.leave_guild_and_report(
        already_interaction,
        owner_id=OWNER,
        guild_id=manage_guild.id,
        query="",
        page=0,
    )
    already_edit = already_interaction.response.original_edits[-1]
    check(already_edit["embed"].title == "Server already left", "already-left guild is reported without error")

    refused_guild = FakeGuild(
        302,
        "Refused",
        leave_error=http_error(discord.Forbidden, 403, 50001),
    )
    refused_cog = guilds_cog.GuildManagement(FakeBot([refused_guild], owners=[OWNER]))
    refused_interaction = FakeInteraction(OWNER)
    await refused_cog.leave_guild_and_report(
        refused_interaction,
        owner_id=OWNER,
        guild_id=refused_guild.id,
        query="",
        page=0,
    )
    refused_edit = refused_interaction.response.original_edits[-1]
    check(refused_edit["embed"].title == "Could not leave server", "leave refusal is reported safely")

    create_guild = FakeGuild(303, "Create Me", can_create=True)
    create_cog = guilds_cog.GuildManagement(FakeBot([create_guild], owners=[OWNER]))
    create_interaction = FakeInteraction(OWNER)
    await create_cog.create_invite_for_guild(
        create_interaction,
        owner_id=OWNER,
        guild_id=create_guild.id,
        guild_name=create_guild.name,
        query="",
        page=0,
    )
    create_edit = create_interaction.response.original_edits[-1]
    check(len(create_guild.text_channels[0].create_calls) == 1, "create-invite flow creates one invite")
    check(create_edit["embed"].title == "Invite created", "create-invite flow reports success")
    check("https://discord.gg/created-by-test" in create_edit["embed"].description, "created invite link is shown")

    no_create_guild = FakeGuild(304, "No Create", can_create=False)
    no_create_cog = guilds_cog.GuildManagement(FakeBot([no_create_guild], owners=[OWNER]))
    no_create_interaction = FakeInteraction(OWNER)
    await no_create_cog.create_invite_for_guild(
        no_create_interaction,
        owner_id=OWNER,
        guild_id=no_create_guild.id,
        guild_name=no_create_guild.name,
        query="",
        page=0,
    )
    no_create_edit = no_create_interaction.response.original_edits[-1]
    check(no_create_edit["embed"].title == "Could not create invite", "missing invite permission is reported safely")


async def async_main():
    test_owner_auth()
    test_search_and_pagination()
    await test_owner_membership()
    await test_invite_availability()
    await test_create_invite()
    await test_leave_guild()
    test_embeds()
    await test_views()
    await test_cog_flows()


def main() -> int:
    asyncio.run(async_main())
    print("\nGUILD MANAGEMENT TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
