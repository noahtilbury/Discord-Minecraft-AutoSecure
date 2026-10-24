"""Owner-only guild management dashboard.

``/guilds list`` opens an ephemeral dashboard listing every guild the bot is
currently connected to. The dashboard can page and search, show whether the
configured owner is a member of each server, display or create invites, and
make the bot leave a server.

Every entry point checks the configured owner list server-side: the slash
command, every view check, and the mutating service functions themselves. The
bot token is never read, logged or returned here.
"""

from __future__ import annotations

import logging

import discord
from discord.ext import commands

from shared import interactions
from shared.guild_admin import (
    CreatedInvite,
    GuildActionError,
    GuildDirectory,
    GuildPage,
    GuildSummary,
    InviteAvailability,
    create_invite,
    invite_availability,
    is_owner,
    leave_guild,
    summary_from_guild,
)
from shared.settings import command_alias
from ui import theme

log = logging.getLogger("bot")

name = command_alias("guilds")
VIEW_TIMEOUT = 30 * 60


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _member_text(count: int | None) -> str:
    return f"{count:,}" if count is not None else "unknown"


def _access_text(value: bool | None) -> str:
    if value is True:
        return "Member"
    if value is False:
        return "Not a member"
    return "Unknown"


def _safe(text: str) -> str:
    """Make guild names safe inside markdown and for mention parsing."""
    return discord.utils.escape_mentions(
        discord.utils.escape_markdown(str(text or ""))
    )


def build_list_embed(data: GuildPage) -> discord.Embed:
    """The paginated server list card."""
    query = str(data.query or "").strip()
    title = "Bot servers"
    if query:
        title = f"Bot servers matching \u201c{_safe(query[:60])}\u201d"
    embed = discord.Embed(title=title, color=theme.INFO)

    if data.total == 0:
        description = (
            "No server matches that search."
            if query
            else "The bot is not connected to any servers."
        )
    else:
        lines = []
        start = data.page * data.per_page + 1
        for offset, item in enumerate(data.summaries):
            status = "" if item.available else "\n\u26a0\ufe0f Unavailable to the bot right now"
            lines.append(
                f"**{start + offset}. {_safe(item.name)}**\n"
                f"`{item.guild_id}` \u2022 Members: {_member_text(item.member_count)} "
                f"\u2022 You: {_access_text(item.owner_is_member)}{status}"
            )
        description = "\n".join(lines)

    embed.description = description[:4096]
    embed.set_footer(
        text=f"Page {data.page + 1}/{data.pages} \u2022 {data.total} server(s) \u2022 Owner-only"
    )
    return embed


def _invite_text(summary: GuildSummary, availability: InviteAvailability) -> str:
    if availability.url:
        source = {
            "vanity": "Existing vanity invite.",
            "existing": "Existing server invite.",
        }.get(availability.source or "", "Invite returned by Discord.")
        return f"{availability.url}\n{source}"

    parts: list[str] = []
    if summary.owner_is_member is False:
        parts.append("You are not a member of this server.")
    elif summary.owner_is_member is None:
        parts.append("The bot could not confirm whether you are a member of this server.")

    parts.append(availability.note or "No invite link is available from Discord's current data.")
    if availability.can_create:
        parts.append("Use the **Create invite** button below to generate a new invite.")
    elif summary.owner_is_member is False:
        parts.append("The bot also lacks permission to create one, so no invite can be provided.")
    else:
        parts.append("The bot cannot create one with its current permissions.")
    return " ".join(part for part in parts if part)[:1024]


def build_detail_embed(summary: GuildSummary, availability: InviteAvailability) -> discord.Embed:
    """One server's details and invite status."""
    embed = discord.Embed(
        title=f"Server: {_safe(summary.name)}",
        color=theme.INFO if summary.available else theme.YELLOW,
    )
    embed.add_field(name="Server ID", value=f"`{summary.guild_id}`", inline=True)
    embed.add_field(name="Members", value=_member_text(summary.member_count), inline=True)
    embed.add_field(name="Your access", value=_access_text(summary.owner_is_member), inline=True)

    if summary.available:
        manage = "Yes" if availability.manage_guild else "No"
        create = (
            f"Yes ({availability.channel_name})"
            if availability.can_create
            else "No"
        )
    else:
        manage = "Unknown (server unavailable)"
        create = "Unknown (server unavailable)"
    embed.add_field(
        name="Bot permissions",
        value=f"Manage Server: {manage}\nCreate Invite: {create}",
        inline=False,
    )
    embed.add_field(name="Invite", value=_invite_text(summary, availability), inline=False)
    if not summary.available:
        embed.add_field(
            name="Status",
            value="Discord has not sent usable details for this server. Leaving still works.",
            inline=False,
        )
    embed.set_footer(text="Owner-only \u2022 Live data from Discord")
    return embed


def build_notice_embed(title: str, description: str, *, color: int | None = None) -> discord.Embed:
    return discord.Embed(
        title=str(title)[:256],
        description=str(description or "")[:4096],
        color=theme.INFO if color is None else color,
    )


def _invite_fallback_note() -> InviteAvailability:
    return InviteAvailability(
        url=None,
        source=None,
        can_create=False,
        channel_name=None,
        manage_guild=False,
        create_permission=False,
        note="The invite lookup failed unexpectedly. Try again later.",
    )


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------


class OwnerView(discord.ui.View):
    """Base view that only the owner who opened it may use."""

    def __init__(self, cog: "GuildManagement", owner_id: int, *, timeout: float = VIEW_TIMEOUT):
        super().__init__(timeout=timeout)
        self.cog = cog
        self.owner_id = int(owner_id)
        self.message: discord.Message | None = None

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if self.cog._interaction_authorized(interaction, self.owner_id):
            return True
        log.warning(
            "denied guild dashboard interaction from %s (owner %s)",
            getattr(getattr(interaction, "user", None), "id", "?"),
            self.owner_id,
        )
        await interactions.respond(
            interaction,
            "You do not have permission to use this dashboard.",
            ephemeral=True,
        )
        return False

    async def on_timeout(self) -> None:
        log.info("guild management dashboard for owner %s expired", self.owner_id)
        self.message = None


class GuildSelect(discord.ui.Select):
    def __init__(self, dashboard: "GuildDashboard", data: GuildPage):
        options = [
            discord.SelectOption(
                label=item.name[:100] or f"Server {item.guild_id}",
                value=str(item.guild_id),
                description=(
                    f"ID {item.guild_id} \u2022 You: {_access_text(item.owner_is_member)}"
                )[:100],
            )
            for item in data.summaries
        ]
        super().__init__(
            placeholder="Select a server to manage",
            min_values=1,
            max_values=1,
            options=options,
            row=0,
        )
        self.dashboard = dashboard

    async def callback(self, interaction: discord.Interaction) -> None:
        try:
            guild_id = int(self.values[0])
        except (IndexError, TypeError, ValueError):
            await interactions.respond(interaction, "That server selection is not valid.", ephemeral=True)
            return
        await self.dashboard.cog.show_detail(
            interaction,
            owner_id=self.dashboard.owner_id,
            guild_id=guild_id,
            query=self.dashboard.query,
            page=self.dashboard.page,
        )


class GuildDashboard(OwnerView):
    """Paginated server list with a page-scoped select menu."""

    def __init__(self, cog: "GuildManagement", owner_id: int, data: GuildPage):
        super().__init__(cog, owner_id, timeout=VIEW_TIMEOUT)
        self.query = data.query
        self.page = data.page
        self._add_items(data)

    def _add_items(self, data: GuildPage) -> None:
        if data.summaries:
            self.add_item(GuildSelect(self, data))

        first = self._nav_button("First", 0, disabled=data.page <= 0)
        previous = self._nav_button("Previous", data.page - 1, disabled=data.page <= 0)
        search = discord.ui.Button(
            label="Search",
            style=discord.ButtonStyle.primary,
            row=1,
        )
        search.callback = self._search
        next_ = self._nav_button(
            "Next", data.page + 1, disabled=data.page >= data.pages - 1
        )
        last = self._nav_button("Last", data.pages - 1, disabled=data.page >= data.pages - 1)
        for item in (first, previous, search, next_, last):
            self.add_item(item)

    def _nav_button(self, label: str, target: int, *, disabled: bool) -> discord.ui.Button:
        button = discord.ui.Button(
            label=label,
            style=discord.ButtonStyle.secondary,
            disabled=disabled,
            row=1,
        )

        async def callback(interaction: discord.Interaction) -> None:
            await self.cog.show_list(
                interaction,
                owner_id=self.owner_id,
                query=self.query,
                page=target,
            )

        button.callback = callback
        return button

    async def _search(self, interaction: discord.Interaction) -> None:
        if not self.cog._interaction_authorized(interaction, self.owner_id):
            await interactions.respond(
                interaction, "You do not have permission to use this dashboard.", ephemeral=True
            )
            return
        modal = GuildSearchModal(self.cog, self.owner_id, self.query)
        await interactions.send_modal(interaction, modal)


class GuildSearchModal(discord.ui.Modal):
    def __init__(self, cog: "GuildManagement", owner_id: int, current_query: str = ""):
        super().__init__(title="Search bot servers")
        self.cog = cog
        self.owner_id = int(owner_id)
        self.query_input = discord.ui.InputText(
            label="Server name or ID",
            placeholder="Leave blank to show every server",
            required=False,
            max_length=100,
            value=str(current_query or "")[:100],
        )
        self.add_item(self.query_input)

    async def callback(self, interaction: discord.Interaction) -> None:
        if not self.cog._interaction_authorized(interaction, self.owner_id):
            log.warning(
                "denied guild search from %s (owner %s)",
                getattr(getattr(interaction, "user", None), "id", "?"),
                self.owner_id,
            )
            await interactions.respond(
                interaction, "You do not have permission to search the bot's servers.", ephemeral=True
            )
            return

        # A modal submit cannot edit the parent dashboard reliably, so it gets
        # its own ephemeral result message. The first response is a short
        # placeholder that is replaced once the page has been built.
        if not await interactions.respond(interaction, "Searching the bot's server list\u2026", ephemeral=True):
            return

        query = str(self.query_input.value or "").strip()
        try:
            data = await self.cog.directory.page(query, 0, owner_id=self.owner_id)
        except Exception:
            log.exception("guild search failed")
            await interactions.edit_original(
                interaction,
                content=None,
                embed=build_notice_embed(
                    "Could not search servers",
                    "The bot could not read its server list. Try again in a moment.",
                    color=theme.RED,
                ),
                view=None,
            )
            return

        view = GuildDashboard(self.cog, self.owner_id, data)
        if not await interactions.edit_original(
            interaction,
            content=None,
            embed=build_list_embed(data),
            view=view,
        ):
            log.warning("could not show guild search results for owner %s", self.owner_id)


class GuildDetailView(OwnerView):
    """One server's actions: create invite, leave, back."""

    def __init__(
        self,
        cog: "GuildManagement",
        owner_id: int,
        summary: GuildSummary,
        availability: InviteAvailability,
        *,
        query: str,
        page: int,
    ):
        super().__init__(cog, owner_id, timeout=VIEW_TIMEOUT)
        self.summary = summary
        self.availability = availability
        self.query = query
        self.page = page

        if availability.url is None and availability.can_create:
            create = discord.ui.Button(label="Create invite", style=discord.ButtonStyle.success)
            create.callback = self._create_invite
            self.add_item(create)

        leave = discord.ui.Button(label="Leave server", style=discord.ButtonStyle.danger)
        leave.callback = self._leave
        self.add_item(leave)

        back = discord.ui.Button(label="Back to servers", style=discord.ButtonStyle.secondary)
        back.callback = self._back
        self.add_item(back)

    async def _create_invite(self, interaction: discord.Interaction) -> None:
        await self.cog.create_invite_for_guild(
            interaction,
            owner_id=self.owner_id,
            guild_id=self.summary.guild_id,
            guild_name=self.summary.name,
            query=self.query,
            page=self.page,
        )

    async def _leave(self, interaction: discord.Interaction) -> None:
        if not self.cog._interaction_authorized(interaction, self.owner_id):
            await interactions.respond(
                interaction, "You do not have permission to manage this server.", ephemeral=True
            )
            return
        view = GuildLeaveConfirmView(
            self.cog,
            self.owner_id,
            self.summary,
            query=self.query,
            page=self.page,
        )
        description = (
            f"The bot will leave **{_safe(self.summary.name)}** (`{self.summary.guild_id}`) "
            "immediately.\n\n"
            "You do not need to be a member of this server. To undo this, invite the bot "
            "again with a new invite."
        )
        await self.cog._update(
            interaction,
            embed=build_notice_embed(
                f"Leave {_safe(self.summary.name)}?",
                description,
                color=theme.YELLOW,
            ),
            view=view,
        )

    async def _back(self, interaction: discord.Interaction) -> None:
        await self.cog.show_list(
            interaction,
            owner_id=self.owner_id,
            query=self.query,
            page=self.page,
        )


class GuildLeaveConfirmView(OwnerView):
    def __init__(
        self,
        cog: "GuildManagement",
        owner_id: int,
        summary: GuildSummary,
        *,
        query: str,
        page: int,
    ):
        super().__init__(cog, owner_id, timeout=VIEW_TIMEOUT)
        self.summary = summary
        self.query = query
        self.page = page

        confirm = discord.ui.Button(label="Confirm leave", style=discord.ButtonStyle.danger)
        confirm.callback = self._confirm
        self.add_item(confirm)
        cancel = discord.ui.Button(label="Cancel", style=discord.ButtonStyle.secondary)
        cancel.callback = self._cancel
        self.add_item(cancel)

    async def _confirm(self, interaction: discord.Interaction) -> None:
        await self.cog.leave_guild_and_report(
            interaction,
            owner_id=self.owner_id,
            guild_id=self.summary.guild_id,
            query=self.query,
            page=self.page,
        )

    async def _cancel(self, interaction: discord.Interaction) -> None:
        await self.cog.show_detail(
            interaction,
            owner_id=self.owner_id,
            guild_id=self.summary.guild_id,
            query=self.query,
            page=self.page,
        )


class GuildResultView(OwnerView):
    """A one-action view for notices and action results."""

    def __init__(
        self,
        cog: "GuildManagement",
        owner_id: int,
        *,
        query: str,
        page: int,
        label: str = "Back to servers",
    ):
        super().__init__(cog, owner_id, timeout=VIEW_TIMEOUT)
        self.query = query
        self.page = page

        back = discord.ui.Button(label=label, style=discord.ButtonStyle.secondary)
        back.callback = self._back
        self.add_item(back)

    async def _back(self, interaction: discord.Interaction) -> None:
        await self.cog.show_list(
            interaction,
            owner_id=self.owner_id,
            query=self.query,
            page=self.page,
        )


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class GuildManagement(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.directory = GuildDirectory(bot)

    guilds = discord.SlashCommandGroup(
        name,
        "Owner-only management of the servers the bot is in",
    )

    @guilds.command(
        name="list",
        description="Browse every server the bot is in and manage invites or leave (owner only)",
    )
    async def list_servers(
        self,
        ctx: discord.ApplicationContext,
        query: str = discord.Option(
            description="Filter by server name or ID (optional)",
            required=False,
            default="",
            max_length=100,
        ),
    ):
        if not self._command_authorized(ctx):
            log.warning(
                "denied /%s command from %s",
                name,
                getattr(getattr(ctx, "author", None), "id", "?"),
            )
            await interactions.respond(
                ctx,
                "You do not have permission to execute this command!",
                ephemeral=True,
            )
            return

        if not await interactions.defer(ctx, ephemeral=True):
            return

        try:
            data = await self.directory.page(str(query or ""), 0, owner_id=ctx.author.id)
        except Exception:
            log.exception("could not build the bot server list")
            await interactions.followup(
                ctx,
                "The bot could not read its server list. Try again in a moment.",
                ephemeral=True,
            )
            return

        view = GuildDashboard(self, ctx.author.id, data)
        message = await interactions.followup_message(
            ctx,
            embed=build_list_embed(data),
            view=view,
            ephemeral=True,
        )
        if message is not None:
            view.message = message

    # ------------------------------------------------------------------
    # Authorisation
    # ------------------------------------------------------------------

    def _command_authorized(self, ctx) -> bool:
        author = getattr(ctx, "author", None)
        return is_owner(self.bot, getattr(author, "id", None))

    def _interaction_authorized(self, interaction, owner_id) -> bool:
        user = getattr(interaction, "user", None)
        user_id = getattr(user, "id", None)
        return (
            user_id is not None
            and int(user_id) == int(owner_id)
            and is_owner(self.bot, user_id)
        )

    async def _require_interaction_owner(self, interaction, owner_id) -> bool:
        if self._interaction_authorized(interaction, owner_id):
            return True
        log.warning(
            "denied guild management action from %s (owner %s)",
            getattr(getattr(interaction, "user", None), "id", "?"),
            owner_id,
        )
        await interactions.respond(
            interaction,
            "You do not have permission to manage the bot's servers.",
            ephemeral=True,
        )
        return False

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    async def _update(self, interaction, *, embed: discord.Embed, view=None) -> bool:
        """Edit the dashboard message, using the interaction safely.

        Component interactions are deferred before this is called. If Discord
        has already acknowledged the interaction, the original response is
        edited; if that is impossible (for example an expired token), a
        follow-up is attempted instead. No failure is allowed to escape and
        take down the bot.
        """
        acknowledged = bool(getattr(interaction, "response", None)) and interaction.response.is_done()
        try:
            if acknowledged:
                if await interactions.edit_original(interaction, embed=embed, view=view):
                    return True
            elif await interactions.edit(interaction, embed=embed, view=view):
                return True
        except Exception:
            log.warning("could not update the guild manager message", exc_info=True)

        try:
            return await interactions.followup(
                interaction, embed=embed, view=view, ephemeral=True
            )
        except Exception:
            log.warning("could not send a guild manager fallback message", exc_info=True)
            return False

    # ------------------------------------------------------------------
    # Pages and details
    # ------------------------------------------------------------------

    async def show_list(self, interaction, *, owner_id, query: str, page: int) -> None:
        if not await self._require_interaction_owner(interaction, owner_id):
            return
        if not await interactions.defer(interaction):
            return
        try:
            data = await self.directory.page(query, page, owner_id=owner_id)
        except Exception:
            log.exception("could not build guild page %s", page)
            await self._update(
                interaction,
                embed=build_notice_embed(
                    "Could not read servers",
                    "The bot could not read its server list. Try again in a moment.",
                    color=theme.RED,
                ),
                view=GuildResultView(self, owner_id, query=query, page=page),
            )
            return

        view = GuildDashboard(self, owner_id, data)
        await self._update(interaction, embed=build_list_embed(data), view=view)

    async def show_detail(self, interaction, *, owner_id, guild_id: int, query: str, page: int) -> None:
        if not await self._require_interaction_owner(interaction, owner_id):
            return
        if not await interactions.defer(interaction):
            return

        try:
            guild = self.bot.get_guild(int(guild_id))
        except Exception:
            log.warning("could not resolve guild %s", guild_id, exc_info=True)
            guild = None

        if guild is None:
            await self._update(
                interaction,
                embed=build_notice_embed(
                    "Server already left",
                    f"The bot is no longer in **Server {guild_id}**. It may already have been "
                    "left; refresh the server list to see the current servers.",
                    color=theme.YELLOW,
                ),
                view=GuildResultView(self, owner_id, query=query, page=page),
            )
            return

        try:
            summary = await self.directory.summary(guild, owner_id=owner_id, force=True)
        except Exception:
            log.warning("could not build details for guild %s", guild_id, exc_info=True)
            summary = summary_from_guild(guild, None)

        try:
            availability = await invite_availability(guild)
        except Exception:
            log.warning("invite lookup failed for guild %s", guild_id, exc_info=True)
            availability = _invite_fallback_note()

        view = GuildDetailView(
            self,
            owner_id,
            summary,
            availability,
            query=query,
            page=page,
        )
        await self._update(interaction, embed=build_detail_embed(summary, availability), view=view)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    async def create_invite_for_guild(
        self, interaction, *, owner_id, guild_id: int, guild_name: str, query: str, page: int
    ) -> None:
        if not await self._require_interaction_owner(interaction, owner_id):
            return
        if not await interactions.defer(interaction):
            return

        try:
            created: CreatedInvite = await create_invite(self.bot, guild_id, interaction.user.id)
        except GuildActionError as exc:
            log.info("invite creation failed for guild %s: %s", guild_id, exc)
            await self._update(
                interaction,
                embed=build_notice_embed(
                    "Could not create invite",
                    str(exc),
                    color=theme.RED,
                ),
                view=GuildResultView(self, owner_id, query=query, page=page),
            )
            return
        except Exception:
            log.exception("unexpected invite creation failure for guild %s", guild_id)
            await self._update(
                interaction,
                embed=build_notice_embed(
                    "Could not create invite",
                    "An unexpected error stopped the invite from being created. Try again later.",
                    color=theme.RED,
                ),
                view=GuildResultView(self, owner_id, query=query, page=page),
            )
            return

        expiry = (
            f"Discord reports it expires {discord.utils.format_dt(created.expires_at, 'R')}."
            if created.expires_at is not None
            else "Discord did not report an expiry for this invite."
        )
        description = (
            f"Created a temporary invite for **{_safe(guild_name)}**"
            f"{f' in {created.channel_name}' if created.channel_name else ''}:\n"
            f"{created.url}\n\n"
            f"{expiry} Anyone with the link can join while it is valid."
        )
        log.info(
            "owner %s created an invite in guild %s (%s) in channel %s",
            interaction.user.id,
            guild_id,
            guild_name,
            created.channel_name or "unknown",
        )
        await self._update(
            interaction,
            embed=build_notice_embed("Invite created", description, color=theme.GREEN),
            view=GuildResultView(self, owner_id, query=query, page=page),
        )

    async def leave_guild_and_report(
        self, interaction, *, owner_id, guild_id: int, query: str, page: int
    ) -> None:
        if not await self._require_interaction_owner(interaction, owner_id):
            return
        if not await interactions.defer(interaction):
            return

        try:
            result = await leave_guild(self.bot, guild_id, interaction.user.id)
        except GuildActionError as exc:
            log.info("leave failed for guild %s: %s", guild_id, exc)
            await self._update(
                interaction,
                embed=build_notice_embed("Could not leave server", str(exc), color=theme.RED),
                view=GuildResultView(self, owner_id, query=query, page=page),
            )
            return
        except Exception:
            log.exception("unexpected leave failure for guild %s", guild_id)
            await self._update(
                interaction,
                embed=build_notice_embed(
                    "Could not leave server",
                    "An unexpected error stopped the bot from leaving that server. Try again later.",
                    color=theme.RED,
                ),
                view=GuildResultView(self, owner_id, query=query, page=page),
            )
            return

        self.directory.invalidate(guild_id)
        if result.left:
            title = "Left server"
            description = (
                f"The bot left **{_safe(result.name)}** (`{result.guild_id}`). "
                "It is no longer connected to that server."
            )
            color = theme.GREEN
        else:
            title = "Server already left"
            description = (
                f"The bot is no longer in **{_safe(result.name)}** (`{result.guild_id}`). "
                "It may already have left; the server list will refresh when you go back."
            )
            color = theme.YELLOW

        log.info(
            "owner %s made the bot leave guild %s (%s)",
            interaction.user.id,
            guild_id,
            result.name,
        )
        await self._update(
            interaction,
            embed=build_notice_embed(title, description, color=color),
            view=GuildResultView(self, owner_id, query=query, page=page),
        )


def setup(bot: commands.Bot) -> None:
    bot.add_cog(GuildManagement(bot))
