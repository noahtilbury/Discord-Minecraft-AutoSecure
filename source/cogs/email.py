from ui.buttons.mail_inbox import get_inbox
from shared.email_view import InboxView

from database.database import DBConnection
from mail import mailtm
from mail import settings as mail_settings
from mail.provision import (
    create_security_email,
    delete_security_email,
    ensure_registered,
    mailbox_login,
)
from discord.ext import commands
import discord
import json
import logging

from shared import interactions

config = json.load(open("config/config.json", "r"))
from shared.settings import command_alias

name = command_alias("email")

log = logging.getLogger(__name__)

PROVIDER_LABEL = {
    "mailtm": "mail.tm (disposable)",
}


class MailListView(discord.ui.View):
    """``/email list`` pagination.

    The buttons are persistent (fixed custom ids) and the page is read back from
    the card, so pressing ◀/▶ on an older list card still works after a restart
    instead of answering with Discord's "Unknown Integration".
    """

    size = 10

    def __init__(self, emails: list | None = None, page: int = 0):
        super().__init__(timeout=None)
        self.emails = emails or []
        self.page = page
        self.total_pages = max(1, (len(self.emails) + self.size - 1) // self.size)

        previous_button = discord.ui.Button(
            label="◀",
            style=discord.ButtonStyle.secondary,
            disabled=(page == 0),
            row=0,
            custom_id="persistent:mail_list_prev",
        )
        previous_button.callback = self.previous
        self.add_item(previous_button)

        self.add_item(discord.ui.Button(
            label=f"{page + 1} / {self.total_pages}",
            style=discord.ButtonStyle.primary,
            disabled=True,
            row=0,
            # Persistent views need a custom_id on every item, even a disabled
            # page label (this one is read back to know which page to show).
            custom_id="persistent:mail_list_page",
        ))

        next_button = discord.ui.Button(
            label="▶",
            style=discord.ButtonStyle.secondary,
            disabled=(page >= self.total_pages - 1),
            row=0,
            custom_id="persistent:mail_list_next",
        )
        next_button.callback = self.next
        self.add_item(next_button)

    def build_embed(self) -> discord.Embed:
        start = self.page * self.size
        chunk = self.emails[start:start + self.size]
        if not self.emails:
            embed = discord.Embed(
                title="Security Emails",
                description="No emails stored. Try `/email new`.",
                color=0x3B89FF,
            )
        else:
            lines = "\n".join(f"`{start + i + 1}.` {e[0]}" for i, e in enumerate(chunk))
            embed = discord.Embed(
                title="Security Emails",
                description=f"**{len(self.emails)}** email(s) stored:\n\n{lines}",
                color=0x3B89FF,
            )
        footer = "mail.tm inboxes are polled live · mail is kept 7 days"
        return embed.set_footer(text=footer)

    def _page_from_message(self, interaction: discord.Interaction) -> int:
        """Read the current page from the "3 / 7" label on the card."""
        try:
            label = interaction.message.components[0].children[1].label
            return max(0, int(str(label).split("/")[0].strip()) - 1)
        except Exception:
            return self.page

    async def _reload(self, interaction: discord.Interaction, delta: int) -> None:
        with DBConnection() as database:
            emails = list(database.get_security_emails())

        if not emails:
            await interactions.respond(interaction,
                "No emails stored. Try `/email new`.", ephemeral=True
            )
            return

        total_pages = max(1, (len(emails) + self.size - 1) // self.size)
        page = max(0, min(self._page_from_message(interaction) + delta, total_pages - 1))
        view = MailListView(emails, page)
        await interactions.edit(interaction, embed=view.build_embed(), view=view)

    async def previous(self, interaction: discord.Interaction):
        await self._reload(interaction, -1)

    async def next(self, interaction: discord.Interaction):
        await self._reload(interaction, 1)


class Email(commands.Cog):
    mail = discord.SlashCommandGroup(name, "Commands related email features")

    def __init__(self, bot):
        self.bot = bot

    @mail.command(
        name="new",
        description="Create a new disposable security email (mail.tm — no domain needed)",
    )
    async def createMail(self, ctx: discord.ApplicationContext, alias: str = None):
        if ctx.author.id not in self.bot.admins:
            await ctx.respond("You do not have permission to execute this command!", ephemeral=True)
            return

        await interactions.defer(ctx, ephemeral=True)

        try:
            mailbox = await create_security_email(local_part=alias)
        except Exception as exc:
            log.exception("email new failed")
            await ctx.respond(
                embed=discord.Embed(
                    title="Email Not Created",
                    description=f"Could not create a mailbox: `{exc}`",
                    color=0xFA4343
                ),
                ephemeral=True
            )
            return

        provider = mailbox.get("provider") or "local"
        embed = discord.Embed(
            title="Email Created",
            description=(
                f"`{mailbox['email']}` has been added!\n\n"
                f"**Provider:** {PROVIDER_LABEL.get(provider, provider)}\n"
                f"**Password:** `{mailbox['password']}`\n"
                f"Sign in at **mail.tm** with these to read the inbox in a browser."
                if provider == "mailtm"
                else f"`{mailbox['email']}` has been added!"
            ),
            color=0x57F287
        )
        embed.set_footer(text="Incoming mail is stored automatically and forwarded to your webhooks")
        await ctx.respond(embed=embed, ephemeral=True)

    @mail.command(name="inbox", description="Shows the inbox of your email")
    async def emailInbox(self, ctx: discord.ApplicationContext, email: str):
        if ctx.author.id not in self.bot.admins:
            await ctx.respond("You do not have permission to execute this command!", ephemeral=True)
            return

        await interactions.defer(ctx, ephemeral=True)
        inbox = await get_inbox(email)

        if not inbox:
            await ctx.respond(
                embed=discord.Embed(description="This email has not been found", color=0xFA4343),
                ephemeral=True
            )
            return

        if len(inbox.get("emails") or []) == 0:
            await ctx.respond(
                embed=discord.Embed(description="No emails found in inbox.", color=0xFA4343),
                ephemeral=True
            )
            return

        await ctx.respond(embed=inbox["embed"], view=inbox["view"], ephemeral=True)

    @mail.command(name="list", description="Lists all security emails")
    async def listMails(self, ctx: discord.ApplicationContext):
        if ctx.author.id not in self.bot.admins:
            await ctx.respond("You do not have permission to execute this command!", ephemeral=True)
            return

        with DBConnection() as database:
            emails = list(database.get_security_emails())

        if not emails:
            await ctx.respond(
                embed=discord.Embed(
                    title="No Emails Found",
                    description="You don't have any emails stored. Try `/email new`",
                    color=0xFA4343
                ),
                ephemeral=True
            )
            return

        view = MailListView(emails)
        await ctx.respond(embed=view.build_embed(), view=view, ephemeral=True)

    @mail.command(name="delete", description="Delete a security email (and its mail.tm mailbox)")
    async def deleteMail(self, ctx: discord.ApplicationContext, email: str):
        if ctx.author.id not in self.bot.admins:
            await ctx.respond("You do not have permission to execute this command!", ephemeral=True)
            return

        await interactions.defer(ctx, ephemeral=True)
        await delete_security_email(email)

        await ctx.respond(
            embed=discord.Embed(
                title="Email Deleted",
                description=f"`{email}` was removed from the email database.",
                color=0x57F287
            ),
            ephemeral=True
        )

    @mail.command(name="domains", description="Show the active mail.tm domains")
    async def listDomains(self, ctx: discord.ApplicationContext):
        if ctx.author.id not in self.bot.admins:
            await ctx.respond("You do not have permission to execute this command!", ephemeral=True)
            return

        await interactions.defer(ctx, ephemeral=True)

        try:
            domains = await mailtm.list_domains()
        except Exception as exc:
            log.exception("email domains failed")
            await ctx.respond(
                embed=discord.Embed(description=f"mail.tm error: `{exc}`", color=0xFA4343),
                ephemeral=True
            )
            return

        names = [str(item.get("domain") or "") for item in domains][:25]
        await ctx.respond(
            embed=discord.Embed(
                title="mail.tm domains",
                description="\n".join(f"`{n}`" for n in names) or "No active domains.",
                color=0x3B89FF
            ).set_footer(text=f"Provider: {mail_settings.mail_provider()}"),
            ephemeral=True
        )

    @mail.command(
        name="login",
        description="Show the sign-in details for a security email (hand these to a buyer)",
    )
    async def loginMail(self, ctx: discord.ApplicationContext, email: str):
        if ctx.author.id not in self.bot.admins:
            await ctx.respond("You do not have permission to execute this command!", ephemeral=True)
            return

        await interactions.defer(ctx, ephemeral=True)

        mailbox = mailbox_login(email)
        if not mailbox:
            await ctx.respond(
                embed=discord.Embed(
                    title="Mailbox Not Found",
                    description=f"`{email}` is not one of our stored security emails.",
                    color=0xFA4343
                ),
                ephemeral=True
            )
            return

        if not mailbox["web_login"]:
            await ctx.respond(
                embed=discord.Embed(
                    title="No Browser Login",
                    description=(
                        f"`{mailbox['email']}` is a self-hosted mailbox — read it with "
                        "`/email inbox` or the dashboard."
                    ),
                    color=0xFA4343
                ),
                ephemeral=True
            )
            return

        # Force a real mail.tm login so the printed password is known to work
        # before it is handed to a buyer.
        verified = await ensure_registered(mailbox["email"])

        embed = discord.Embed(
            title="Mailbox Login",
            description=(
                f"Sign in at **mail.tm** with the address + password below to read codes "
                f"for `{mailbox['email']}`.\n"
                "Hand both values over when you sell the account."
            ),
            color=0x57F287
        )
        embed.add_field(name="Email", value=f"```{mailbox['email']}```", inline=False)
        embed.add_field(name="Password", value=f"```{mailbox['password']}```", inline=False)
        embed.add_field(name="Login page", value=mailbox["login_url"], inline=False)
        embed.set_footer(
            text=(
                "Login verified just now"
                if verified
                else "Could not verify the login right now — the stored password is unchanged"
            )
        )
        await ctx.respond(embed=embed, ephemeral=True)


def setup(bot: commands.Bot) -> None:
    bot.add_cog(Email(bot))
    # Persistent components for mail cards posted before a restart.
    bot.add_view(MailListView())
    bot.add_view(InboxView())
