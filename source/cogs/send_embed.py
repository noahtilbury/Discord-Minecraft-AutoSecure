from ui.buttons.link_account import LinkAccountView
from ui import theme

from discord.ext import commands
import discord
import json

from shared.settings import command_alias
from shared.interactions import followup

name = command_alias("send_embed")


class sendEmbed(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    send = discord.SlashCommandGroup(name)

    @send.command(name="embed", description="Sends the verification embed")
    async def embed_command(self, ctx: discord.ApplicationContext):
        if ctx.author.id not in self.bot.admins:
            await ctx.respond(
                "You do not have permission to execute this command!",
                ephemeral=True,
            )
            return

        config = json.load(open("config/config.json", "r"))

        if not config["discord"]["logs_channel"] or not config["discord"]["accounts_channel"]:
            await ctx.respond(
                "You must set the logs and Hits channel first with /set channel!",
                ephemeral=True,
            )
            return

        await ctx.defer(ephemeral=True)

        # Components V2 card: the greeting and the green Verify button live in
        # the same card (classic embeds cannot embed a button). The card's
        # thumbnail is a local asset referenced as attachment://….
        file = theme.verify_image_file()
        if file is not None:
            await ctx.channel.send(view=LinkAccountView(), file=file)
        else:
            await ctx.channel.send(view=LinkAccountView())

        await followup(ctx, "Sent!", ephemeral=True)


def setup(bot: commands.Bot) -> None:
    bot.add_cog(sendEmbed(bot))
