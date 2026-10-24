from discord import ui
import discord

from shared.gen_totp import totp
from shared import interactions

class ButtonTOTP(ui.View):
    def __init__(self, secret: str):
        super().__init__(timeout=None)
        self.secret = secret

    @discord.ui.button(label="🔄 Refresh Code", style=discord.ButtonStyle.green, custom_id="persistent:button_refresh")
    async def button_one(self, button: discord.ui.Button, interaction: discord.Interaction):
        getTOTP = await totp(self.secret)
        await interactions.edit(interaction,
            embed=discord.Embed(
                title="Authenticator Code",
                description=f"```{getTOTP}```"
            )
        )
