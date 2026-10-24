from discord.ext import commands
import hashlib
import logging
import discord
import asyncio
import inspect
import json
import sys
import os

# ---------------------------------------------------------------------------
# Compatibility shim — MUST run before any project module imports.
#
# The Components-V2 API changed shape between py-cord releases:
#
#   * py-cord < 2.7 has no Components-V2 at all (``discord.ui.Container``,
#     ``Section``, ``TextDisplay``, ``DesignerView``), which is why
#     requirements.txt asks for 2.7 or newer.
#   * some builds spell the container accent ``accent_colour=`` while others
#     spell it ``colour=`` / ``color=`` and *reject* ``accent_colour=``.
#
# The previous shim patched unconditionally and always forwarded ``colour=``
# to ``accent_colour=``.  On py-cord 2.8.1 that made every card crash with
#   TypeError: Container.__init__() got an unexpected keyword argument
#   'accent_colour'
# the moment the bot reached ``on_ready`` and added its persistent views.
#
# Patch only what the installed version is actually missing, and never forward
# a keyword the installed version does not accept.
# ---------------------------------------------------------------------------
from discord.ui import Container as _Container


if not hasattr(discord.ui, "DesignerView"):

    class _DesignerViewShim(discord.ui.View):
        """Drop-in replacement for the missing ``discord.ui.DesignerView``."""

        def __init__(self, container=None, *, timeout=None):
            super().__init__(timeout=timeout)
            if container is not None:
                self._children.append(container)

    discord.ui.DesignerView = _DesignerViewShim


def _container_accepts(name: str) -> bool:
    """True when the installed ``Container`` accepts ``name`` as a keyword."""
    try:
        return name in inspect.signature(_Container.__init__).parameters
    except (TypeError, ValueError):  # pragma: no cover - builtins/C slots
        return False


# Only the pre-2.8 spelling needs translating.  On 2.8+ ``colour=`` is native
# and ``accent_colour=`` is an error, so the patch must not be installed.
if not _container_accepts("colour") and _container_accepts("accent_colour"):
    _orig_container_init = _Container.__init__

    def _patched_container_init(
        self,
        *children,
        accent_colour=None,
        accent_color=None,
        spoiler=False,
        id=None,
        colour=None,
        **_,
    ):
        if colour is not None and accent_colour is None and accent_color is None:
            accent_colour = colour
        return _orig_container_init(
            self,
            *children,
            accent_colour=accent_colour,
            accent_color=accent_color,
            spoiler=spoiler,
            id=id,
        )

    _Container.__init__ = _patched_container_init

from ui.buttons.link_account import LinkAccountView
from ui.buttons.create_ticket import CreateTicketView
from database.database import DBConnection
from mail import start_mail, stop_mail
from mail.discord_forward import set_client as set_mail_client
from ui.buttons.claim_button import ClaimPersistentView
from shared import interactions

# Every config path in this project is relative to the repo root, so pin the
# working directory instead of inheriting whatever the launcher/task used.
ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)


def force_utf8_streams() -> None:
    """Make stdout/stderr UTF-8 no matter what code page started the bot.

    A double-clicked start.bat inherits the OEM/ANSI code page (cp1252 here), so
    any message with a non-ASCII character raised ``UnicodeEncodeError`` from the
    logging ``StreamHandler`` and printed a full "--- Logging error ---" traceback
    per line. Guild names are the usual trigger - "Atlantis Mods\u2122 \u2503 FREE
    Minecraft Clients" contains both \u2122 and \u2503, and neither exists in cp1252.
    ``errors="replace"`` keeps a future unknown character from ever taking a log
    line down again instead of printing a '?'.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            # Detached/pythonw (stream is None) or a stream that cannot be
            # reconfigured - nothing to fix here.
            pass


force_utf8_streams()


def load_json(path: str, label: str) -> dict:
    """Load a config object or exit with a message a new user can act on."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        example = f"{path}.example"
        print(f"[X] Missing {label}: {path}", flush=True)
        if os.path.isfile(example):
            print(f"    Copy {example} to {path} and fill in your values.", flush=True)
        raise SystemExit(2) from None
    except json.JSONDecodeError as exc:
        print(f"[X] {label} is not valid JSON ({path}): {exc}", flush=True)
        raise SystemExit(2) from None
    if not isinstance(data, dict):
        print(f"[X] {label} must contain a JSON object: {path}", flush=True)
        raise SystemExit(2)
    return data


config = load_json("config/config.json", "bot config")
settings = load_json("config/bot.json", "bot settings")


def validate_config(data: dict) -> None:
    """Stop with instructions when the token placeholder was never filled in.

    start.bat creates config/config.json from the example so a fresh download
    gets a file, not a crash; that file has an empty token until the user edits
    it. Failing here prints what to do instead of a discord LoginFailure.
    """
    tokens = data.get("tokens")
    if isinstance(tokens, dict):
        token = str(tokens.get("bot_token") or "").strip()
    else:
        token = ""
    upper = token.upper()
    if (
        not token
        or upper in {"YOUR_BOT_TOKEN", "BOT_TOKEN", "TOKEN", "PASTE_TOKEN_HERE"}
        or upper.startswith("YOUR_")
        or token.startswith("<")
    ):
        print("[X] config/config.json has no bot token yet.", flush=True)
        print("    Open config/config.json and set tokens.bot_token to your bot's token", flush=True)
        print("    (Discord Developer Portal -> your application -> Bot -> Reset Token).", flush=True)
        print("    Set owners to your Discord user ID too, or admin commands stay locked.", flush=True)
        raise SystemExit(2)

    owners = data.get("owners")
    valid_owners = (
        [owner for owner in owners if str(owner).strip() not in ("", "0", "None")]
        if isinstance(owners, list)
        else []
    )
    if not valid_owners:
        print("[!] config/config.json has no owners - admin commands will refuse everyone.", flush=True)
        print("    Add your Discord user ID to owners and restart.", flush=True)


validate_config(config)


class DiscordBot(commands.Bot):
    def __init__(self):
        super().__init__(
            command_prefix="!",
            case_insensitive=True,
            intents=discord.Intents.all(),
            allowed_mentions=discord.AllowedMentions(roles=False, everyone=False, users=True)
        )
        self.logger = logging.getLogger("bot")
        self.admins = [int(owner) for owner in (config.get("owners") or [])]

        self.statuses = {
            "online": discord.Status.online,
            "idle": discord.Status.idle,
            "dnd": discord.Status.dnd,
            "invisible": discord.Status.invisible,
        }
        
        self.activities = {
            "playing": discord.ActivityType.playing,
            "streaming": discord.ActivityType.streaming,
            "listening": discord.ActivityType.listening,
            "watching": discord.ActivityType.watching,
            "competing": discord.ActivityType.competing,
        }

    
    # Builds fake commands
    async def build_command(self, name: str, description: str, response: str):
        async def cog(ctx: discord.ApplicationContext):
            await ctx.respond(response, ephemeral=True)

        cog.__name__ = name
        command = discord.SlashCommand(cog, name=name, description=description)
        self.add_application_command(command)

    def command_signature(self) -> str:
        payloads = []
        for cmd in self.pending_application_commands:
            try:
                payloads.append(cmd.to_dict())
            except Exception:
                payloads.append({"name": getattr(cmd, "name", "?")})
                
        blob = json.dumps(payloads, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    async def on_ready(self):
        self.add_view(LinkAccountView())
        self.add_view(CreateTicketView())
        self.add_view(ClaimPersistentView())
        self.logger.info("Logged in as %s (%s)", self.user, self.user.id if self.user else "?")

        # Presence from the config. Old/partial configs used "activity" instead
        # of "activity_text" and omitted activity_type — accept both shapes and
        # never let a typo here stop the bot from coming online.
        presence = settings.get("presence")
        if not isinstance(presence, dict):
            presence = {}
        activity_text = str(
            presence.get("activity_text") or presence.get("activity") or ""
        ).strip()
        activity_type = str(presence.get("activity_type") or "playing").strip().lower()
        status = str(presence.get("status") or "online").strip().lower()

        try:
            await self.change_presence(
                status=self.statuses.get(status, discord.Status.online),
                activity=(
                    discord.Activity(
                        type=self.activities.get(
                            activity_type, discord.ActivityType.playing
                        ),
                        name=activity_text,
                    )
                    if activity_text
                    else None
                ),
            )
        except Exception:
            self.logger.exception("Could not set presence — continuing without it")

        await self.sync_application_commands()

    async def on_guild_join(self, guild: discord.Guild):
        """Register commands for a server that adds the bot after startup."""
        if not self.is_ready():
            return  # on_ready is running (or about to run) and covers it
        try:
            await self.sync_application_commands()
            self.logger.info(f"Joined {guild.name} ({guild.id}); slash commands registered")
        except Exception:
            self.logger.exception(f"Command sync failed for {guild.name} ({guild.id})")

    async def on_view_error(self, error: Exception, item, interaction) -> None:
        """Last line of defence for button/modal callbacks.

        Discord throws two errors that are not our fault: an interaction whose
        token expired (404 / code 10062) and an interaction that was already
        answered (400 / code 40060). Both are logged quietly, because the user
        simply moved on or pressed the button twice. Every other error is a
        real bug and gets the full traceback.
        """
        if interactions.is_expired(error) or interactions.is_already_acknowledged(error):
            self.logger.info(
                "Interaction %s could not be answered (%s)",
                getattr(interaction, "id", "?"),
                interactions.describe(error),
            )
            return
        self.logger.error(
            "Unhandled error in a %s callback",
            type(item).__name__,
            exc_info=error,
        )

    async def sync_application_commands(self, guild_ids: list[int] | None = None) -> None:
        """Register slash commands in every guild the bot is currently in.

        Guild-scoped registration is what makes commands show up instantly; the
        global set only propagates over Discord's own schedule (up to an hour).
        pycord's ``sync_commands(guild_ids=[...])`` *mutates* each command's
        ``guild_ids``, and an empty list means "no scope at all" — which is why
        the old unconditional call registered nothing when the bot had not been
        invited yet and left it commandless until the next restart. on_guild_join
        now covers the bot being invited while it is running.
        """
        targets = [guild.id for guild in self.guilds] if guild_ids is None else list(guild_ids)
        if not targets:
            self.logger.warning(
                "Bot is in no guild(s); slash commands register as soon as it is invited"
            )
            return
        await self.sync_commands(guild_ids=targets)
        self.logger.info(f"Synced commands to {len(targets)} guild(s)")

    @staticmethod
    def setup_logging() -> None:
        root = logging.getLogger()
        root.setLevel(logging.INFO)

        # A fresh clone has no logs/ folder and FileHandler would raise before
        # the bot ever reaches Discord.
        os.makedirs("logs", exist_ok=True)
        # Same reason as force_utf8_streams(): the file handler defaults to the
        # locale encoding, so one \u2503 in a guild name would fail to write.
        file_handler = logging.FileHandler("logs/securing.log", mode="a", encoding="utf-8")
        file_handler.setLevel(logging.INFO)
        root.addHandler(file_handler)

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter("%(levelname)s | %(asctime)s | %(name)s | %(message)s"))

        bot_logger = logging.getLogger("bot")
        bot_logger.addHandler(console_handler)
        # Keep propagating: the root file handler then records bot INFO lines in
        # logs/securing.log as well, so the file is a complete history instead of
        # module messages only.
        bot_logger.propagate = True

        for name in ("discord", "discord.http", "discord.gateway", "httpx", "mail.log"):
            logging.getLogger(name).setLevel(logging.WARNING)

    def enabled_commands(self) -> tuple[bool, dict, dict]:
        """``(default_on, per-cog overrides, fake commands)`` from the config.

        ``enabled_commands`` accepts either a bare ``true``/``false`` (every cog
        on / off) or the full ``{"real": {...}, "fake": {...}}`` object, so an
        older or hand-edited config can no longer crash the startup.
        """
        enabled = settings.get("enabled_commands", True)
        if isinstance(enabled, dict):
            real = enabled.get("real")
            fake = enabled.get("fake")
            return True, real if isinstance(real, dict) else {}, fake if isinstance(fake, dict) else {}
        return bool(enabled), {}, {}

    async def load_cogs(self, directory="./cogs") -> None:
        default_on, real, fake = self.enabled_commands()

        for file in sorted(os.listdir(directory)):
            if file.endswith(".py"):
                if file == "__init__.py":
                    continue
                cog_name = file[:-3]
                if not real.get(cog_name, default_on):
                    continue
                module = f"{directory[2:].replace('/', '.')}.{cog_name}"
                # One broken cog must not take the whole bot down; it is logged
                # and skipped instead.
                try:
                    # pycord's load_extension is synchronous (older forks
                    # returned an awaitable), so support both.
                    loaded = self.load_extension(module)
                    if inspect.isawaitable(loaded):
                        await loaded
                except Exception:
                    self.logger.exception("Could not load cog %s", module)
                else:
                    self.logger.info("Loaded: %s", cog_name)
            elif not (
                file in ["__pycache__", "utils", "buttons", "modals"] or file.endswith(("pyc", "txt"))
            ):
                await self.load_cogs(f"{directory}/{file}")

        for command, values in fake.items():
            if not isinstance(values, dict):
                continue
            try:
                await self.build_command(
                    name=values.get("title") or command,
                    description=values.get("description") or "No description",
                    response=values.get("response") or "",
                )
            except Exception:
                self.logger.exception("Could not build fake command %s", command)

        with DBConnection() as database:
            database.setup_tables()

LOCK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "bot.lock")


def _pid_alive(pid: int) -> bool:
    """True when ``pid`` looks like a running python process.

    The image name is checked too: a recycled PID belonging to some unrelated
    program must not make a stale ``logs/bot.lock`` look like a live bot.
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        import subprocess

        try:
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout or ""
        except Exception:
            # Cannot tell -> assume alive; never risk a duplicate bot.
            return True
        return str(pid) in out and "python" in out.lower()
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def claim_single_instance() -> bool:
    """Refuse to start when another autosecure-bot is already running.

    A second ``pm2 start ecosystem.config.cjs`` starts a second copy under the
    same name; both then hold the same Discord gateway, run the same mail
    poller and write the same SQLite DB. The first copy keeps a PID lock in
    ``logs/bot.lock``, so a later copy exits instead of duplicating all of it.
    """
    # A fresh clone has no logs/ folder yet (setup_logging() creates it later, after
    # this check runs), which used to make the lock write raise FileNotFoundError and
    # silently disable the guard.
    try:
        os.makedirs(os.path.dirname(LOCK_FILE), exist_ok=True)
    except Exception:
        logging.getLogger("bot").exception("Could not create %s", os.path.dirname(LOCK_FILE))

    other = 0
    try:
        with open(LOCK_FILE, "r", encoding="utf-8") as fh:
            other = int((fh.read() or "0").strip() or 0)
    except Exception:
        other = 0

    if other and other != os.getpid() and _pid_alive(other):
        print(
            f"[X] - Another autosecure-bot instance is already running (pid {other})"
            f" - exiting so this one does not duplicate the gateway, the mail"
            f" poller and the database. If that process is gone, delete"
            f" {LOCK_FILE} and restart.",
            flush=True,
        )
        return False

    try:
        with open(LOCK_FILE, "w", encoding="utf-8") as fh:
            fh.write(str(os.getpid()))
    except Exception:
        logging.getLogger("bot").exception("Could not write lock file %s", LOCK_FILE)
    return True


asyncio.set_event_loop(asyncio.new_event_loop())
bot = DiscordBot()

async def main():
    async with bot:
        bot.remove_command("help")
        bot.setup_logging()

        # Mail forwarding falls back to the logs channel when a Discord webhook
        # was deleted, so the forwarder needs the client before the poller runs.
        set_mail_client(bot)

        # Inbound mail: mail.tm polling by default, local SMTP only when
        # mail.provider is "local" (own domain + MX). A mail failure must not
        # keep the bot offline.
        try:
            await start_mail()
        except Exception:
            bot.logger.exception("Inbound mail failed to start — continuing without it")

        try:
            await bot.load_cogs()
            await bot.start(config["tokens"]["bot_token"])
        finally:
            await stop_mail()


if __name__ == "__main__":
    if not claim_single_instance():
        sys.exit(0)
    asyncio.run(main())
