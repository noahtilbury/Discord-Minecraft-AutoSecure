"""Components V2 verification cards.

Every user-facing verification/secure status is rendered with the same visual
language so the bot looks consistent:

* a ``Container`` with a green accent (red for failures/timouts) holding a
  ``Section`` (heading + body + optional boxed value, with a right-hand
  thumbnail) and an ``ActionRow`` of buttons rendered *inside* the card.

The classic ``Embed`` can never carry a button inside the card, which is why the
whole flow uses Components V2 (``DesignerView``) instead.
"""

from __future__ import annotations

import json
import os
from typing import Callable, Optional

import discord

# ---------------------------------------------------------------------------
# Palette / brand
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Configuration (config/bot.json -> embeds.components_v2)
# ---------------------------------------------------------------------------

# The Minelink card look below is the default: any key the config omits keeps
# exactly the value that used to be hard-coded here, so an untouched (or older)
# config renders the same cards as before.
DEFAULT_COLOURS = {
    "success": 0x52A435,  # exact green sampled from the MineLink logo
    "error": 0xED4245,  # failures + timeouts
    "warning": 0xFEE75C,
    "info": 0x5865F2,
}
# The verify card ships without a footer. ``embeds.components_v2.footer`` can
# still add one (a plain string, or "-# text" for Discord subtext); an empty
# string means "no footer", which is why the config is read with a sentinel
# instead of ``or DEFAULT_FOOTER``.
DEFAULT_FOOTER = ""
DEFAULT_HEADING = "🔷"
_MISSING = object()

BUTTON_STYLES = {
    "primary": discord.ButtonStyle.primary,
    "secondary": discord.ButtonStyle.secondary,
    "success": discord.ButtonStyle.success,
    "danger": discord.ButtonStyle.danger,
}


def load_components_v2() -> dict:
    """Read ``embeds.components_v2`` from config/bot.json (or ``{}``)."""
    try:
        with open("config/bot.json", encoding="utf-8") as handle:
            embeds = json.load(handle).get("embeds") or {}
    except Exception:
        return {}
    cfg = embeds.get("components_v2")
    return cfg if isinstance(cfg, dict) else {}


def _hex_colour(value: object, fallback: int) -> int:
    """Accept ``"#52A435"``, ``"0x52A435"`` or ``2102309``."""
    if isinstance(value, int):
        return value
    text = str(value or "").strip().lower().replace("#", "").replace("0x", "")
    try:
        return int(text, 16) if text else fallback
    except ValueError:
        return fallback


def _palette(cfg: dict) -> dict[str, int]:
    colours = cfg.get("colors") or cfg.get("colours") or {}
    if not isinstance(colours, dict):
        colours = {}
    return {
        name: _hex_colour(colours.get(name), default)
        for name, default in DEFAULT_COLOURS.items()
    }


_V2 = load_components_v2()
_PALETTE = _palette(_V2)

GREEN = _PALETTE["success"]
RED = _PALETTE["error"]
YELLOW = _PALETTE["warning"]
INFO = _PALETTE["info"]


def _footer_text(cfg: dict) -> str:
    """Footer line for the verify card; "" when the config asks for none."""
    value = cfg.get("footer", _MISSING)
    if value is _MISSING or value is None:
        return DEFAULT_FOOTER
    return str(value).strip()


# The public verification prompt keeps its own small footer label (usually none).
VERIFY_FOOTER = _footer_text(_V2)
HEADING_EMOJI = str(_V2.get("heading_emoji") or DEFAULT_HEADING)


def _button_settings(name: str) -> dict:
    raw = _V2.get(name)
    return raw if isinstance(raw, dict) else {}


def configured_style(name: str, fallback: discord.ButtonStyle) -> discord.ButtonStyle:
    key = str(_button_settings(name).get("style") or "").strip().lower()
    return BUTTON_STYLES.get(key, fallback)

# 3D isometric full-body render (1x, standing). visage.surgeplay renders
# the whole character (head + torso + limbs) so the username-found card shows
# a full body (like the screenshots) instead of a flat 2D avatar.
# "full" = 3D isometric full body facing forward (vs /frontfull which is 2D).
FULL_SIZE = 512
SKIN_URL = "https://visage.surgeplay.com/full/" + str(FULL_SIZE) + "/{name}?y=-40"
# Square avatar render (used for log-channel thumbnails / other embeds).
AVATAR_URL = "https://mc-heads.net/avatar/{name}/256"

ButtonCallback = Callable[[discord.Interaction], object]


# ---------------------------------------------------------------------------
# Low level helpers
# ---------------------------------------------------------------------------


def box(value: str) -> str:
    """Boxed value (single-line code block) used for usernames / codes."""
    text = str(value if value is not None else "").replace("```", "")
    return f"```\n{text}\n```"


def skin_url(username: str) -> str:
    return SKIN_URL.format(name=str(username or "MHF_Steve").strip())


def avatar_url(username: str) -> str:
    return AVATAR_URL.format(name=str(username or "MHF_Steve").strip())


def button(
    label: str,
    style: discord.ButtonStyle,
    callback: Optional[ButtonCallback] = None,
    *,
    custom_id: Optional[str] = None,
    emoji: Optional[str] = None,
    disabled: bool = False,
) -> discord.ui.Button:
    item = discord.ui.Button(
        label=label,
        style=style,
        custom_id=custom_id,
        emoji=emoji,
        disabled=disabled,
    )
    if callback is not None:
        item.callback = callback
    return item


def card(
    colour: int,
    text: str,
    *,
    thumbnail: Optional[str] = None,
    buttons: Optional[list[discord.ui.Button]] = None,
) -> discord.ui.DesignerView:
    """Build one accented container card."""
    if thumbnail:
        body: discord.ui.ViewItem = discord.ui.Section(
            discord.ui.TextDisplay(text),
            accessory=discord.ui.Thumbnail(thumbnail),
        )
    else:
        body = discord.ui.TextDisplay(text)

    items: list[discord.ui.ViewItem] = [body]
    if buttons:
        items.append(discord.ui.ActionRow(*buttons))

    return discord.ui.DesignerView(
        discord.ui.Container(*items, colour=colour),
        timeout=None,
    )


def waiting_button(label: str = "Waiting...") -> discord.ui.Button:
    return button(label, discord.ButtonStyle.secondary, disabled=True)


# ---------------------------------------------------------------------------
# Cards
# ---------------------------------------------------------------------------


def _verification_content() -> tuple[str, Optional[str]]:
    """Heading/description/thumbnail for the public prompt.

    Prefers the compact ``embeds.verify_card`` block; otherwise renders the
    full ``embeds.verification`` welcome content into the card.
    """
    try:
        with open("config/bot.json") as f:
            embeds = json.load(f).get("embeds", {})
    except Exception:
        embeds = {}

    compact = embeds.get("verify_card") or {}
    if compact.get("title") or compact.get("description"):
        title = compact.get("title") or "Verify your account"
        description = compact.get("description") or ""
        thumb = compact.get("thumbnail") or None
        # Title is inline bold (not a markdown heading) with a small brand
        # footer underneath, matching the supplied reference card.
        lines = [f"{HEADING_EMOJI} **{title}**"]
        if description:
            lines.append(description)
        if VERIFY_FOOTER:
            lines.append(VERIFY_FOOTER)
        return "\n".join(lines), thumb

    default = (embeds.get("verification") or {}).get("default") or {}
    title = default.get("title") or "Verify your account"
    description = default.get("description") or ""
    lines = [f"{HEADING_EMOJI} **{title}**"]
    if description:
        lines.append(description)
    for field in default.get("fields") or []:
        name = field.get("name") or ""
        value = field.get("value") or ""
        if name:
            lines.append(f"**{name}**")
        if value:
            lines.append(value)
    if VERIFY_FOOTER:
        lines.append(VERIFY_FOOTER)
    return "\n".join(lines), (default.get("thumbnail") or None)


def verify_image_file() -> Optional[discord.File]:
    """Local attachment for the verify card thumbnail (``attachment://…``).

    Returns ``None`` when the config uses a normal URL or the asset is missing.
    """
    thumb = None
    try:
        with open("config/bot.json") as f:
            embeds = json.load(f).get("embeds", {})
        thumb = (embeds.get("verify_card") or {}).get("thumbnail") or (
            (embeds.get("verification") or {}).get("default") or {}
        ).get("thumbnail")
    except Exception:
        thumb = None

    if not thumb or not str(thumb).startswith("attachment://"):
        return None
    name = str(thumb).split("attachment://", 1)[1].strip()
    path = os.path.join("assets", name)
    if not name or not os.path.isfile(path):
        return None
    return discord.File(path, filename=name)


def verify_button(on_verify: ButtonCallback) -> discord.ui.Button:
    cfg = _button_settings("verify_button")
    emoji = cfg.get("emoji", "✅")
    return button(
        str(cfg.get("label") or "Verify"),
        configured_style("verify_button", discord.ButtonStyle.success),
        on_verify,
        custom_id="persistent:button_one",
        emoji=str(emoji) if emoji else None,
    )


def verify_container(on_verify: ButtonCallback) -> discord.ui.Container:
    """Accented container for the persistent verification prompt."""
    text, thumb = _verification_content()
    body: discord.ui.ViewItem
    if thumb:
        body = discord.ui.Section(
            discord.ui.TextDisplay(text),
            accessory=discord.ui.Thumbnail(thumb),
        )
    else:
        body = discord.ui.TextDisplay(text)
    return discord.ui.Container(
        body,
        discord.ui.ActionRow(verify_button(on_verify)),
        colour=GREEN,
    )


def verify_card(
    *,
    on_verify: ButtonCallback,
    title: str = "Verify your account",
    description: str = "Link your Minecraft account. Hit **Verify** when ready.",
    thumbnail: Optional[str] = None,
) -> discord.ui.DesignerView:
    """Public verification prompt (green, Verify button inside the card)."""
    lines = [f"{HEADING_EMOJI} **{title}**", description]
    if VERIFY_FOOTER:
        lines.append(VERIFY_FOOTER)
    text = "\n".join(line for line in lines if line)
    return card(
        GREEN,
        text,
        thumbnail=thumbnail,
        buttons=[verify_button(on_verify)],
    )


def username_found_card(
    username: str,
    *,
    on_email: ButtonCallback,
    title: str = "Username found",
    description: str = "Continue to finish verification.",
) -> discord.ui.DesignerView:
    """Username step result: shows the name + the account's full 3D body
    (visage.surgeplay) facing forward. This is the only card that gets the
    character render; every other username render stays a flat avatar.

    Uses the /full endpoint (3D isometric full body) with ?y=-40 to face the
    character forward (vs /frontfull which is a flat 2D render)."""
    text = (
        f"## 👤 {title}\n"
        f"{description}\n"
        f"### 👤 Username\n{box(username)}"
    )
    return card(
        GREEN,
        text,
        thumbnail=skin_url(username),
        buttons=[
            button("Enter email", discord.ButtonStyle.secondary, on_email),
        ],
    )


def checking_card(
    description: str = "One moment...",
    *,
    title: str = "Checking",
) -> discord.ui.DesignerView:
    """Waiting card shown while a step is in flight."""
    return card(GREEN, f"## {title}\n{description}", buttons=[waiting_button()])


def being_verified_card(
    username: str = "",
    *,
    title: str = "Verifying",
    description: Optional[str] = None,
) -> discord.ui.DesignerView:
    """Shown while the securing pipeline runs after the code is accepted.

    The live status is the temporary message above the embed, so the card carries
    a short prompt and the real detail is updated in the follow-up message.
    """
    if description is None:
        who = f"**{username}**" if username else "your account"
        description = f"Verifying {who}. This can take a minute — hang tight."
    return card(GREEN, f"## {title}\n{description}", buttons=[waiting_button()])


def authenticator_card(
    number: str,
    *,
    title: str = "Authenticator",
    description: str = "Tap the number in Microsoft Authenticator.",
) -> discord.ui.DesignerView:
    """Number-matching push card."""
    text = f"## {title}\n{description}\n### Number\n{box(number)}"
    return card(GREEN, text, buttons=[waiting_button()])


def otp_card(
    security_email: str,
    *,
    on_submit: ButtonCallback,
    title: str = "Last Step",
    description: str = (
        "To complete verification, enter the confirmation code we sent to "
        "`{email}`.\nThis step prevents automated or fake verifications."
    ),
) -> discord.ui.DesignerView:
    """Email-OTP card with a Submit Code button inside the card."""
    body = description.replace("{email}", str(security_email or ""))
    text = f"## {title}\n{body}\n### Destination\n{box(security_email)}"
    return card(
        GREEN,
        text,
        buttons=[
            button("Submit Code", discord.ButtonStyle.success, on_submit),
        ],
    )


def success_card(
    username: str = "",
    *,
    title: str = "Successfully Verified",
    description: Optional[str] = None,
) -> discord.ui.DesignerView:
    if description is None:
        who = f"**{username}**" if username else "your account"
        description = f"{who} is verified. Your account is all set — have fun!"
    return card(GREEN, f"## {title}\n{description}")


def fail_card(
    title: str,
    description: str,
    *,
    field_label: Optional[str] = None,
    field_value: Optional[str] = None,
    on_retry: Optional[ButtonCallback] = None,
    retry_label: str = "Retry",
    extra_buttons: Optional[list[discord.ui.Button]] = None,
) -> discord.ui.DesignerView:
    """Red failure card, optionally with a boxed field and a Retry button."""
    lines = [f"## {title}", description]
    if field_label and field_value is not None:
        lines.append(f"### {field_label}\n{box(field_value)}")
    buttons: list[discord.ui.Button] = []
    if on_retry:
        buttons.append(button(retry_label, discord.ButtonStyle.secondary, on_retry))
    if extra_buttons:
        buttons.extend(extra_buttons)
    return card(RED, "\n".join(lines), buttons=buttons or None)


def timeout_card(
    reason: str = "No response; retry to send a new prompt.",
    *,
    title: str = "Timed out",
    on_retry: Optional[ButtonCallback] = None,
) -> discord.ui.DesignerView:
    """Red 'Timed out' card whose description changes with the reason."""
    return fail_card(
        title,
        reason,
        on_retry=on_retry,
        retry_label="Retry",
    )
