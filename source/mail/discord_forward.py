"""Forward inbound mail to Discord webhooks, with a bot-channel fallback.

A deleted webhook answers every POST with ``404 Unknown Webhook`` (Discord code
10015) - the same "unknown integration" family the Discord client shows - and
the mail is lost. So a dead webhook is detected (at startup and on the first
failure), skipped for the rest of the process, and the mail is posted through
the bot into ``discord.logs_channel`` instead.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone

import discord
import httpx

from mail.otp_detect import detect_otp

log = logging.getLogger(__name__)

_UA = "DiscordBot (https://github.com/noahtilbury/Cloudy-Secure, 1.0)"

_config = None
_client = None

# URLs Discord says do not exist any more (404/401). Never retried in this
# process, so a deleted webhook cannot spam a warning on every single email.
_dead_webhooks: set[str] = set()


class WebhookUnavailable(Exception):
    """The configured webhook was deleted or its token was reset."""


def set_client(client) -> None:
    """Give this module the bot so mail survives a dead webhook."""
    global _client
    _client = client


def _load_config() -> dict:
    global _config
    if _config is None:
        with open("config/config.json", "r", encoding="utf-8") as f:
            _config = json.load(f)
    return _config


def _truncate(text: str, max_len: int) -> str:
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _embed_payload(
    *,
    subject: str,
    body: str,
    from_address: str,
    to_addresses: list[str],
    domain: str,
    otp: dict | None = None,
) -> dict:
    fields = [
        {"name": "From", "value": _truncate(from_address or "unknown", 1024), "inline": False},
        {"name": "To", "value": _truncate(", ".join(to_addresses) or "unknown", 1024), "inline": False},
    ]
    if otp and otp.get("code"):
        fields.insert(0, {"name": "Detected OTP", "value": f"`{otp['code']}`", "inline": True})

    return {
        "title": _truncate(subject or "(no subject)", 256),
        "description": _truncate((body or "").replace("\r", ""), 4000) or "(empty body)",
        "color": 0xF1C40F if otp else 0x3498DB,
        "fields": fields,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {
            "text": f"{'OTP webhook' if otp else 'Inbox webhook'} • {domain}",
        },
    }


def _mark_dead(webhook_url: str, detail: str) -> None:
    if webhook_url not in _dead_webhooks:
        _dead_webhooks.add(webhook_url)
        # Through the bot logger so it shows in the launcher window too, not
        # only in logs/securing.log.
        logging.getLogger("bot").warning(
            "[discord] mail webhook is gone (%s). Create a new webhook in the "
            "channel and update mail.discord_webhook_all / discord_webhook_otp; "
            "until then mail is posted to the logs channel.",
            detail,
        )


async def _post_webhook(
    webhook_url: str,
    *,
    subject: str,
    body: str,
    from_address: str,
    to_addresses: list[str],
    domain: str,
    otp: dict | None = None,
) -> None:
    if webhook_url in _dead_webhooks:
        raise WebhookUnavailable("webhook was deleted (cached)")

    payload = {
        "username": "OTP Inbox" if otp else "Mail Inbox",
        "embeds": [
            _embed_payload(
                subject=subject,
                body=body,
                from_address=from_address,
                to_addresses=to_addresses,
                domain=domain,
                otp=otp,
            )
        ],
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            webhook_url, json=payload, headers={"User-Agent": _UA}
        )
        if response.status_code in (401, 404):
            _mark_dead(webhook_url, f"HTTP {response.status_code} {response.text[:120]}")
            raise WebhookUnavailable(response.text[:200])
        response.raise_for_status()


async def _post_via_bot(
    *,
    subject: str,
    body: str,
    from_address: str,
    to_addresses: list[str],
    domain: str,
    otp: dict | None = None,
) -> bool:
    """Post the mail through the bot when its webhook no longer exists."""
    client = _client
    if client is None:
        return False
    try:
        channel_id = int(str((_load_config().get("discord") or {}).get("logs_channel") or 0))
    except Exception:
        channel_id = 0
    if not channel_id:
        return False

    try:
        channel = client.get_channel(channel_id) or await client.fetch_channel(channel_id)
        embed = discord.Embed.from_dict(
            _embed_payload(
                subject=subject,
                body=body,
                from_address=from_address,
                to_addresses=to_addresses,
                domain=domain,
                otp=otp,
            )
        )
        await channel.send(embed=embed)
        log.info("[discord] mailed %r to logs channel %s (webhook unavailable)", subject, channel_id)
        return True
    except Exception:
        log.warning("[discord] fallback post to the logs channel failed", exc_info=True)
        return False


async def probe_webhook(webhook_url: str) -> tuple[bool, str]:
    """``(alive, detail)`` — a GET returns the webhook, or 404 when it was deleted."""
    if not webhook_url:
        return False, "not configured"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(webhook_url, headers={"User-Agent": _UA})
    except httpx.HTTPError as err:
        return False, f"{type(err).__name__}: {err}"

    if response.status_code == 200:
        return True, "ok"
    if response.status_code in (401, 404):
        return False, f"HTTP {response.status_code} {response.text[:120]}"
    return True, f"HTTP {response.status_code} (not confirmed)"


async def validate_webhooks() -> list[str]:
    """Check the configured mail webhooks once at startup. Returns dead keys."""
    mail_cfg = _load_config().get("mail") or {}
    dead: list[str] = []
    for key in ("discord_webhook_all", "discord_webhook_otp"):
        url = str(mail_cfg.get(key) or "").strip()
        if not url:
            continue
        alive, detail = await probe_webhook(url)
        if alive:
            log.info("[discord] %s ok", key)
            continue
        dead.append(key)
        _mark_dead(url, f"{key}: {detail}")
    return dead


async def _push_otp_to_bridge(
    *,
    recipients: list[str],
    from_address: str,
    subject: str,
    body: str,
    code: str | None,
    bridge_url: str,
    bridge_token: str,
) -> None:
    if not bridge_url or not recipients:
        return

    payload = {
        "to": recipients,
        "from": from_address,
        "subject": subject,
        "text": body,
        "html": body if "<" in body and ">" in body else "",
        "code": code,
    }
    headers = {"X-OTP-Bridge-Token": bridge_token} if bridge_token else {}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(bridge_url, json=payload, headers=headers)
            response.raise_for_status()
        log.info(
            "[otp-bridge] pushed to %s for %s%s",
            bridge_url,
            ", ".join(recipients),
            f" code={code}" if code else "",
        )
    except httpx.HTTPError as err:
        log.warning("[otp-bridge] push to %s failed: %s", bridge_url, err)


def _bridge_targets(mail_cfg: dict) -> list[tuple[str, str]]:
    """Collect OTP bridge endpoints. Prefer otp_bridge_urls (fan-out to
    playtime + cft on separate ports); fall back to legacy otp_bridge_url."""
    token = str(mail_cfg.get("otp_bridge_token") or "")
    urls: list[str] = []

    raw_list = mail_cfg.get("otp_bridge_urls")
    if isinstance(raw_list, list):
        urls.extend(str(u).strip() for u in raw_list if str(u or "").strip())
    elif isinstance(raw_list, str) and raw_list.strip():
        urls.extend(u.strip() for u in raw_list.split(",") if u.strip())

    legacy = str(mail_cfg.get("otp_bridge_url") or "").strip()
    if legacy and legacy not in urls:
        urls.append(legacy)

    # De-dupe while preserving order
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        out.append((url, token))
    return out


async def forward_email(
    *,
    from_address: str,
    to_addresses: list[str],
    subject: str,
    body: str,
) -> None:
    cfg = _load_config()
    mail_cfg = cfg.get("mail", {})
    # Label only: the mailbox domain the message landed on.
    domain = next(
        (str(addr).partition("@")[2] for addr in to_addresses if "@" in str(addr)),
        "",
    ) or "mail.tm"

    webhook_all = str(mail_cfg.get("discord_webhook_all") or "").strip()
    webhook_otp = str(mail_cfg.get("discord_webhook_otp") or "").strip()
    bridges = _bridge_targets(mail_cfg)

    if not webhook_all and not webhook_otp:
        return

    recipients = [addr.lower() for addr in to_addresses if addr]
    otp = detect_otp(subject or "", body or "", from_address or "")

    delivered = False
    if webhook_all:
        try:
            await _post_webhook(
                webhook_all,
                subject=subject,
                body=body,
                from_address=from_address,
                to_addresses=recipients,
                domain=domain,
            )
            log.info('[discord] posted to all webhook (%s)', subject or "(no subject)")
            delivered = True
        except WebhookUnavailable:
            pass
        except httpx.HTTPError as err:
            log.warning("[discord] all webhook failed: %s", err)

    if otp.get("is_otp") and webhook_otp and webhook_otp != webhook_all:
        try:
            await _post_webhook(
                webhook_otp,
                subject=subject,
                body=body,
                from_address=from_address,
                to_addresses=recipients,
                domain=domain,
                otp=otp,
            )
            log.info('[discord] posted to otp webhook (%s)', subject or "(no subject)")
            delivered = True
        except WebhookUnavailable:
            pass
        except httpx.HTTPError as err:
            log.warning("[discord] otp webhook failed: %s", err)

    if not delivered:
        await _post_via_bot(
            subject=subject,
            body=body,
            from_address=from_address,
            to_addresses=recipients,
            domain=domain,
            otp=otp if otp.get("is_otp") else None,
        )

    # Fan-out OTP to every bridge in parallel (playtime :12798 + cft :12799).
    # One failing target must never block the others.
    if otp.get("is_otp") and bridges:
        await asyncio.gather(
            *[
                _push_otp_to_bridge(
                    recipients=recipients,
                    from_address=from_address,
                    subject=subject or "",
                    body=body or "",
                    code=otp.get("code"),
                    bridge_url=url,
                    bridge_token=token,
                )
                for url, token in bridges
            ]
        )


def schedule_forward(**kwargs) -> None:
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(forward_email(**kwargs))
    except RuntimeError:
        asyncio.run(forward_email(**kwargs))
