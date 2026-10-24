"""Inbound mail for Cloudy Secure.

Default provider is **mail.tm** — free disposable inboxes, no domain, no MX
records and no SMTP server to host:

* ``mail.mailtm``     — REST client (domains, accounts, tokens, messages)
* ``mail.provision``  — create/delete the security mailboxes we use
* ``mail.poller``     — polls inboxes -> DB, Discord webhooks, OTP bridges
* ``mail.discord_forward`` — shared webhook / OTP-bridge fan-out
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)


async def start_mail() -> None:
    """Start inbound mail handling for the configured provider."""
    from database.database import DBConnection
    from mail.discord_forward import validate_webhooks
    from mail.poller import start_poller

    # The poller reads security_emails/provider columns — make sure the schema
    # is migrated before the first tick (bot.py loads cogs later on).
    try:
        with DBConnection() as db:
            db.setup_tables()
    except Exception:
        log.exception("mail: schema setup failed")

    # A webhook that was deleted answers 404 Unknown Webhook forever. Check it
    # once so the log says exactly what to fix instead of failing quietly on
    # every email, and remember it is dead for the rest of the process.
    try:
        await validate_webhooks()
    except Exception:
        log.warning("mail: webhook check failed", exc_info=True)

    start_poller()


async def stop_mail() -> None:
    from mail.poller import stop_poller

    await stop_poller()


__all__ = [
    "start_mail",
    "stop_mail",
]
