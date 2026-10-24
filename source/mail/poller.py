"""mail.tm inbox poller.

Replaces the self-hosted SMTP server: instead of owning a domain and MX records
we poll every stored mail.tm mailbox and push new mail through the exact same
pipelines the SMTP server fed:

* ``received_emails`` table  -> ``/email inbox``, dashboard, ``get_email_code``
* Discord webhooks           -> ``mail.discord_forward`` (all + OTP)
* OTP bridges                -> playtime / cft endpoints

Polling is rate-limit aware: mail.tm allows 8 QPS per IP, so we pace calls,
rotate over the mailboxes and poll recently-active ones much faster (that is
the mailbox a running secure is waiting on).
"""

from __future__ import annotations

import asyncio
import logging
import time

from database.database import DBConnection
from mail import mailtm
from mail import settings as mail_settings
from mail.discord_forward import schedule_forward

log = logging.getLogger(__name__)

_MAX_MESSAGES_PER_POLL = 20
_MAX_ACCOUNTS_PER_TICK = 6

_task: asyncio.Task | None = None
_stop = False

_last_poll: dict[str, float] = {}
_last_active: dict[str, float] = {}
_poll_locks: dict[str, asyncio.Lock] = {}
_failures: dict[str, int] = {}

ACTIVE_WINDOW_SECONDS = 15 * 60


def _lock_for(address: str) -> asyncio.Lock:
    lock = _poll_locks.get(address)
    if lock is None:
        lock = asyncio.Lock()
        _poll_locks[address] = lock
    return lock


def is_mailtm_account(address: str) -> bool:
    key = str(address or "").strip().lower()
    if not key or "@" not in key:
        return False
    try:
        with DBConnection() as db:
            row = db.get_security_email_record(key)
    except Exception:
        log.exception("poller: failed to look up %s", key)
        return False
    if not row:
        return False
    provider = str(row[2] or "local").strip().lower()
    return provider == "mailtm"


def stored_token(address: str) -> str | None:
    """Token saved in the DB when we last logged into this mailbox."""
    key = str(address or "").strip().lower()
    try:
        with DBConnection() as db:
            row = db.get_security_email_record(key)
    except Exception:
        return None
    if not row:
        return None
    token = row[3]
    return str(token) if token else None


def _login_hint(address: str) -> dict | None:
    try:
        with DBConnection() as db:
            row = db.get_security_email_record(address)
    except Exception:
        log.exception("poller: failed to load mailbox %s", address)
        return None
    if not row:
        return None
    email, password, provider, token, account_id = (list(row) + [None] * 5)[:5]
    return {
        "email": str(email or "").strip().lower(),
        "password": str(password or ""),
        "provider": str(provider or "local").strip().lower(),
        "token": token,
        "account_id": account_id,
    }


async def refresh_account(
    address: str,
    *,
    force: bool = False,
    min_interval: float | None = None,
    notify: bool = True,
) -> int:
    """Pull new mail for one mailbox. Returns how many messages were stored.

    Throttled per address (``min_interval``, default from settings) and
    serialised per address so the securing flow can call it in a tight loop.
    """
    key = str(address or "").strip().lower()
    if not key or "@" not in key:
        return 0

    interval = mail_settings.mailtm_settings().get("active_poll_seconds", 2)
    try:
        interval = float(min_interval if min_interval is not None else interval)
    except (TypeError, ValueError):
        interval = 2.0
    interval = max(0.8, interval)

    now = time.monotonic()
    _last_active[key] = now

    if not force and (now - _last_poll.get(key, 0.0)) < interval:
        return 0

    lock = _lock_for(key)
    if lock.locked():
        return 0

    async with lock:
        now = time.monotonic()
        if not force and (now - _last_poll.get(key, 0.0)) < interval:
            return 0

        record = _login_hint(key)
        if not record or record["provider"] != "mailtm":
            return 0

        password = record["password"]
        if not password:
            log.debug("poller: %s has no mail.tm password stored", key)
            return 0

        _last_poll[key] = time.monotonic()

        try:
            messages = await mailtm.list_messages(key, password)
        except mailtm.MailTmError as exc:
            _failures[key] = _failures.get(key, 0) + 1
            log.warning("poller: mail.tm inbox fetch failed for %s: %s", key, exc)
            return 0
        except Exception:
            log.exception("poller: unexpected failure fetching %s", key)
            return 0

        stored = await _store_messages(key, password, messages, notify=notify)

        _failures.pop(key, None)
        try:
            with DBConnection() as db:
                db.touch_security_email_polled(key)
        except Exception:
            log.debug("poller: could not stamp last_polled_at for %s", key)

        return stored


async def _store_messages(
    address: str,
    password: str,
    messages: list[dict],
    *,
    notify: bool = True,
) -> int:
    stored = 0

    for message in messages[:_MAX_MESSAGES_PER_POLL]:
        message_id = mailtm.message_key(message)
        if not message_id:
            continue

        try:
            with DBConnection() as db:
                if db.has_received_message(message_id):
                    continue
        except Exception:
            log.exception("poller: dedupe check failed for %s", message_id)
            continue

        try:
            full = await mailtm.get_message(address, password, str(message.get("id") or message_id))
        except mailtm.MailTmError as exc:
            log.warning("poller: could not read message %s: %s", message_id, exc)
            continue

        subject = str(full.get("subject") or message.get("subject") or "")
        body = mailtm.message_body(full)
        from_address = mailtm.sender_address(full) or mailtm.sender_address(message)
        recipients = mailtm.recipient_addresses(full) or [address]

        try:
            with DBConnection() as db:
                db.add_email(
                    to_address=address,
                    from_address=from_address,
                    subject=subject,
                    body=body,
                    message_id=message_id,
                    provider="mailtm",
                )
        except Exception:
            log.exception("poller: failed to store message %s for %s", message_id, address)
            continue

        stored += 1
        log.info("mail.tm mail for %s: %s", address, subject or "(no subject)")

        try:
            await mailtm.mark_seen(address, password, str(message.get("id") or message_id))
        except Exception:
            log.debug("poller: mark_seen failed for %s", message_id)

        if notify:
            try:
                schedule_forward(
                    from_address=from_address,
                    to_addresses=recipients,
                    subject=subject,
                    body=body,
                )
            except Exception:
                log.exception("poller: forwarding failed for %s", message_id)

    return stored


async def poll_once(*, max_accounts: int = _MAX_ACCOUNTS_PER_TICK, notify: bool = True) -> int:
    """Poll the mailboxes that are due. Returns the number of new messages."""
    if not mail_settings.mailtm_enabled():
        return 0

    try:
        with DBConnection() as db:
            rows = db.get_security_email_accounts(provider="mailtm")
    except Exception:
        log.exception("poller: failed to list mail.tm mailboxes")
        return 0

    if not rows:
        return 0

    cfg = mail_settings.mailtm_settings()
    try:
        idle_interval = float(cfg.get("account_poll_seconds") or 30)
    except (TypeError, ValueError):
        idle_interval = 30.0
    try:
        active_interval = float(cfg.get("active_poll_seconds") or 2)
    except (TypeError, ValueError):
        active_interval = 2.0

    now = time.monotonic()
    due: list[tuple[float, str]] = []
    for row in rows:
        address = str(row[0] or "").strip().lower()
        if not address or "@" not in address:
            continue
        if not str(row[1] or ""):
            continue
        # A mailbox with a pending secure gets polled fast, the rest rotate.
        active = (now - _last_active.get(address, 0.0)) < ACTIVE_WINDOW_SECONDS
        interval = active_interval if active else idle_interval
        age = now - _last_poll.get(address, 0.0)
        if age >= interval:
            due.append((age, address))

    if not due:
        return 0

    # Oldest first — keeps every mailbox moving even with a long rotation.
    due.sort(reverse=True)
    total = 0
    for _, address in due[: max(1, int(max_accounts))]:
        total += await refresh_account(address, min_interval=0.0, notify=notify)

    return total


async def _loop() -> None:
    global _stop
    log.info("mail.tm poller started")
    while not _stop:
        interval = 5.0
        try:
            cfg = mail_settings.mailtm_settings()
            interval = float(cfg.get("poll_interval_seconds") or 5)
        except (TypeError, ValueError):
            interval = 5.0
        interval = max(1.0, min(interval, 60.0))

        try:
            await poll_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("poller: tick failed (continuing)")

        await asyncio.sleep(interval)
    log.info("mail.tm poller stopped")


def start_poller() -> asyncio.Task | None:
    """Start the background poller (no-op when mail.tm is not the provider)."""
    global _task, _stop

    if not mail_settings.mailtm_enabled():
        log.info("mail provider is '%s' — mail.tm poller not started", mail_settings.mail_provider())
        return None

    if _task is not None and not _task.done():
        return _task

    _stop = False
    _task = asyncio.get_event_loop().create_task(_loop())
    return _task


async def stop_poller() -> None:
    global _task, _stop
    _stop = True
    task = _task
    _task = None
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
    await mailtm.aclose()


# Backwards friendly alias used by the OTP wait loop.
async def maybe_refresh(address: str, *, min_interval: float | None = None) -> int:
    """Refresh a mailbox only when it is a mail.tm one (used by get_email_code)."""
    if not mail_settings.mailtm_enabled():
        return 0
    key = str(address or "").strip().lower()
    if not key:
        return 0
    if not is_mailtm_account(key):
        return 0
    return await refresh_account(key, min_interval=min_interval)
