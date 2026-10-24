from database.database import DBConnection
from mail.poller import maybe_refresh
from mail.settings import mailtm_enabled
import logging

log = logging.getLogger(__name__)


async def fetchInbox(email: str) -> list:
    """Inbox for ``email``.

    mail.tm mailboxes are pulled live first (real-time viewer), then read from
    the local store the poller keeps — so the same call works for mail.tm and
    for legacy self-hosted mailboxes.
    """
    identifier = str(email or "").strip()

    if identifier and mailtm_enabled():
        try:
            await maybe_refresh(identifier, min_interval=1.5)
        except Exception:
            log.exception("fetchInbox: live mail.tm refresh failed for %s", identifier)

    with DBConnection() as db:
        rows = db.get_emails(identifier)

    emails = []
    for _, _, from_addr, subject, body, received_at in rows:
        emails.append(
            f"**From:** {from_addr}\n"
            f"**Subject:** {subject}\n"
            f"**Date:** {received_at}\n\n{body}"
        )

    return emails[::-1]


async def fetchInboxRecords(email: str) -> list[dict]:
    """Structured inbox (dashboard / API): newest first, live-refreshed."""
    identifier = str(email or "").strip()

    if identifier and mailtm_enabled():
        try:
            await maybe_refresh(identifier, min_interval=1.5)
        except Exception:
            log.exception("fetchInboxRecords: live refresh failed for %s", identifier)

    with DBConnection() as db:
        rows = db.get_emails(identifier)

    records = [
        {
            "id": row[0],
            "to_address": row[1],
            "from_address": row[2],
            "subject": row[3],
            "body": row[4],
            "received_at": row[5],
        }
        for row in rows
    ]
    return records[::-1]


async def refreshInbox(email: str, *, force: bool = True) -> int:
    """Force a live mail.tm pull (used by the dashboard refresh button)."""
    identifier = str(email or "").strip()
    if not identifier or not mailtm_enabled():
        return 0
    try:
        return await maybe_refresh(identifier, min_interval=0.0 if force else 1.5)
    except Exception:
        log.exception("refreshInbox failed for %s", identifier)
        return 0
