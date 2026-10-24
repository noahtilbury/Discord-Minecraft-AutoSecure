"""mail.tm mailbox provisioning.

Creates the disposable inboxes used as Microsoft *security emails* (and by the
`email new` command / dashboard). A mail.tm mailbox is an ordinary account
(address + password), so we store both in ``security_emails`` exactly like the
old self-hosted ones — the OTP pipeline keeps working unchanged.
"""

from __future__ import annotations

import logging

from database.database import DBConnection
from mail import mailtm
from mail import settings as mail_settings

log = logging.getLogger(__name__)

_ADDRESS_ATTEMPTS = 4


def _record(row) -> dict | None:
    if not row:
        return None
    email, password, provider, token, account_id = (list(row) + [None] * 5)[:5]
    return {
        "email": str(email or "").strip().lower(),
        "password": str(password or ""),
        "provider": str(provider or "local").strip().lower() or "local",
        "token": token,
        "account_id": account_id,
    }


async def create_security_email(
    *,
    local_part: str | None = None,
    password: str | None = None,
) -> dict:
    """Provision a mail.tm mailbox and store it. Returns the stored record."""
    return await _create_mailtm_email(local_part=local_part, password=password)


async def _create_mailtm_email(*, local_part: str | None = None, password: str | None = None) -> dict:
    domain = await mailtm.pick_domain()
    pwd = password or mailtm.random_password()
    last_error: Exception | None = None

    hint = (local_part or "").strip().lower()

    for attempt in range(_ADDRESS_ATTEMPTS):
        if "@" in hint:
            # Caller asked for a full address — only the first attempt is exact.
            address = hint if attempt == 0 else f"{mailtm.random_local_part()}@{domain}"
        elif hint and attempt == 0:
            address = f"{hint}@{domain}"
        else:
            address = f"{mailtm.random_local_part()}@{domain}"

        try:
            await mailtm.create_account(address, pwd)
        except mailtm.MailTmError as exc:
            last_error = exc
            log.warning("mail.tm account %s failed (%s) — retrying", address, exc)
            continue

        token = None
        account_id = None
        try:
            record = await mailtm.login(address, pwd, force=True)
            token = record.get("token")
            account_id = record.get("account_id")
        except mailtm.MailTmError as exc:
            log.warning("mail.tm login after create failed for %s: %s", address, exc)

        with DBConnection() as db:
            db.add_security_email(
                address,
                pwd,
                provider="mailtm",
                token=token,
                account_id=account_id,
            )

        # The new domain must count as "ours" immediately — the very next step
        # of the secure flow picks proofs / polls this inbox.
        mail_settings.invalidate_domains_cache()

        log.info("mail.tm mailbox ready: %s", address)
        return {
            "email": address,
            "password": pwd,
            "provider": "mailtm",
            "token": token,
            "account_id": account_id,
        }

    raise mailtm.MailTmError(
        f"could not create a mail.tm mailbox after {_ADDRESS_ATTEMPTS} attempts: {last_error}"
    )


def get_security_email(email: str) -> dict | None:
    """Stored mailbox record (provider/password/token) for ``email``."""
    try:
        with DBConnection() as db:
            row = db.get_security_email_record(email)
    except Exception:
        log.exception("failed to read security email record for %s", email)
        return None
    return _record(row)


MAILTM_LOGIN_URL = "https://mail.tm"

_MISSING_MAILBOXES = {
    "",
    "couldn't change!",
    "couldnt change!",
    "unknown",
    "n/a",
    "?",
    "failed to get",
}


def _login_from_record(record: dict | None) -> dict | None:
    """Browser sign-in details for a stored mailbox record (or None)."""
    if not record or not record.get("email"):
        return None

    provider = record.get("provider") or "local"
    password = record.get("password") or ""
    # Only mail.tm mailboxes have a browser login: the legacy local provider is
    # a catch-all SMTP receiver with no account a buyer could sign into.
    login_url = mail_settings.mail_web_login_url() or MAILTM_LOGIN_URL
    web_login = provider == "mailtm" and bool(password) and bool(login_url)

    return {
        "email": record["email"],
        "password": password if web_login else "",
        "provider": provider,
        "login_url": login_url if web_login else "",
        "web_login": web_login,
        "note": (
            f"Log in at {login_url} with this address and password to read the codes."
            if web_login
            else "Self-hosted mailbox — codes are read with /email inbox."
        ),
    }


def mailbox_login(address: str | None) -> dict | None:
    """Sign-in details for the security mailbox behind ``address``.

    A mail.tm mailbox is an ordinary account: the address plus the password we
    generated open it in any browser (the site's "Log in to your account"
    dialog accepts API-created mailboxes). Hand these two values over with a
    sold account and the buyer can read Microsoft codes by hand instead of
    relying on our webhooks. The login page comes from
    ``mail.web_login_url`` (``https://mail.tm`` by default).

    Returns ``None`` when the address is not a mailbox we manage.
    """
    key = str(address or "").strip().lower()
    if key in _MISSING_MAILBOXES or "@" not in key:
        return None

    return _login_from_record(get_security_email(key))


def list_security_emails() -> list[dict]:
    try:
        with DBConnection() as db:
            rows = db.get_security_email_accounts()
    except Exception:
        log.exception("failed to list security emails")
        return []
    return [record for record in (_record(row) for row in rows) if record]


async def delete_security_email(email: str, *, remote: bool = True) -> bool:
    """Drop a mailbox locally (and from mail.tm when we know the password)."""
    address = str(email or "").strip().lower()
    if not address:
        return False

    record = get_security_email(address)

    with DBConnection() as db:
        db.remove_security_email(address)

    mail_settings.invalidate_domains_cache()
    mailtm.forget_token(address)

    if remote and record and record["provider"] == "mailtm" and record["password"]:
        try:
            await mailtm.delete_account(address, record["password"])
        except mailtm.MailTmError as exc:
            log.warning("mail.tm delete_account(%s) failed: %s", address, exc)
            return False

    return True


async def ensure_registered(email: str) -> bool:
    """Make sure we can log into a stored mailbox (re-login if the token died)."""
    record = get_security_email(email)
    if not record or record["provider"] != "mailtm" or not record["password"]:
        return False

    try:
        token_record = await mailtm.login(record["email"], record["password"], force=True)
    except mailtm.MailTmError as exc:
        log.warning("mail.tm login failed for %s: %s", record["email"], exc)
        return False

    with DBConnection() as db:
        db.set_security_email_token(
            record["email"],
            token_record.get("token"),
            token_record.get("account_id"),
        )
    return True
