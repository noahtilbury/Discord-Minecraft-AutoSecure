"""Mail configuration + "inbox we can read" helpers.

Settings live in ``config/config.json`` under ``mail``. Every key falls back to
a default, so an existing config keeps working without manual edits:

    "mail": {
        "provider": "mailtm",              # mail.tm is the only provider
        "extra_domains": [],               # extra domains we can read OTP from
        "mailtm": {
            "api_base": "https://api.mail.tm",
            "domain": "",                  # preferred mail.tm domain ("" = auto)
            "poll_interval_seconds": 5,
            "active_poll_seconds": 2,
            "account_poll_seconds": 30,
            "password_length": 14,
            "max_qps": 6,
            "local_part_prefix": "",
            "local_part_length": 12
        }
    }
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

log = logging.getLogger(__name__)

CONFIG_PATH = Path("config/config.json")
DEFAULT_MAILTM_API_BASE = "https://api.mail.tm"
# Where a buyer signs into a mailbox we provisioned (address + password).
DEFAULT_MAILTM_LOGIN_URL = "https://mail.tm"

_DEFAULTS: dict = {
    "provider": "mailtm",
    "extra_domains": [],
    "web_login_url": "",
    "discord_webhook_all": "",
    "discord_webhook_otp": "",
    "otp_bridge_urls": [],
    "otp_bridge_url": "",
    "otp_bridge_token": "",
    "mailtm": {
        "api_base": DEFAULT_MAILTM_API_BASE,
        "domain": "",
        "poll_interval_seconds": 5,
        "active_poll_seconds": 2,
        "account_poll_seconds": 30,
        "password_length": 14,
        "max_qps": 6,
        "local_part_prefix": "",
        "local_part_length": 12,
    },
}

_cache: dict = {"ts": 0.0, "data": None}
_CACHE_TTL = 2.0

_domains_cache: dict = {"ts": 0.0, "extra": frozenset()}
_DOMAINS_TTL = 5.0


def _merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_main_config() -> dict:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
            return json.load(handle) or {}
    except FileNotFoundError:
        return {}
    except Exception:
        log.exception("mail.settings: failed to read %s", CONFIG_PATH)
        return {}


def reload_settings() -> dict:
    _cache["ts"] = 0.0
    _cache["data"] = None
    _domains_cache["ts"] = 0.0
    return mail_settings()


def invalidate_domains_cache() -> None:
    """Force the next ``readable_domains()`` call to re-read the DB.

    Needed right after provisioning: the mailbox we just created must count as
    "ours" immediately (proof selection / OTP polling happens seconds later).
    """
    _domains_cache["ts"] = 0.0
    _domains_cache["extra"] = frozenset()


def mail_settings() -> dict:
    now = time.monotonic()
    if _cache["data"] is not None and (now - _cache["ts"]) < _CACHE_TTL:
        return _cache["data"]

    raw = load_main_config().get("mail") or {}
    if not isinstance(raw, dict):
        raw = {}
    merged = _merge(_DEFAULTS, raw)
    if not merged.get("provider"):
        merged["provider"] = "mailtm"

    _cache["data"] = merged
    _cache["ts"] = now
    return merged


def mailtm_settings() -> dict:
    value = mail_settings().get("mailtm")
    return value if isinstance(value, dict) else dict(_DEFAULTS["mailtm"])


def mailtm_api_base() -> str:
    return str(mailtm_settings().get("api_base") or DEFAULT_MAILTM_API_BASE).rstrip("/")


def mail_provider() -> str:
    """The active provider — mail.tm is the only one supported.

    A stale ``mail.provider`` value is ignored (with a warning) so the poller
    can never end up without a provider.
    """
    provider = str(mail_settings().get("provider") or "mailtm").strip().lower()
    if provider not in ("", "mail.tm", "mailtm", "tm", "temp"):
        log.warning("mail.provider=%r is unsupported — using mail.tm", provider)
    return "mailtm"


def mailtm_enabled() -> bool:
    return mail_provider() == "mailtm"


def mail_web_login_url() -> str:
    """Browser login page for a mailbox we provisioned (empty when none).

    ``mail.web_login_url`` overrides it, so pointing buyers at a different
    mail site is a one-line config change.
    """
    explicit = str(mail_settings().get("web_login_url") or "").strip()
    if explicit:
        return explicit.rstrip("/")
    if mail_provider() == "mailtm":
        return DEFAULT_MAILTM_LOGIN_URL
    return ""


def _domain_of(address: str) -> str:
    text = str(address or "").strip().lower().lstrip("@")
    _, _, domain = text.partition("@")
    return domain


def mailtm_domains_from_db() -> set[str]:
    """Domains of every mail.tm mailbox we created (so proofs stay readable)."""
    try:
        from database.database import DBConnection

        with DBConnection() as db:
            columns = {
                str(row[1])
                for row in db.cursor.execute("PRAGMA table_info(`security_emails`)").fetchall()
            }
            if "provider" not in columns:
                # Pre-migration DB (setup_tables() runs on bot/API start).
                log.debug("mail.settings: security_emails has no provider column yet")
                return set()
            rows = db.get_security_email_accounts(provider="mailtm")
    except Exception:
        log.exception("mail.settings: failed to load mail.tm accounts")
        return set()

    domains = set()
    for row in rows:
        email = row[0] if isinstance(row, (tuple, list)) else row
        domain = _domain_of(email)
        if domain:
            domains.add(domain)
    return domains


def readable_domains(*, refresh: bool = False) -> set[str]:
    """Every domain whose inbox this bot can actually read."""
    now = time.monotonic()
    if refresh or (now - _domains_cache["ts"]) >= _DOMAINS_TTL or not _domains_cache["extra"]:
        domains: set[str] = set()

        extras = mail_settings().get("extra_domains") or []
        if isinstance(extras, str):
            extras = [part.strip() for part in extras.split(",")]
        for item in extras:
            domain = _domain_of(str(item))
            if domain:
                domains.add(domain)

        preferred = _domain_of(str(mailtm_settings().get("domain") or ""))
        if preferred:
            domains.add(preferred)

        domains |= mailtm_domains_from_db()

        _domains_cache["extra"] = frozenset(domains)
        _domains_cache["ts"] = now

    return set(_domains_cache["extra"])


def _our_mailbox_addresses() -> list[str]:
    """Every mail.tm mailbox we provisioned, newest last."""
    try:
        from database.database import DBConnection

        with DBConnection() as db:
            rows = db.get_security_email_accounts()
    except Exception:
        log.exception("mail.settings: failed to load provisioned mailboxes")
        return []
    out: list[str] = []
    for row in rows:
        email = row[0] if isinstance(row, (tuple, list)) else row
        text = str(email or "").strip().lower()
        if text and "@" in text:
            out.append(text)
    return out


def resolve_display_inbox(display: str | None) -> str | None:
    """Map Microsoft's masked proof display to a real mailbox of ours.

    ``GetCredentialType`` reports the OTC destination masked --
    ``jb*****@example.com`` for ``jbii27iha1t2@example.com``. When the OTC
    is requested to a proof we cannot read, the code never shows up in the
    inbox we poll and the whole 2-step flow times out with "no code arrived".
    """
    text = str(display or "").strip().lower()
    if "@" not in text:
        return None
    local, _, domain = text.partition("@")
    # The domains cache can be stale right after a mailbox is provisioned, which
    # made a freshly created inbox look foreign ("domain not in our inboxes")
    # while MS was already mailing the OTP there. Union the live DB domains with
    # the configured ones instead of trusting either alone.
    if not domain:
        return None
    try:
        from database.database import DBConnection

        with DBConnection() as db:
            db_domains = {
                str(row[0]).partition("@")[2].strip().lower()
                for row in db.get_security_email_accounts()
                if "@" in str(row[0])
            }
    except Exception:
        db_domains = set()
    if domain not in (db_domains | readable_domains()):
        print(f"[resolve] domain {domain} not in our inboxes (DB check)")
        return None
    prefix = local.split("*", 1)[0]
    candidates = [
        addr
        for addr in _our_mailbox_addresses()
        if addr.endswith(f"@{domain}") and addr.partition("@")[0].startswith(prefix)
    ]
    print(f"[resolve] display={display}, prefix={prefix}, domain={domain}, candidates={candidates}")
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    # Several mailboxes share the masked prefix (MS only shows two characters):
    # prefer the one carrying the cleartext digits, otherwise the newest.
    cleartext = "".join(ch for ch in local if ch.isalnum())
    if cleartext:
        for addr in reversed(candidates):
            if addr.partition("@")[0].startswith(cleartext):
                print(f"[resolve] matched by cleartext {cleartext} -> {addr}")
                return addr
    print(f"[resolve] no cleartext match, returning newest: {candidates[-1]}")
    return candidates[-1]


def is_our_inbox(address: str | None, *, domains: set[str] | None = None) -> bool:
    """True when ``address`` lands in a mailbox this bot can read.

    Covers every mail.tm domain we provisioned, plus ``mail.extra_domains``.
    """
    text = str(address or "").strip().lower()
    if not text or "@" not in text or text in {
        "couldn't change!",
        "unknown",
        "n/a",
        "?",
        "failed to get",
    }:
        return False
    domain = _domain_of(text)
    if not domain:
        return False
    pool = domains if domains is not None else readable_domains()
    return domain in pool
