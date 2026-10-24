"""mail.tm REST client — free disposable inboxes, no domain or SMTP needed.

Docs: https://docs.mail.tm  (base ``https://api.mail.tm``)

* ``GET  /domains``            -> pick an active public domain
* ``POST /accounts``           -> create a mailbox (address + password)
* ``POST /token``              -> bearer token for that mailbox
* ``GET  /messages``           -> inbox list (paged)
* ``GET  /messages/{id}``      -> full body (``text`` / ``html``)
* ``PATCH/DELETE /messages/{id}``

The service allows **8 queries per second per IP**, so every call goes through a
small pacer and a retry/backoff wrapper.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import string
import time

import httpx

from mail import settings as mail_settings

log = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(25.0, connect=15.0)
_BACKOFF = (0.6, 1.5, 3.0)

# token cache: address -> {"token", "account_id", "ts"}
_tokens: dict[str, dict] = {}

_pace_lock: asyncio.Lock | None = None
_last_call = 0.0
_client: httpx.AsyncClient | None = None


class MailTmError(RuntimeError):
    """Any mail.tm failure (HTTP error, rate limit, bad payload)."""


class MailTmAuthError(MailTmError):
    """Mailbox login rejected (wrong password / deleted account)."""


class MailTmRateLimited(MailTmError):
    """429 — caller should slow down."""


def _headers(*, token: str | None = None) -> dict:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            base_url=mail_settings.mailtm_api_base(),
            timeout=_TIMEOUT,
            follow_redirects=True,
        )
    return _client


async def aclose() -> None:
    global _client
    if _client is not None and not _client.is_closed:
        try:
            await _client.aclose()
        except Exception:
            pass
    _client = None


async def _pace() -> None:
    """Keep well under mail.tm's 8 QPS per-IP limit."""
    global _pace_lock, _last_call

    if _pace_lock is None:
        _pace_lock = asyncio.Lock()

    try:
        qps = float(mail_settings.mailtm_settings().get("max_qps") or 6)
    except (TypeError, ValueError):
        qps = 6.0
    interval = 1.0 / max(1.0, min(qps, 7.0))

    async with _pace_lock:
        now = time.monotonic()
        wait = _last_call + interval - now
        if wait > 0:
            await asyncio.sleep(wait)
        _last_call = time.monotonic()


def _error_detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except Exception:
        return (response.text or "")[:300]

    if isinstance(payload, dict):
        for key in ("message", "detail", "hydra:description"):
            value = payload.get(key)
            if value:
                return str(value)[:300]
        if isinstance(payload.get("violations"), list):
            parts = [
                str(v.get("message") or v)
                for v in payload["violations"]
                if isinstance(v, dict)
            ]
            if parts:
                return "; ".join(parts)[:300]
        return json.dumps(payload)[:300]
    return str(payload)[:300]


async def _request(
    method: str,
    path: str,
    *,
    token: str | None = None,
    json_body: dict | None = None,
    params: dict | None = None,
    expected: tuple[int, ...] = (200, 201, 204),
    retries: int = 3,
) -> httpx.Response:
    last_error: Exception | None = None

    for attempt in range(retries):
        try:
            await _pace()
            client = await _get_client()
            response = await client.request(
                method,
                path,
                headers=_headers(token=token),
                json=json_body,
                params=params,
            )
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            last_error = exc
            log.warning("mail.tm %s %s network error: %s", method, path, exc)
            if attempt + 1 < retries:
                await asyncio.sleep(_BACKOFF[min(attempt, len(_BACKOFF) - 1)])
                continue
            raise MailTmError(f"mail.tm unreachable: {exc}") from exc

        if response.status_code in expected:
            return response

        detail = _error_detail(response)
        status = response.status_code

        if status == 429:
            retry_after = 1.5 * (attempt + 1)
            try:
                retry_after = max(retry_after, float(response.headers.get("retry-after") or 0))
            except (TypeError, ValueError):
                pass
            log.warning("mail.tm rate limited on %s %s (%s)", method, path, detail)
            last_error = MailTmRateLimited(detail)
            if attempt + 1 < retries:
                await asyncio.sleep(retry_after)
                continue
            raise MailTmRateLimited(detail)

        if status >= 500 and attempt + 1 < retries:
            log.warning("mail.tm %s %s -> %s (%s), retrying", method, path, status, detail)
            last_error = MailTmError(f"HTTP {status}: {detail}")
            await asyncio.sleep(_BACKOFF[min(attempt, len(_BACKOFF) - 1)])
            continue

        if status in (401, 403):
            raise MailTmAuthError(f"HTTP {status}: {detail}")

        raise MailTmError(f"HTTP {status}: {detail}")

    raise MailTmError(str(last_error) if last_error else "mail.tm request failed")


def _collection(payload) -> list[dict]:
    """mail.tm returns a plain array for ``application/json`` and a Hydra
    envelope (``hydra:member``) for JSON-LD — accept both."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("hydra:member", "member", "items", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


# --------------------------------------------------------------------------- #
# domains / accounts
# --------------------------------------------------------------------------- #
async def list_domains(*, active_only: bool = True) -> list[dict]:
    domains: list[dict] = []
    page = 1
    while page <= 10:
        response = await _request("GET", "/domains", params={"page": page})
        chunk = _collection(response.json())
        if not chunk:
            break
        domains.extend(chunk)
        if len(chunk) < 30:
            break
        page += 1

    if active_only:
        domains = [
            item
            for item in domains
            if item.get("isActive", True) and not item.get("isPrivate", False)
        ]
    return domains


async def pick_domain(preferred: str | None = None) -> str:
    """Choose an active mail.tm domain (prefers the configured one)."""
    desired = str(preferred or mail_settings.mailtm_settings().get("domain") or "").strip().lower()
    domains = await list_domains()
    if not domains:
        raise MailTmError("mail.tm returned no active public domains")

    names = [str(item.get("domain") or "").strip().lower() for item in domains]
    names = [name for name in names if name]

    if desired:
        for name in names:
            if name == desired:
                return name
        log.warning("mail.tm: preferred domain %s is not active — picking another", desired)

    return names[0]


def random_local_part(prefix: str | None = None, length: int | None = None) -> str:
    cfg = mail_settings.mailtm_settings()
    prefix = str(cfg.get("local_part_prefix") if prefix is None else prefix or "")
    try:
        length = int(cfg.get("local_part_length") if length is None else length)
    except (TypeError, ValueError):
        length = 12
    length = max(6, min(length, 24))

    alphabet = string.ascii_lowercase + string.digits
    body_len = max(1, length - len(prefix))
    body = "".join(secrets.choice(alphabet) for _ in range(body_len))
    local = f"{prefix}{body}"
    # mail.tm rejects local parts starting with a digit on some domains
    if local[0].isdigit():
        local = f"m{local}"[:length]
    return local


def random_password(length: int | None = None) -> str:
    cfg = mail_settings.mailtm_settings()
    try:
        length = int(cfg.get("password_length") if length is None else length)
    except (TypeError, ValueError):
        length = 14
    length = max(10, min(length, 40))

    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


async def create_account(address: str, password: str) -> dict:
    response = await _request(
        "POST",
        "/accounts",
        json_body={"address": address, "password": password},
        expected=(200, 201, 422),
    )
    payload = response.json() if response.content else {}
    if response.status_code == 422:
        raise MailTmError(
            f"mail.tm rejected {address}: {_error_detail(response) or 'address unavailable'}"
        )
    return payload if isinstance(payload, dict) else {}


async def get_token(address: str, password: str) -> dict:
    response = await _request(
        "POST",
        "/token",
        json_body={"address": address, "password": password},
        expected=(200,),
    )
    payload = response.json()
    if not isinstance(payload, dict) or not payload.get("token"):
        raise MailTmAuthError("mail.tm login returned no token")

    record = {
        "token": str(payload["token"]),
        "account_id": str(payload.get("id") or ""),
        "ts": time.time(),
    }
    _tokens[address.strip().lower()] = record
    return record


def cached_token(address: str) -> dict | None:
    return _tokens.get(str(address or "").strip().lower())


def forget_token(address: str) -> None:
    _tokens.pop(str(address or "").strip().lower(), None)


async def login(address: str, password: str, *, force: bool = False) -> dict:
    key = str(address or "").strip().lower()
    if not force and key in _tokens:
        return _tokens[key]
    return await get_token(key, password)


async def account_info(address: str, password: str) -> dict:
    record = await login(address, password)
    response = await _request("GET", "/me", token=record["token"])
    payload = response.json()
    return payload if isinstance(payload, dict) else {}


async def delete_account(address: str, password: str) -> None:
    record = await login(address, password)
    account_id = record.get("account_id")
    if not account_id:
        info = await account_info(address, password)
        account_id = info.get("id")
    if not account_id:
        raise MailTmError("cannot delete mail.tm account without its id")
    await _request("DELETE", f"/accounts/{account_id}", token=record["token"])
    forget_token(address)


# --------------------------------------------------------------------------- #
# messages
# --------------------------------------------------------------------------- #
async def list_messages(
    address: str,
    password: str,
    *,
    page: int = 1,
    _retry: bool = True,
) -> list[dict]:
    record = await login(address, password)
    try:
        response = await _request(
            "GET", "/messages", token=record["token"], params={"page": page}
        )
    except MailTmAuthError:
        # Token went stale (mail.tm rotates on new logins) — log in again once.
        if not _retry:
            raise
        forget_token(address)
        await login(address, password, force=True)
        return await list_messages(address, password, page=page, _retry=False)

    return _collection(response.json())


async def get_message(
    address: str,
    password: str,
    message_id: str,
    *,
    _retry: bool = True,
) -> dict:
    record = await login(address, password)
    try:
        response = await _request("GET", f"/messages/{message_id}", token=record["token"])
    except MailTmAuthError:
        if not _retry:
            raise
        forget_token(address)
        await login(address, password, force=True)
        return await get_message(address, password, message_id, _retry=False)

    payload = response.json()
    return payload if isinstance(payload, dict) else {}


async def mark_seen(address: str, password: str, message_id: str, seen: bool = True) -> None:
    try:
        record = await login(address, password)
        await _request(
            "PATCH",
            f"/messages/{message_id}",
            token=record["token"],
            json_body={"seen": seen},
            retries=2,
        )
    except MailTmError as exc:
        log.debug("mail.tm mark_seen(%s) failed: %s", message_id, exc)


async def delete_message(address: str, password: str, message_id: str) -> None:
    record = await login(address, password)
    await _request("DELETE", f"/messages/{message_id}", token=record["token"])


# --------------------------------------------------------------------------- #
# helpers used by the poller / inbox UI
# --------------------------------------------------------------------------- #
_TAG_RE = re.compile(r"<[^>]+>")


def html_to_text(html) -> str:
    """Flatten a mail.tm ``html`` body (list of strings or str) into text."""
    if isinstance(html, list):
        html = "\n".join(str(part) for part in html)
    text = str(html or "")
    if not text:
        return ""
    text = re.sub(r"<(script|style)[\s\S]*?</\1>", " ", text, flags=re.I)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"</p>", "\n", text, flags=re.I)
    text = _TAG_RE.sub(" ", text)
    text = (
        text.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#39;", "'")
        .replace("&quot;", '"')
    )
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def message_body(message: dict) -> str:
    text = str(message.get("text") or "").strip()
    if text:
        return text
    return html_to_text(message.get("html"))


def sender_address(message: dict) -> str:
    sender = message.get("from") or {}
    if isinstance(sender, dict):
        return str(sender.get("address") or sender.get("name") or "")
    return str(sender or "")


def sender_name(message: dict) -> str:
    sender = message.get("from") or {}
    if isinstance(sender, dict):
        return str(sender.get("name") or "")
    return ""


def recipient_addresses(message: dict) -> list[str]:
    recipients = message.get("to") or []
    out: list[str] = []
    if isinstance(recipients, list):
        for item in recipients:
            if isinstance(item, dict) and item.get("address"):
                out.append(str(item["address"]).lower())
            elif isinstance(item, str) and item:
                out.append(item.lower())
    return out


def message_key(message: dict) -> str:
    return str(message.get("msgid") or message.get("id") or "")
