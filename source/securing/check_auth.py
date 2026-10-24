"""Poll GetSessionState for the Microsoft Authenticator (NGC) approval.

Upstream shared the login session here; this rebuilds that (the session carries
the NGC cookies the challenge was created with) while keeping the MSPOK client
cookie header that the endpoint expects.

A non-JSON answer (MS error page, 5xx, empty body) used to raise inside the
Discord modal's waiting loop, which killed the flow after the user had already
tapped the number. It now reports "still pending" and logs, so the loop simply
keeps waiting until it times out.
"""

import json
import logging

import httpx

log = logging.getLogger(__name__)

# Values GetSessionState itself returns while the user has not answered yet.
_PENDING = {"SessionState": 1, "AuthorizationState": 1}


async def check_authenticator(flowtoken: str, session: httpx.AsyncClient | None = None) -> dict:
    """Check whether the authenticator request has been confirmed."""
    headers = {
        "Content-Type": "application/json",
        "Cookie": "MSPOK=$uuid-3d6b1bc3-9fcd-4bd0-a4b1-1a8855505627$uuid-1a3e6d72-d224-456d-868f-4b85ff342088$uuid-58a49dcf-5abd-4a23-95ef-ed1b5999931e;",
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": "https://login.live.com",
        "Referer": "https://login.live.com/",
    }
    url = f"https://login.live.com/GetSessionState.srf?mkt=EN-US&lc=1033&slk={flowtoken}&slkt=NGC"

    async def _poll(client: httpx.AsyncClient) -> httpx.Response:
        return await client.post(url, headers=headers, json={"DeviceCode": flowtoken})

    try:
        if session is not None:
            response = await _poll(session)
        else:
            async with httpx.AsyncClient(timeout=None) as own_session:
                response = await _poll(own_session)
    except Exception:
        log.exception("check_authenticator: request failed")
        return dict(_PENDING)

    body = (response.text or "").strip()
    try:
        data = response.json()
    except json.JSONDecodeError:
        log.error(
            "check_authenticator: non-JSON status=%s snippet=%r",
            response.status_code,
            body[:300],
        )
        return dict(_PENDING)

    if not isinstance(data, dict) or "SessionState" not in data or "AuthorizationState" not in data:
        log.error(
            "check_authenticator: unexpected payload status=%s body=%r",
            response.status_code,
            body[:300],
        )
        return dict(_PENDING)

    return data
