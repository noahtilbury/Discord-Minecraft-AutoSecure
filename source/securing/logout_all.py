import logging

import httpx

log = logging.getLogger(__name__)

# Mirrors the login live-com sign-out URL (documented sign-out navigation).
# Kills the current session cookie jar cleanly on top of the device delete.
_LOGOUT_SRF = "https://login.live.com/logout.srf?wa=wsignin1.0"


async def logout_all(session: httpx.AsyncClient, apicanary: str):
    """Sign out of all devices.

    Two actions:

    1. ``API/Proofs/DeleteDevices`` — removes the registered trusted devices
       (this is what the working reference bot uses).
    2. ``login.live.com/logout.srf`` — performs the real session sign-out on
       the account. Combined with the fresh RecoverUser password set just
       before this step (which invalidates every password-based session),
       other-device access ends.

    Response bodies are logged so the effect is visible in the logs.
    """
    remove = await session.post(
        "https://account.live.com/API/Proofs/DeleteDevices",
        headers={
            "canary": apicanary,
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": "https://account.live.com",
            "Referer": "https://account.live.com/consent/Manage",
        },
        json={
            "uiflvr": 1001,
            "uaid": "abd2ca2a346c43c198c9ca7e4255f3bc",
            "scid": 100109,
            "hpgid": 201030,
        },
        follow_redirects=False,
    )
    body = (remove.text or "").strip()
    if remove.status_code == 200:
        if body:
            print(f"[~] - DeleteDevices response: {body[:300]}")
        print("[+] - Deleted trusted devices")
    else:
        print(f"[X] - Failed DeleteDevices (status={remove.status_code}) {body[:200]}")
        log.warning(
            "DeleteDevices status=%s body=%r", remove.status_code, body[:300]
        )

    # Real session sign-out (logout.srf) — ends the browser/session cookies.
    try:
        out = await session.post(
            _LOGOUT_SRF,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
            data={"wreply": "https://login.live.com/"},
            follow_redirects=True,
        )
        log.info(
            "logout.srf status=%s len=%s", out.status_code, len(out.text or "")
        )
        if out.status_code < 400:
            print("[+] - Signed out everywhere (logout.srf)")
        else:
            print(f"[X] - logout.srf failed (status={out.status_code})")
    except Exception as exc:
        log.warning("logout.srf soft-fail: %s", exc)
        print(f"[~] - logout.srf skipped ({exc.__class__.__name__})")
