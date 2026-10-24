"""Tests for the safe Discord interaction helpers.

The securing pipeline runs for minutes, so by the time a result card is
written the original interaction token has often expired (404 / 10062), and a
button can be pressed twice (already acknowledged). Both are normal, and
neither may raise out of a button callback — that shows the user
"This interaction failed".

These tests use fake interactions; no Discord connection is made.

Run:  ./.venv/Scripts/python.exe tests/test_interactions.py
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import discord

from shared import interactions as ix


class _Resp:
    def __init__(self, status: int):
        self.status = status
        self.reason = "Not Found"


def _http_exception(status: int = 404, code: int = 10062):
    return discord.HTTPException(
        _Resp(status), {"code": code, "message": "Unknown interaction"}
    )


class _FakeResponse:
    def __init__(self, exc=None):
        self.exc = exc
        self.calls = []

    async def send_message(self, **kwargs):
        self.calls.append(("send_message", kwargs))
        if self.exc:
            raise self.exc
        return "message"

    async def defer(self, **kwargs):
        self.calls.append(("defer", kwargs))
        if self.exc:
            raise self.exc
        return None

    async def edit_message(self, **kwargs):
        self.calls.append(("edit_message", kwargs))
        if self.exc:
            raise self.exc
        return "edited"

    async def send_modal(self, modal):
        self.calls.append(("send_modal", modal))
        if self.exc:
            raise self.exc
        return None


class _FakeFollowup:
    def __init__(self, exc=None):
        self.exc = exc
        self.calls = []

    async def send(self, content=None, **kwargs):
        self.calls.append((content, kwargs))
        if self.exc:
            raise self.exc
        return "followup"


class _FakeInteraction:
    def __init__(self, exc=None):
        self.id = 1
        self.response = _FakeResponse(exc)
        self.followup = _FakeFollowup(exc)
        self.edited = []

    async def edit_original_response(self, **kwargs):
        self.edited.append(kwargs)
        if self.response.exc:
            raise self.response.exc
        return "edited"


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------


def test_is_expired():
    assert ix.is_expired(_http_exception(404, 10062)) is True
    assert ix.is_expired(_http_exception(400, 10062)) is True
    assert ix.is_expired(_http_exception(500, 0)) is False
    assert ix.is_expired(ValueError("nope")) is False


def test_is_already_acknowledged():
    assert ix.is_already_acknowledged(discord.InteractionResponded(None)) is True
    assert ix.is_already_acknowledged(_http_exception(400, 40060)) is True
    assert ix.is_already_acknowledged(_http_exception(404, 10062)) is False


def test_describe():
    text = ix.describe(_http_exception(404, 10062))
    assert "status=404" in text
    assert "code=10062" in text


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


async def _test_respond_success():
    inter = _FakeInteraction()
    assert await ix.respond(inter, "hi") is True
    assert inter.response.calls[0][0] == "send_message"


async def _test_respond_already_acknowledged():
    inter = _FakeInteraction(discord.InteractionResponded(None))
    assert await ix.respond(inter, "hi") is False


async def _test_respond_expired():
    inter = _FakeInteraction(_http_exception(404, 10062))
    assert await ix.respond(inter, "hi") is False


async def _test_respond_reraises_other_errors():
    inter = _FakeInteraction(_http_exception(500, 0))
    try:
        await ix.respond(inter, "hi")
    except discord.HTTPException:
        return True
    raise AssertionError("a 500 must not be swallowed")


async def _test_defer():
    inter = _FakeInteraction()
    assert await ix.defer(inter) is True
    inter = _FakeInteraction(_http_exception(404, 10062))
    assert await ix.defer(inter) is False


async def _test_edit():
    inter = _FakeInteraction()
    assert await ix.edit(inter, content="x") is True
    inter = _FakeInteraction(discord.InteractionResponded(None))
    assert await ix.edit(inter, content="x") is False


async def _test_edit_original():
    inter = _FakeInteraction()
    assert await ix.edit_original(inter, content="x") is True
    inter = _FakeInteraction(_http_exception(404, 10062))
    assert await ix.edit_original(inter, content="x") is False


async def _test_followup():
    inter = _FakeInteraction()
    assert await ix.followup(inter, "hi") is True
    inter = _FakeInteraction(_http_exception(404, 10062))
    assert await ix.followup(inter, "hi") is False


async def _test_followup_message_returns_message():
    inter = _FakeInteraction()
    assert await ix.followup_message(inter, "hi") == "followup"
    inter = _FakeInteraction(_http_exception(404, 10062))
    assert await ix.followup_message(inter, "hi") is None


async def _test_send_modal():
    inter = _FakeInteraction()
    assert await ix.send_modal(inter, "modal") is True
    inter = _FakeInteraction(discord.InteractionResponded(None))
    assert await ix.send_modal(inter, "modal") is False


def main() -> int:
    sync_tests = [
        test_is_expired,
        test_is_already_acknowledged,
        test_describe,
    ]
    async_tests = [
        _test_respond_success,
        _test_respond_already_acknowledged,
        _test_respond_expired,
        _test_respond_reraises_other_errors,
        _test_defer,
        _test_edit,
        _test_edit_original,
        _test_followup,
        _test_followup_message_returns_message,
        _test_send_modal,
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
