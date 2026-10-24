"""Per-stage wall-clock timing for the securing pipeline.

The secure flow is mostly serial network work, so "why did this take 4
minutes?" is only answerable if every stage reports its own duration. Each
stage prints one line as soon as it finishes, and the run ends with a summary
that is also appended to ``logs/secure_timing.log``.

Usage (no re-indentation of the block being measured)::

    t0 = start()
    await do_work()
    mark("minecraft check", t0)
"""

from __future__ import annotations

import os
import time

_STAGES: list[tuple[str, float]] = []
_RUN_START: float | None = None


def reset() -> float:
    """Start a new run and return its monotonic start time."""
    global _RUN_START
    _STAGES.clear()
    _RUN_START = time.perf_counter()
    return _RUN_START


def start() -> float:
    return time.perf_counter()


def mark(label: str, started: float, *, quiet: bool = False) -> float:
    """Record + print one stage. Returns the stage duration in seconds."""
    seconds = time.perf_counter() - started
    _STAGES.append((label, seconds))
    if not quiet:
        print(f"[TIMER] {seconds:6.2f}s  {label}", flush=True)
    return seconds


def has_stages() -> bool:
    return bool(_STAGES)


def elapsed(stages: dict[str, float], name: str) -> float:
    return stages.get(name, 0.0)


def summary() -> str:
    total = time.perf_counter() - _RUN_START if _RUN_START is not None else 0.0
    if not _STAGES:
        return f"[TIMER] total {total:.2f}s"
    measured = sum(s for _, s in _STAGES)
    slowest = sorted(_STAGES, key=lambda kv: kv[1], reverse=True)[:5]
    parts = " | ".join(f"{label} {secs:.2f}s" for label, secs in _STAGES)
    top = ", ".join(f"{label} {secs:.1f}s" for label, secs in slowest)
    return (
        f"[TIMER] total {total:.2f}s (stages {measured:.2f}s, "
        f"other {total - measured:.2f}s) — slowest: {top} — {parts}"
    )


def report(total: float | None = None, path: str | None = None) -> str:
    """Print the summary and append it to a log file. Returns the summary."""
    line = summary()
    print(line, flush=True)
    target = path or os.path.join("logs", "secure_timing.log")
    try:
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        prefix = f"{stamp} secured_in={total:.2f}s" if total is not None else stamp
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(f"{prefix} {line}\n")
    except Exception:
        pass
    return line
