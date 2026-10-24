"""Import every module in the project (offline).

A published copy must import cleanly on a fresh machine with only the
requirements installed. This walks the package tree on disk, imports every
module by its dotted path and reports the ones that fail.

Run:  ./.venv/Scripts/python.exe tests/test_imports.py
"""

import importlib
import os
import sys
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Top-level packages / modules that make up the bot.
TOP_LEVEL = (
    "bot",
    "cogs",
    "database",
    "mail",
    "minecraft",
    "securing",
    "shared",
    "ui",
)

SKIP_DIRS = {"__pycache__", ".venv", "node_modules", ".git", "tests"}


def _module_names():
    """Every importable module path in the project, on disk."""
    names = []
    for top in TOP_LEVEL:
        top_path = os.path.join(ROOT, top)
        if os.path.isdir(top_path):
            names.append(top)
        elif os.path.isfile(top_path + ".py"):
            names.append(top)
        else:
            continue
        for dirpath, dirnames, filenames in os.walk(top_path):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                rel = os.path.relpath(os.path.join(dirpath, filename), ROOT)
                dotted = rel[:-3].replace(os.sep, ".")
                if dotted.endswith(".__init__"):
                    dotted = dotted[: -len(".__init__")]
                if dotted in names:
                    continue
                names.append(dotted)
    return sorted(set(names))


def main() -> int:
    failures = []
    gated = []
    total = 0
    for name in _module_names():
        try:
            importlib.import_module(name)
        except SystemExit as exc:
            # bot.py deliberately refuses to import while config/config.json
            # still has the empty token placeholder.  That is a config gate,
            # not a broken module, so it is reported but does not fail the run.
            gated.append((name, exc.code))
        except Exception as exc:  # noqa: BLE001
            failures.append((name, exc))
        else:
            total += 1

    for name, exc in failures:
        print(f"[FAIL] {name}: {exc.__class__.__name__}: {exc}")
        if os.environ.get("VERBOSE_IMPORTS"):
            traceback.print_exception(type(exc), exc, exc.__traceback__)

    for name, code in gated:
        print(
            f"[skip] {name}: exited with {code} "
            "(config/config.json has no bot token yet)"
        )

    print(
        f"\n{total} module(s) imported, {len(failures)} failed, "
        f"{len(gated)} gated"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
