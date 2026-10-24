# Contributing

Thanks for looking at Cloudy Secure. It is a small project, so the bar for a pull
request is mostly "it still works on a fresh install".

## Before you open a pull request

1. Create the environment the way a user would:

   ```bat
   setup.bat
   ```

2. Run the checks (no network, no account needed):

   ```powershell
   .venv\Scripts\python.exe -m compileall -q .
   .venv\Scripts\python.exe smoketest_startup.py
   .venv\Scripts\python.exe tests\test_imports.py
   .venv\Scripts\python.exe tests\test_login_session.py
   .venv\Scripts\python.exe tests\test_interactions.py
   .venv\Scripts\python.exe tests\test_guilds.py
   ```

   All five scripts have to exit `0`.

3. Keep `config/config.json`, `config/bot.json`, `database/*.db`, `logs/` and
   `.venv/` out of your commit - they are gitignored, so `git status` should never
   show them.

## Style

- Follow the file you are editing: 4-space indent, `from __future__ import
  annotations` at the top of a module, one class/function per logical block.
- No new runtime dependencies without a reason - `requirements.txt` is intentionally
  tiny so a clone installs fast.
- Comments explain *why*, not *what*. Do not add comments that restate the line
  below them.
- Never log or embed a token, a webhook URL, a mailbox password or the secured
  account's data.

## Things that are easy to get wrong

- **Discord interactions.** Answer every interaction exactly once. Use the helpers
  in `shared/interactions.py` (`respond`, `defer`, `edit`, `followup`,
  `followup_message`, `send_modal`) instead of calling `ctx.respond` /
  `ctx.followup.send` / `ctx.response.defer` directly - the helpers turn expired
  (error `10062`) and already-answered interactions into a logged no-op.
- **Components V2 cards.** `ui/theme.py` builds the cards; a new card has to build
  with `smoketest_startup.py`, which renders every one of them.
- **User-facing text.** A verify card may only show a short, non-technical reason.
  Internal details belong in `logs/securing.log` and the logs channel.

## Reporting a security problem

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).
