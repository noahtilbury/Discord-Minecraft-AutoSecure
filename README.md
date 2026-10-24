# Cloudy Secure

Autosecure Discord bot + mail automation: slash commands and Components V2 cards,
account-securing flows under `securing/`, mail.tm inbox polling, SQLite persistence,
a claim/giveaway flow, and a Windows launcher plus GitHub updater.

## Quick start (Windows)

```bat
git clone https://github.com/noahtilbury/Cloudy-Secure.git
cd Cloudy-Secure
start.bat
```

Double-click `start.bat` or run it from cmd. On the first run it creates `.venv`,
installs `requirements.txt`, and - because a fresh clone has no `config/config.json` -
creates that file from `config/config.json.example`, prints exactly what to fill in
and stops. Add your bot token and owners, run `start.bat` again, and the bot comes
online. See [First-time setup](#first-time-setup).

There is **no license key, no activation and no licence server**: clone, fill in the
config and run.

`start.bat` is plain batch on purpose: Windows ships with the PowerShell execution
policy set to `Restricted`, so any `.ps1` launcher fails with "running scripts is
disabled on this system" on a fresh machine.

## What is in the project

- `bot.py` - bot entrypoint (mail polling, cogs, gateway)
- `start.bat` - Windows launcher (venv + deps + run)
- `setup.bat` - standalone setup (Python check, venv, deps, config check)
- `setup_check.py` - pre-flight config check used by `setup.bat`
- `update_from_github.bat` - pulls updates, installs requirements, migrates the DB
- `ecosystem.config.cjs` - pm2 process config
- `cogs/` - slash command modules
- `securing/` - verification and account-security automation
- `mail/` - inbound mail (mail.tm) polling and provisioning
- `ui/` - Discord views, modals and Components V2 cards
- `shared/` - shared helpers
- `database/database.py` - SQLite persistence (the `.db` itself is not shipped)
- `minecraft/` - profile/ban/name lookups (ban checks need Node, see below)
- `assets/` - images referenced by the cards
- `config/` - runtime configuration (only the `.example` files are shipped)

## Prerequisites

- **Python 3.11+** - `start.bat` creates the local `.venv` for you
- **Git** - the updater pulls from the repo you cloned
- Optional: **Node.js 18+** only if you enable `autosecure.reject.check_hypixel_ban`
  or `check_donutsmp_ban`; those run `minecraft/ban_check/check.js`, so run
  `cd minecraft\ban_check && npm install` once (its `node_modules/` is gitignored)
- Optional: **pm2** (`npm install -g pm2`) to keep the bot running

`requirements.txt` pins `py-cord>=2.7,<3`: Components V2 (`discord.ui.Container`,
`Section`, `TextDisplay`) does not exist in py-cord 2.6 or older, and the whole
card-based verification flow needs it.

## First-time setup

### 1. Create the Python environment

`start.bat` and `update_from_github.bat` do this automatically. By hand:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

`setup.bat` does the same thing as a separate step and is safe to run again at any
time - it finds a Python 3.11+ interpreter, creates `.venv`, installs
`requirements.txt` and then checks the config:

```bat
setup.bat
```

It ends with one of three messages: the bot is ready, the config still has to be
filled in (it creates the missing files from the `.example` files), or something is
wrong (the message says exactly what). `setup_check.py` is that check on its own and
can be run at any time with `.venv\Scripts\python.exe setup_check.py`.

### 2. Configure the bot

A fresh clone has no `config/config.json` (it is gitignored because it holds the bot
token), so `start.bat` copies `config/config.json.example` to `config/config.json` on
the first run and stops with instructions. By hand:

```powershell
copy config\config.json.example config\config.json
```

Then edit `config/config.json`. `tokens.bot_token` (Discord Developer Portal ->
Bot -> Reset Token) and `owners` (your Discord user ID) are the only values needed
to boot; the rest can stay as shipped:

- `owners`, `tokens.bot_token`, `tokens.skytools_key`, `tokens.donut_key`
- `discord.logs_channel`, `discord.accounts_channel`, `discord.censored_logs_channel`
- `mail.*` - provider, mail.tm settings, webhooks, OTP bridge, `otp_login_email`
  (the fallback login address for the temp-mailbox OTP path; empty = use the secured
  account's own address)
- `claims.*` - see [Claims](#claims)
- `coldproxy.*`, `proxy.*` - only if you use proxies
- `autosecure.*` - rejection and behaviour settings

`config/bot.json` covers behaviour and looks. It is created from
`config/bot.json.example` when it is missing, and it is untracked, so your own
embeds, command names and presence survive an update:

- `enabled_commands` - `true`/`false` for all commands, or an object with `real`
  (per-cog on/off), `fake` and `aliases` (command names)
- `embeds` - verification text and the `components_v2` card styling
- `presence` - `status`, `activity_text`, `activity_type`
- `post_verification`, `refresh_posts` - follow-up actions and periodic reposts

Config is read at startup: restart the bot after editing, and keep the JSON valid
(an invalid file prints the exact parse error and exits).

### 3. Run it

```bat
start.bat
```

or, with the environment already set up:

```powershell
.venv\Scripts\python.exe bot.py
```

### 4. Keep it running (pm2)

`ecosystem.config.cjs` resolves `.venv` relative to itself, so it survives moving or
cloning the folder:

```powershell
npm install -g pm2
pm2 start ecosystem.config.cjs
pm2 logs autosecure-bot
```

## Environment variables

All of them are optional - the defaults work for a normal install.

| Variable | Default | Meaning |
| --- | --- | --- |
| `AUTOSECURE_ALIAS_RETRY` | off | `1` restores the slow wait-and-retry behaviour when the primary alias cannot be changed (up to 3 attempts instead of 1). |
| `AUTOSECURE_PWD_BUDGET` | `18` | Wall-clock budget in seconds for the password-verify escalation. Raise it to allow more `RecoverUser` rounds, lower it to fail faster. |
| `NODE_BIN` | `node` | Path to the Node.js executable used by the Minecraft ban checks. |
| `PYTHONUTF8` | set by the launchers | `1` makes Python use UTF-8 everywhere (Windows consoles otherwise use cp1252 and break on the emoji in the cards). |
| `PYTHONIOENCODING` | set by the launchers | `utf-8` - same reason as above, for stdout/stderr. |
| `PYTHONUNBUFFERED` | set by the launchers | `1` so the log output appears immediately in a console instead of in chunks. |

Example (pm2):

```js
// ecosystem.config.cjs
env: { PYTHONUNBUFFERED: "1", AUTOSECURE_PWD_BUDGET: "25" }
```

## Claims

When a secure succeeds, the bot posts an `@everyone` ping and one Components V2 card
with a single `Claim` button (unless `claims.enabled` is `false`, in which case the hit
channel only gets the usual hit embed).

`config/config.json` -> `claims`:

| Key | Meaning |
| --- | --- |
| `enabled` | Turn the claim card on/off. |
| `claim_button_label` | Text on the button (cosmetic; still one button). |
| `claim_role_id` | Role required to press `Claim`. Empty = claims disabled. |
| `require_minecraft_username` | `true` = pressing `Claim` opens a modal asking for the secured account's Minecraft username; the claim only goes through when it matches the stored name, or when the account has no Minecraft name. `false` = first person to press wins. |
| `claim_requires_verified`, `claim_notes_prompt` | Reserved for the verification-gated/notes variants. |

What a claim does:

1. The presser's role is checked and the claim row is written. A later presser gets
   "already claimed by ..." instead of a second copy.
2. The public card is edited in place: `Claimed by @user` (a real mention) and a
   disabled, greyed `Claimed` button, so it stops being clickable for everyone.
3. The claimer gets one DM with the Microsoft email/password, the temporary mailbox
   credentials, the recovery code and the authenticator secret. Nothing secret is ever
   posted in the hit channel; a blocked DM is reported ephemerally instead.

Claim buttons live in the bot's memory: after a restart, cards posted earlier stop
responding.

## Guild management

`/guilds list` opens an ephemeral, owner-only dashboard for every server the bot is
connected to. It is the only supported way to inspect the bot's server list or remove
it from servers, and it never needs you to join those servers. Use the `Search` button
or `/guilds list query:<name or id>` to filter; the dashboard shows 10 servers per page
with First / Previous / Next / Last controls.

Each entry shows the server name, guild ID, Discord's approximate member count when it
is available, and whether you are personally a member. A lookup that Discord refuses is
shown as `Unknown`, never guessed. Selecting a server opens its detail card with:

- **Invite** - a real existing invite when the bot can see one, the server's vanity
  invite when it has one, or a **Create invite** button when the bot has Create Invite
  permission in a visible text channel. Generated invites last 24 hours and are created
  only when you press the button.
- **Leave server** - a confirmation card; the bot leaves using its own membership, so
  you do not have to be in the server yourself. An already-gone server is reported as
  already left instead of failing.
- **Back to servers** - returns to the same page and search.

Invite limitations are explained in the card instead of being guessed at:

- listing existing invites and vanity invites needs **Manage Server**, which is also
  Discord's own requirement for that API;
- creating an invite needs **Create Invite** in a channel the bot can see; if this is
  missing, no link is shown or fabricated;
- the bot only reads guild data Discord already gives it. It does not try to bypass
  permissions or inspect channels it cannot access.

Only user IDs in `config/config.json` -> `owners` can use `/guilds`. The check runs in
the command, in every button/select/modal callback, and again inside the leave and
create-invite functions. Other users get an ephemeral refusal and cannot perform any
action. The bot token is never read, logged or displayed by this feature.

The dashboard and its replies are ephemeral and expire after 30 minutes; run
`/guilds list` again to reopen it. If `owners` is empty, every management action is
denied, matching the other admin commands. The command alias can be changed with
`enabled_commands.aliases.guilds` in `config/bot.json`; leaving it out keeps the default
`guilds`.

## Verification cards (Components V2)

The verification flow uses Minelink-style Components V2 cards (`ui/theme.py`) - a
`Container` with heading, body and buttons inside the card, which classic embeds cannot
do. The look is configured in `config/bot.json` under `embeds.components_v2`; every key
is optional and anything you leave out keeps the current design:

```json
"components_v2": {
    "colors": {
        "success": "#52A435",
        "error": "#ED4245",
        "warning": "#FEE75C",
        "info": "#5865F2"
    },
    "footer": "",
    "heading_emoji": "\ud83d\udd37",
    "verify_button": { "label": "Verify", "emoji": "\u2705", "style": "success" }
}
```

- `colors` accepts `"#RRGGBB"`, `"0xRRGGBB"` or a decimal integer.
- `footer` is the small line under the verify prompt. It ships empty (no footer);
  set it to `"-# Minecraft Verification"` to get Discord subtext back, or any other
  string to render it as-is.
- `verify_button`: `label`, optional `emoji` (`""` removes it) and one of `primary`,
  `secondary`, `success`, `danger`.
- The card text is `embeds.verify_card` (`title`, `description`, `thumbnail`); if that
  block is empty the card falls back to `embeds.verification.default`.
- `thumbnail` may be a URL or `attachment://minelink.png` for a file in `assets/`
  (the `/send embed` command attaches it automatically).

## Updating an install

Run `update_from_github.bat` inside the project folder (double-click, or from cmd).

1. Prints branch/remote/commit. A folder without `.git` (a ZIP download) skips git
   entirely and takes the ZIP path described below.
2. Fetches `origin` and compares your copy with GitHub.
3. Lists the new commits and asks before changing anything.
4. Pulls with `--ff-only`; if local edits block it, it explains how to keep them or
   how to force GitHub's version (`RESET` prompt).
5. Creates `.venv` if missing, installs `requirements.txt`, re-runs the DB migrations.
6. Creates `config/config.json` from the example on a first run, never overwrites an
   existing one.
7. Tells you whether the bot still needs a restart.

**ZIP installs.** A copy extracted from GitHub's ZIP has no `.git`, so the updater
downloads the latest source archive from the repository and copies it over the folder
instead, keeping `config/config.json`, the database, `logs/` and `.venv/`. It cannot
compare commits, so `/check` exits `10` and a normal run always refreshes to the
latest `main`. The newer updater arrives as `update_from_github.bat.new`; swap it in
with `move /y update_from_github.bat.new update_from_github.bat` after the window
closes.

| Flag | Meaning |
| --- | --- |
| *(none)* | Interactive: asks before pulling, waits for a key at the end. |
| `/check` | Only check. Exit code `10` = update available, `0` = up to date. |
| `/y` | Unattended: no confirmation prompt, no final pause. |

Exit codes: `0` ok/up to date, `2` no git or not a repo, `3` fetch failed,
`4` Python/venv problem, `5` pull blocked by local changes, `7` ZIP download or copy
failed, `10` update available.

`config/`, `config/refresh_posts_state.json`, the SQLite database and `logs/` are
untracked, so updates never touch them.

## Running the checks

There is no pytest dependency: every check is a plain script that exits `0` on
success and prints `[ok]`/`[X]` lines. Run them with the project venv:

```powershell
.venv\Scripts\python.exe smoketest_startup.py
.venv\Scripts\python.exe tests\test_imports.py
.venv\Scripts\python.exe tests\test_login_session.py
.venv\Scripts\python.exe tests\test_interactions.py
.venv\Scripts\python.exe tests\test_guilds.py
```

| Script | What it proves |
| --- | --- |
| `smoketest_startup.py` | The bot entrypoint imports, all cogs load, the persistent views register and every Components V2 card still builds. |
| `tests/test_imports.py` | Every `.py` file in the project imports cleanly (no broken or half-removed module). |
| `tests/test_login_session.py` | The Microsoft login/session helpers work: the classic continuation form and the BSso form are detected and posted, `WLSSC`/`AMCSecAuth` are recognised, and the user-facing failure text never leaks an internal reason. |
| `tests/test_interactions.py` | The Discord interaction helpers turn expired / already-answered interactions into logged no-ops instead of red error boxes. |
| `tests/test_guilds.py` | Owner authorisation, search/pagination, membership lookups, invite selection/creation limits and leave handling (including unavailable and already-left guilds) work offline. |

None of them touch the network or a real account.

The same checks run on every push to `main` through
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) (Python 3.11, 3.12 and
3.13), together with a byte-compile pass and a check that no Discord token or
webhook URL was committed.

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md) - how to set up, which checks to run and the
  conventions the project follows.
- [SECURITY.md](SECURITY.md) - how to report a problem privately.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - the rules for the community spaces.

## Publishing this project

`origin` is `https://github.com/noahtilbury/Cloudy-Secure.git` and
`update_from_github.bat` ships that URL in its hints, plus a warning if a copy still
tracks the old `waitno01/sunnysecure` repo or the previous repository name. To publish
a change:

1. Check nothing sensitive is about to be committed - `config/config.json`, `*.db`,
   `.venv/` and `logs/` are already covered:

   ```bash
   git status --short
   git check-ignore -v config/config.json database/database.db
   ```

2. Commit and push (drop `set-url` unless the remote is wrong):

   ```bash
   git remote set-url origin https://github.com/noahtilbury/Cloudy-Secure.git
   git remote -v
   git add -A
   git commit -m "your change"
   git push origin main
   ```

   Installations that already exist update with `update_from_github.bat`; a first
   push of a brand-new repo needs `-u` once (`git push -u origin main`).

Anyone running `update_from_github.bat` then sees those commits and pulls them with one
keypress. Keep everything users need on `main` and never force-push it - installs that
are behind must be able to fast-forward.

## Troubleshooting

- **"running scripts is disabled on this system"** - you ran a PowerShell script
  such as a `.ps1` launcher; use `start.bat` instead, which needs no PowerShell.
- **"Missing bot config: config/config.json"** - `start.bat` creates that file on the
  first run and says what to fill in. If it is still missing, the copy failed: do it
  by hand with `copy config\config.json.example config\config.json`.
- **"has no bot token yet"** - `tokens.bot_token` in `config/config.json` is empty.
  Paste the token from the Discord Developer Portal, save, run `start.bat` again.
- **"Another autosecure-bot instance is already running"** - another copy holds
  `logs/bot.lock`. Stop that copy, or delete the lock file if that process is gone.
- **Missing module errors** - reinstall into the venv you run:
  `.venv\Scripts\python.exe -m pip install -r requirements.txt`.
- **Commands or views misbehave** - check `config/config.json` and `config/bot.json`
  first: token, guild/channel ids, `enabled_commands`, `claims.claim_role_id`.
- **Mail does not arrive** - the default provider is mail.tm; confirm `mail.provider`,
  the mail.tm settings and any webhook/OTP bridge values.
- **Mail webhook says 404 `Unknown Webhook`** - the webhook in
  `mail.discord_webhook_all` / `discord_webhook_otp` was deleted. The bot checks it
  once at startup, warns in the console, and posts mail to `discord.logs_channel`
  instead. Create a new webhook in the channel and paste its URL into the config.
- **"Unknown Integration" on an old verify or mail card** - that is Discord telling
  you the component's interaction is no longer valid (expired token or a bot
  restart). Mail cards now carry persistent buttons and the verify result falls back
  to a DM, so both keep working; older messages posted before this update still need
  to be re-sent with the command.
- **"This interaction failed" on a button** - the interaction was answered too late
  (Discord's token expired, error `10062`) or it was already answered (the button
  was pressed twice). Every button and modal now answers through
  `shared/interactions.py`, which turns both of those into a logged no-op instead
  of a red error box; the securing result is delivered by DM when the card can no
  longer be edited.
- **The verify card fails with a generic "something went wrong"** - the card only
  ever shows a short, non-technical reason; the details (status codes, missing
  cookies, the Microsoft step that failed) are in `logs/securing.log` and in the
  logs channel, where only you can see them. If the log says the login session is
  missing `WLSSC`/`AMCSecAuth`, the account's Microsoft sign-in was not completed;
  running `/secure` again usually fixes it, and `AUTOSECURE_PWD_BUDGET` can be
  raised to allow more attempts.
- **Ban checks always fail** - `npm install` in `minecraft/ban_check` (Node.js 18+).
- **Updater in a ZIP copy** - a folder without `.git` updates by downloading the latest
  source archive (Git is not needed); `config/`, the database, `logs/` and `.venv/` are
  kept. **"could not be applied cleanly"** - local edits conflict with the update;
  commit them or type `RESET` (your `config/` and database are kept).
- **Logs** - `logs/securing.log`.

## Security note

This project handles account verification and security mail. Treat `config/`, the
database and `logs/` as sensitive, and never commit or share real tokens, webhook URLs,
mailbox credentials or the secured-account data.


```text
Cloudy Secure/
  start.bat                 # launcher (boots the bot from source\)
  setup.bat                 # full setup on its own
  setup_check.py            # pre-flight config check
  update_github.bat         # pulls updates, keeps config/ and database/
  readme.md                 # this document
  source\                   # every single bot part.  The bot runs from here
  config\                   # config.json, bot.json, defaults.json (created)
  database\                 # SQLite files (kept across updates)
  logs\                     # bot.log, securing.log (kept across updates)
  .venv\                    # Python environment (inside source\)
  .github/workflows/ci.yml  # the checks above, run on every push
```

## Packaging it for someone else

Ship the tracked files (a `git clone` or the zip GitHub generates) and nothing else.
Do not include `.venv/`, `logs/`, `__pycache__/`, `database/*.db`,
`config/config.json` or `config/refresh_posts_state.json` - all of it is gitignored, so
a plain clone already excludes them. The recipient runs `start.bat` once to build
`.venv` and get `config/config.json` created from the example, fills in their own token
and ids, and runs `start.bat` again.
