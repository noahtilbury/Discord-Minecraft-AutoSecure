@echo off
REM Setup for Cloudy-Secure: builds config, environment and keeps the download
REM separate from the running source tree.
REM
REM Layout:
REM   source\        every single bot part (updated from update_github.bat)
REM   config\        defaults.json (paste your values here), config.json (created),
REM                  bot.json (created), refresh_posts_state.json (runtime)
REM   start.bat      launcher
REM   update_github.bat  pull updates, keep config/database
REM   readme.md      this document
REM
REM 1.  Creates/setups config\config.json and config\bot.json from their
REM     .example files when they are missing.
REM 2.  Creates the Python environment in source\.venv.
REM 3.  Installs requirements.txt.
REM 4.  Checks the config again and reports a short status.

setlocal

set "REPO_NAME=Cloudy-Secure"
set "PROJECT_ROOT=%~dp0"
set "SOURCE_DIR=%PROJECT_ROOT%source"
set "CONFIG_DIR=%PROJECT_ROOT%config"
set "PYEXE="

chcp 65001 >nul

echo %DATE% %TIME% | findstr /r /c:"^[0-9]{4}-[0-9]{2}-[0-9]{2} " >nul 2>&1
if %errorlevel% equ 0 (
    set "TS=%DATE% %TIME:~0,8%"
) else (
    set "TS=%DATE:~10,4%-%DATE:~4,2%-%DATE:~7,2% %TIME:~0,8%"
)

echo [i] %TS% Setup %REPO_NAME% ...
echo.

REM -------------------------------------------------------------------------
REM 0.  Python must be installed and on PATH.
REM -------------------------------------------------------------------------
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Python was not found on PATH. Install Python 3.11+ and mark
    echo     "Add Python to PATH" on first run, then run this again.
    pause
    exit /b 2
)

REM -------------------------------------------------------------------------
REM 1.  Make sure the source folder exists (update_github.bat fills it).
REM -------------------------------------------------------------------------
if not exist "%SOURCE_DIR%" mkdir "%SOURCE_DIR%"

REM -------------------------------------------------------------------------
REM 2.  Create config files from the examples when they are missing.
REM -------------------------------------------------------------------------
if not exist "%CONFIG_DIR%\config.json" (
    if exist "%CONFIG_DIR%\config.json.example" (
        echo [i] Creating config\config.json from the example.
        copy /y "%CONFIG_DIR%\config.json.example" "%CONFIG_DIR%\config.json" >nul
    ) else (
        echo [!] config\config.json.example was not found.
        exit /b 2
    )
)

if not exist "%CONFIG_DIR%\bot.json" (
    if exist "%CONFIG_DIR%\bot.json.example" (
        echo [i] Creating config\bot.json from the example.
        copy /y "%CONFIG_DIR%\bot.json.example" "%CONFIG_DIR%\bot.json" >nul
    ) else (
        echo [!] config\bot.json.example was not found.
        exit /b 2
    )
)

REM -------------------------------------------------------------------------
REM 3.  Python environment + requirements.
REM -------------------------------------------------------------------------
if not exist "%SOURCE_DIR%\.venv" (
    echo [i] Creating the Python environment in source\.venv ...
    python -m venv "%SOURCE_DIR%\.venv"
)

set "PYEXE=%SOURCE_DIR%\.venv\Scripts\python.exe"
if exist "%PYEXE%" goto :have_python
set "PYEXE=python"
:have_python

%PYEXE% -c "import pycord, discord, httpx" >nul 2>&1
if %errorlevel% neq 0 (
    echo [i] Installing / upgrading requirements ...
    "%PYEXE%" -m pip install --upgrade pip -q
    "%PYEXE%" -m pip install -r "%SOURCE_DIR%\requirements.txt" -q
)

REM -------------------------------------------------------------------------
REM 4.  Config pre-flight.
REM -------------------------------------------------------------------------
echo [i] Checking config ...
%PYEXE% - <<'PY'
import json, sys
from pathlib import Path

root = Path.cwd()
files = {
    "config.json": root / "config" / "config.json",
    "bot.json": root / "config" / "bot.json",
}
for name, path in files.items():
    if not path.is_file():
        print(f"[X] {name} is missing.")
        sys.exit(1)
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception as exc:
        print(f"[X] {name} is not valid JSON: {exc}")
        sys.exit(1)
    if not isinstance(data, dict):
        print(f"[X] {name} must contain a JSON object.")
        sys.exit(1)

cfg = json.load(open(root / "config/config.json", encoding="utf-8"))
tokens = cfg.get("tokens") or {}
if not str(tokens.get("bot_token") or "").strip():
    print("[X] config\config.json has no bot token yet. Set tokens.bot_token and restart.")
    sys.exit(1)

owners = cfg.get("owners") or []
if not any(str(o).strip() not in ("", "0", "None") for o in owners):
    print("[!] config\config.json has no owners yet. Add your Discord user ID.")
    sys.exit(1)
print("[ok] bot token and owners are set.")
PY
if %errorlevel% neq 0 (
    echo.
    echo [!] One of the config files is missing or invalid. Fix the problem
    echo     above, then run this script again.
    pause
    exit /b 1
)

echo.
echo [ok] Setup complete.
echo.
echo [i] Next steps:
echo     1.  Edit config\config.json (tokens, owners, channels, mail, claims ...).
echo     2.  Edit config\bot.json (command toggles, embeds, presence ...).
echo     3.  Double-click start.bat to run the bot.
echo     4.  update_github.bat pulls updates; source\ is replaced, your config stays.
echo.
pause
