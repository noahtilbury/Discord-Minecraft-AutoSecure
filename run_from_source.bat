@echo off
REM Run the bot from source\.  Launchers call this, they never run bot.py here.
REM The working directory is source\ so all relative config paths (config\*, logs*)
REM resolve to the source tree and never touch the download root.

setlocal

set "SOURCE_DIR=%~dp0"
cd /d "%SOURCE_DIR%"

REM Force UTF-8 everywhere so guild names with symbols never corrupt the log.
python -c "import sys; [s.reconfigure(encoding='utf-8', errors='replace') for s in (sys.stdout, sys.stderr)]" >nul 2>&1

set "LOCK=%CD%\logs\bot.lock"
if exist "%LOCK%" (
    set /p OLD_PID=<"%LOCK%"
    echo [i] Existing lock: %OLD_PID%
    tasklist /FI "PID eq %OLD_PID%" 2>nul | find /i "python" >nul
    if %errorlevel% equ 0 (
        echo [X] Another bot instance is already running (pid %OLD_PID%). Delete %LOCK% to restart.
        exit /b 1
    )
)

echo [i] Launching bot from %CD%
python bot.py
if %errorlevel% neq 0 (
    echo [X] bot.py exited with code %errorlevel%.
    pause
)
