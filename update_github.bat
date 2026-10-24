@echo off
REM Pull the latest source from GitHub and keep the user config safe.
REM
REM Layout:
REM   source\        every single bot part.  This is what gets replaced.
REM   config\        config.json, bot.json, defaults.json, refresh_posts_state.json
REM                  (these are never touched by an update)
REM   database\      SQLite files are kept.
REM   logs\          logs are kept.
REM   .venv\         environment is recreated/updated.
REM   readme.md      this document
REM
REM The bot must be stopped before this runs: it replaces source\ entirely.
REM Stop the bot, close the window, then run this script - or pass /y to skip
REM the confirmation.

setlocal

set "REPO_NAME=Cloudy-Secure"
set "PROJECT_ROOT=%~dp0"
set "SOURCE_DIR=%PROJECT_ROOT%source"
set "CONFIG_DIR=%PROJECT_ROOT%config"
set "DB_DIR=%PROJECT_ROOT%database"
set "LOG_DIR=%PROJECT_ROOT%logs"
set "VENV_DIR=%SOURCE_DIR%\.venv"

chcp 65001 >nul

echo %DATE% %TIME% | findstr /r /c:"^[0-9]{4}-[0-9]{2}-[0-9]{2} " >nul 2>&1
if %errorlevel% equ 0 (
    set "TS=%DATE% %TIME:~0,8%"
) else (
    set "TS=%DATE:~10,4%-%DATE:~4,2%-%DATE:~7,2% %TIME:~0,8%"
)

echo [i] %TS% Updating %REPO_NAME% ...
echo.

:check
echo [i] Checking for a running bot ...
if exist "%LOG_DIR%\bot.lock" (
    set /p OLD_PID=<"%LOG_DIR%\bot.lock"
    echo [i] Existing lock: %OLD_PID%
    tasklist /FI "PID eq %OLD_PID%" 2>nul | find /i "python" >nul
    if %errorlevel% equ 0 (
        echo [X] The bot is still running (pid %OLD_PID%). Stop it, then run this again.
        pause
        exit /b 1
    )
)

if "%1" == "/y" goto :yes
echo [i] The bot source tree will be replaced from GitHub.
echo     Your config\*, database\* and logs\* are kept - only source\* is replaced.
echo.
set /p YES=no= Continue? [Y/n]:
if /i not "%YES%" == "Y" (
    echo [i] cancelled.
    pause
    exit /b 0
)
:yes

echo [i] Stopping any local pm2 processes ...
call npm run stop >nul 2>&1

REM -------------------------------------------------------------------------
REM 1.  Download the latest source into source\. The download root also contains
REM     the same files as source\ - but the bot must read from source\ because
REM     that is where run_from_source.bat cd's to and where the .venv lives.
REM -------------------------------------------------------------------------
if not exist "%SOURCE_DIR%" mkdir "%SOURCE_DIR%"

echo [i] Fetching the latest source from GitHub ...
call git -C "%SOURCE_DIR%" fetch origin main >nul 2>&1
if %errorlevel% neq 0 (
    echo [i] git fetch failed (or this folder is not a git clone). Downloading a
    echo     fresh source archive from GitHub instead.
    call curl -L -o "%TEMP%\source.zip" "https://github.com/noahtilbury/Cloudy-Secure/archive/refs/heads/main.zip" >nul 2>&1
    if %errorlevel% neq 0 (
        echo [X] Could not download the source archive.
        pause
        exit /b 3
    )
    tar -xf "%TEMP%\source.zip" -C "%SOURCE_DIR%" >nul 2>&1
    if %errorlevel% neq 0 (
        echo [X] Could not unpack the source archive.
        pause
        exit /b 7
    )
    ren "%SOURCE_DIR%\Cloudy-Secure-main" "%SOURCE_DIR%" 2>nul
    if exist "%SOURCE_DIR%\Cloudy-Secure-main" ren "Cloudy-Secure-main" "Cloudy-Secure-main-keep" 2>nul
)

REM -------------------------------------------------------------------------
REM 2.  Copy the user config + database + logs into source\ so the bot that
REM     now reads from source\ still sees its own files. The download root
REM     keeps the originals.
REM -------------------------------------------------------------------------
echo [i] Keeping your config, database and logs ...
if exist "%CONFIG_DIR%" xcopy /s /y /i /q "%CONFIG_DIR%\*" "%SOURCE_DIR%config\" >nul 2>&1
if exist "%DB_DIR%" xcopy /s /y /i /q "%DB_DIR%\*" "%SOURCE_DIR%database\" >nul 2>&1
if exist "%LOG_DIR%" xcopy /s /y /i /q "%LOG_DIR%\*" "%SOURCE_DIR%logs\" >nul 2>&1

REM -------------------------------------------------------------------------
REM 3.  Install requirements into source\.venv.
REM -------------------------------------------------------------------------
echo [i] Installing requirements into source\.venv ...
if not exist "%VENV_DIR%" (
    python -m venv "%VENV_DIR%"
)
set "PYEXE=%VENV_DIR%\Scripts\python.exe"
if exist "%PYEXE%" goto :have_python
set "PYEXE=python"
:have_python

%PYEXE% -m pip install --upgrade pip -q
%PYEXE% -m pip install -r "%SOURCE_DIR%\requirements.txt" -q

REM -------------------------------------------------------------------------
REM 4.  Remove any stale .pyc files from the updated code.
REM -------------------------------------------------------------------------
echo [i] Cleaning cached bytecode ...
if exist "%SOURCE_DIR%\.venv\Lib\site-packages\__pycache__" rmdir /s /q "%SOURCE_DIR%\.venv\Lib\site-packages\__pycache__" >nul 2>&1
if exist "%SOURCE_DIR%\__pycache__" rmdir /s /q "%SOURCE_DIR%\__pycache__" >nul 2>&1
if exist "%SOURCE_DIR%\*.pyc" del /q "%SOURCE_DIR%\*.pyc" >nul 2>&1

echo.
echo [ok] Update complete. The bot source has been updated.
echo. 3 files to note:
echo     - source\ now holds the latest bot parts.
echo     - config\ and database\ and logs\ are untouched.
echo.
echo [i] Restart the bot: double-click start.bat.
echo.
pause
