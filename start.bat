@echo off
setlocal

echo ============================================
echo   PhishGuard AI - Startup
echo ============================================
echo.

cd /d "%~dp0backend"

REM --- Check Python is installed ---
where python >nul 2>nul
if errorlevel 1 (
    echo ERROR: Python was not found on this system.
    echo Install Python 3.10+ from https://www.python.org/downloads/
    echo During install, make sure "Add python.exe to PATH" is checked.
    pause
    exit /b 1
)

REM --- Create venv if it doesn't exist yet ---
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment.
        pause
        exit /b 1
    )
)

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Installing dependencies (this may take a few minutes the first time)...
python -m pip install --upgrade pip >nul
pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo ERROR: Dependency installation failed. See the messages above.
    echo.
    echo Common cause: pip tried to COMPILE a package from source instead of
    echo using a prebuilt wheel. This usually means your Python version is
    echo too new or too old for one of the pinned package versions.
    echo Fix: install Python 3.11 or 3.12 from python.org, delete the
    echo "venv" folder in this directory, and run start.bat again.
    echo.
    pause
    exit /b 1
)

REM --- Warn (don't fail) if Gmail integration isn't set up yet ---
if not exist client_secret.json (
    echo.
    echo NOTE: client_secret.json not found in backend\
    echo PhishGuard will still run, but Gmail auto-scanning will be disabled.
    echo See SETUP_GMAIL.md in the project root to enable it.
    echo.
)

echo.
echo Starting PhishGuard AI...
echo Once running, open http://localhost:5000 in your browser.
echo.
echo NOTE: The server now only accepts connections from THIS machine
echo (127.0.0.1) for security. It is no longer reachable from other
echo devices on your network. This is intentional.
echo.
echo Press CTRL+C in this window to stop the server.
echo.

REM OAuth libraries require HTTPS by default; this project intentionally
REM uses http://localhost for local development, so this override is needed.
REM Safe here since it only ever applies to localhost traffic on this machine.
set OAUTHLIB_INSECURE_TRANSPORT=1

REM Google sometimes returns a slightly different OAuth scope than requested
REM (e.g. a permission was partially granted). Without this, the token
REM exchange fails outright instead of just accepting what was granted.
set OAUTHLIB_RELAX_TOKEN_SCOPE=1

python app.py

pause
