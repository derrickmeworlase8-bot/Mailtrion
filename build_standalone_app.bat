@echo off
setlocal

echo ================================================
echo   PhishGuard AI - Full Standalone App Build
echo ================================================
echo.
echo This builds everything: the Python backend executable, then wraps
echo it in a real Electron desktop app with an installer. Windows only.
echo Takes several minutes, mostly for the backend step.
echo.
pause

cd /d "%~dp0"

echo.
echo ===== STEP 1 of 2: Building the backend executable =====
echo.
call build_exe.bat chained
if not exist "backend\dist\PhishGuard\PhishGuard.exe" (
    echo.
    echo ERROR: backend\dist\PhishGuard\PhishGuard.exe was not produced.
    echo Check the output above for the actual error before continuing.
    pause
    exit /b 1
)

echo.
echo ===== STEP 2 of 2: Building the Electron desktop app =====
echo.
cd electron

where node >nul 2>nul
if errorlevel 1 (
    echo ERROR: Node.js was not found. Install it from https://nodejs.org
    echo ^(the LTS version^) and run this script again.
    pause
    exit /b 1
)

echo Installing Electron build tools ^(first run only, several minutes^)...
call npm install
if errorlevel 1 (
    echo ERROR: npm install failed. See messages above.
    pause
    exit /b 1
)

echo.
echo Building the installer...
call npm run dist
if errorlevel 1 (
    echo ERROR: electron-builder failed. See messages above.
    pause
    exit /b 1
)

echo.
echo ================================================
echo   BUILD COMPLETE
echo ================================================
echo.
echo Your installer and portable app are in:
echo   electron\dist_installer\
echo.
echo - The .exe installer (e.g. "PhishGuard AI Setup 1.0.0.exe") installs
echo   PhishGuard AI like any normal Windows app, with a Start Menu entry.
echo - The portable .exe in the "win-unpacked" folder can be copied to any
echo   folder or machine and run directly with no installation at all.
echo.
echo Either way, this app runs standalone — no Python, no manual setup,
echo just double-click and go. Gmail/Outlook still need their one-time
echo credential files placed next to PhishGuard.exe inside the installed
echo app folder — see SETUP_GMAIL.md / SETUP_OUTLOOK.md.
echo.
pause
