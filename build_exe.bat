@echo off
setlocal

echo ============================================
echo   PhishGuard AI - Build Standalone App
echo ============================================
echo.
echo This produces a real, portable PhishGuard.exe that runs without
echo Python installed. Must be run on WINDOWS (PyInstaller builds for
echo whatever OS it runs on — it cannot cross-compile).
echo.

cd /d "%~dp0backend"

where python >nul 2>nul
if errorlevel 1 (
    echo ERROR: Python was not found. Install Python 3.10+ from python.org first.
    pause
    exit /b 1
)

if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)
call venv\Scripts\activate.bat

echo Installing runtime dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install requirements.txt. See messages above.
    pause
    exit /b 1
)

echo Installing build-only dependencies (PyInstaller)...
pip install -r requirements-build.txt
if errorlevel 1 (
    echo ERROR: Failed to install requirements-build.txt. See messages above.
    pause
    exit /b 1
)

echo.
echo Downloading NLTK language data for offline bundling...
python predownload_nltk.py
if errorlevel 1 (
    echo ERROR: Could not download NLTK data. Check your internet connection.
    pause
    exit /b 1
)

echo.
echo Running PyInstaller (this takes a few minutes)...
rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
pyinstaller phishguard.spec --noconfirm
if errorlevel 1 (
    echo.
    echo ERROR: PyInstaller build failed. See the messages above.
    echo Common cause: a "ModuleNotFoundError" for some package during the
    echo build — if you see one, open backend\phishguard.spec, add the
    echo missing module name to the hidden_imports list near the top, and
    echo run this script again. This is normal, expected iteration for a
    echo project with this many dependencies, not a sign of a broken setup.
    pause
    exit /b 1
)

echo.
echo Assembling the portable app folder...
set OUT=dist\PhishGuard

xcopy /E /I /Y "..\frontend" "%OUT%\frontend" >nul
xcopy /E /I /Y "..\models" "%OUT%\models" >nul
xcopy /E /I /Y "..\data" "%OUT%\data" >nul
xcopy /E /I /Y "..\nltk_data" "%OUT%\nltk_data" >nul
if exist "..\phishguard.db" copy /Y "..\phishguard.db" "%OUT%\phishguard.db" >nul
copy /Y "..\README.md" "%OUT%\README.md" >nul
copy /Y "..\SETUP_GMAIL.md" "%OUT%\SETUP_GMAIL.md" >nul
copy /Y "..\SETUP_OUTLOOK.md" "%OUT%\SETUP_OUTLOOK.md" >nul
copy /Y "..\SETUP_YAHOO.md" "%OUT%\SETUP_YAHOO.md" >nul

echo.
echo ============================================
echo   BUILD COMPLETE
echo ============================================
echo.
echo Your standalone app is ready at:
echo   backend\%OUT%\
echo.
echo That entire folder is the app — copy it anywhere, including a
echo different computer with no Python installed, and PhishGuard.exe
echo inside it will run correctly. Double-click PhishGuard.exe to start it.
echo.
echo To enable Gmail/Outlook, put client_secret.json / outlook_secret.json
echo directly in that folder (next to PhishGuard.exe) — see SETUP_GMAIL.md
echo and SETUP_OUTLOOK.md, which are copied into that folder for reference.
echo.
if "%~1"=="chained" exit /b 0
pause
