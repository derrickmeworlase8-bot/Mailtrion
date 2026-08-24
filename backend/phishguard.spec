# PhishGuard AI — PyInstaller build spec
#
# Run via build_exe.bat (Windows only — PyInstaller does not cross-compile;
# this must run on the same OS you want the executable to run on).
#
# Produces a "onedir" build (a folder containing PhishGuard.exe plus its
# bundled Python runtime and libraries) rather than a single "onefile" exe.
# onedir starts noticeably faster (no self-extraction on every launch) and
# is easier to debug if something's missing — the right tradeoff here.

import sys
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

# These are libraries that dynamically import submodules (plugins, discovery
# documents, etc.) in ways PyInstaller's static analysis can miss. Listing
# them explicitly here is the standard fix — if the built exe ever errors
# with "ModuleNotFoundError" for something not listed below, add it here
# and rebuild; this is normal, expected iteration for PyInstaller + a stack
# this size, not a sign anything is fundamentally wrong.
hidden_imports = (
    collect_submodules("sklearn")
    + collect_submodules("apscheduler")
    + collect_submodules("googleapiclient")
    + collect_submodules("google_auth_oauthlib")
    + collect_submodules("msal")
    + [
        "gmail_integration",
        "outlook_integration",
        "imap_integration",
        "providers",
        "providers.base",
        "providers.gmail_provider",
        "providers.outlook_provider",
        "providers.imap_provider",
        "poller",
        "paths",
        "waitress",
        "nltk",
    ]
)

a = Analysis(
    ["app.py"],
    pathex=["."],
    binaries=[],
    datas=[],  # deliberately empty — frontend/models/data/db are copied
               # alongside the exe by build_exe.bat, not bundled inside it
               # (see paths.py for why: they need to stay writable)
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PhishGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # UPX can trigger false-positive antivirus flags — skip it
    console=True,        # keep a console window so startup errors are visible;
                          # switch to False once you're confident it's stable
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="PhishGuard",
)
