# PyInstaller spec for ArgusService.exe — the Windows service host.
#
# Build (from the repo root, on Windows):
#     pyinstaller packaging/ArgusService.spec
# Output: dist/ArgusService.exe
#
# Console build: the Service Control Manager launches it, and the
# same exe answers management commands (install/start/stop/status).
# pywin32's service modules are pulled in via hiddenimports because
# the imports are lazy by design in argus.winservice.

from pathlib import Path

ROOT = Path(SPECPATH).parent

a = Analysis(
    [str(ROOT / "packaging" / "launch_service.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=[
        "win32serviceutil",
        "win32service",
        "win32event",
        "win32com",
        "win32com.client",
        "servicemanager",
        "pywintypes",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ArgusService",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "packaging" / "argus.ico"),
)
