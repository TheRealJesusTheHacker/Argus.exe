# PyInstaller spec for THE Argus.exe — the whole product in one
# file (v1.1.0+): GUI, protection service host, and self-install
# engine, routed at launch by argus.entry.
#
# Build (from the repo root, on Windows):
#     pyinstaller packaging/Argus.spec
# Output: dist/Argus.exe
#
# One-file, no console window: this is the program a person
# downloads and double-clicks. PySide6 is bundled by PyInstaller's
# Qt hooks; the pywin32 service stack is pulled in via
# hiddenimports because those imports are lazy by design in
# argus.winservice / argus.setup_engine (the package imports
# cleanly on any platform, so nothing pulls pywin32 in at module
# level where static analysis would find it on its own).

from pathlib import Path

# PyInstaller 6 does NOT inject the Windows version-info classes
# into the spec namespace — they must be imported explicitly, or
# the build dies with NameError the first time the spec runs
# (v1.1.1 build, step 7). Import exactly the classes used below.
from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo,
    StringFileInfo,
    StringStruct,
    StringTable,
    VSVersionInfo,
    VarFileInfo,
    VarStruct,
)

ROOT = Path(SPECPATH).parent

# Windows version resource for the exe: File Explorer, the task
# manager, and SmartScreen all read THIS — an exe with no version
# info looks anonymous. Version 1.2.11 matches argus.__version__
# (the release workflow's tag check keeps them from drifting).
version_info = VSVersionInfo(
    ffi=FixedFileInfo(
        filevers=(1, 2, 11, 0),
        prodvers=(1, 2, 11, 0),
        mask=0x3F,
        flags=0x0,
        OS=0x40004,
        fileType=0x1,
        subtype=0x0,
        date=(0, 0),
    ),
    kids=[
        StringFileInfo(
            [
                StringTable(
                    "040904B0",
                    [
                        StringStruct(
                            "CompanyName", "Sentinel Safeguard LLC"
                        ),
                        StringStruct(
                            "FileDescription",
                            "ARGUS.EXE — antivirus & malware detector",
                        ),
                        StringStruct("FileVersion", "1.2.11.0"),
                        StringStruct("InternalName", "Argus"),
                        StringStruct(
                            "LegalCopyright",
                            "© Sentinel Safeguard LLC",
                        ),
                        StringStruct("OriginalFilename", "Argus.exe"),
                        StringStruct("ProductName", "ARGUS.EXE"),
                        StringStruct("ProductVersion", "1.2.11"),
                    ],
                )
            ]
        ),
        VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
    ],
)

a = Analysis(
    [str(ROOT / "packaging" / "launch_argus.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=[
        # Windows service stack (argus.winservice / setup engine)
        "win32serviceutil",
        "win32service",
        "win32event",
        "win32com",
        "win32com.client",
        "servicemanager",
        "argus.cli",
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
    name="Argus",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "packaging" / "argus.ico"),
    version=version_info,
)
