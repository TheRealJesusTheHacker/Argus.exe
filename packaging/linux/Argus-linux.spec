# PyInstaller spec for the Linux Argus — the whole product in one
# file, exactly as on Windows (v1.2.0+): GUI, protection service
# host, and setup logic, routed at launch by argus.entry. The
# .deb (packaging/linux/build-deb.sh) installs this binary as
# /usr/lib/argus/argus; systemd runs it with --service, the
# desktop entry runs it plain for the GUI.
#
# Build (from the repo root, on Linux):
#     pyinstaller packaging/linux/Argus-linux.spec
# Output: dist/argus
#
# One-file. PySide6 is bundled by PyInstaller's Qt hooks. The
# Linux platform layer (argus.linuxservice, argus.socket_channel,
# argus.platform_dpkg, argus.inotify_watcher) is imported lazily
# by design, so it is named in hiddenimports — the same treatment
# the Windows service stack gets in packaging/Argus.spec.
# pywin32 does not exist on Linux and appears nowhere here; the
# Windows-only modules stay out of this build entirely.
#
# console=True so the systemd daemon's logging reaches the
# journal and `argus service status` prints in a terminal; the
# desktop entry launches the GUI without a terminal
# (Terminal=false), and a Linux binary opens no console window
# of its own either way.

from pathlib import Path

ROOT = Path(SPECPATH).parent.parent

a = Analysis(
    [str(ROOT / "packaging" / "launch_argus.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=[
        # Linux platform layer (lazy by design in argus.service /
        # argus.entry / argus.analyze paths)
        "argus.linuxservice",
        "argus.socket_channel",
        "argus.platform_dpkg",
        "argus.inotify_watcher",
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
    name="argus",
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
)
