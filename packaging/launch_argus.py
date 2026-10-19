"""PyInstaller entry point for the ONE Argus.exe (v1.1.0+).

Kept outside the package so PyInstaller's analysis starts from a
plain script. All it does is hand the launch to
:func:`argus.entry.main`, which routes by how the file was
launched: a person double-clicking gets the GUI; Windows starting
the protection service (argv carries ``--service``) gets the
service host; the GUI's own elevated helpers get setup/uninstall.
"""

import sys

from argus.entry import main

if __name__ == "__main__":
    sys.exit(main())
