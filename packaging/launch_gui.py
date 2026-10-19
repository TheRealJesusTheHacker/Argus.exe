"""PyInstaller entry point for Argus.exe (the GUI).

Kept outside the package so PyInstaller's analysis starts from a
plain script. All it does is start the GUI.
"""

import sys

from argus.gui import main

if __name__ == "__main__":
    sys.exit(main())
