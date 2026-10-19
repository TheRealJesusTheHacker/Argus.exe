"""PyInstaller entry point for ArgusService.exe.

The Service Control Manager launches this executable with no
arguments; ``argus.winservice.main`` routes that to the pywin32
service dispatch. The same executable also answers management
commands: ``ArgusService.exe install|uninstall|start|stop|status``.
"""

import sys

from argus.winservice import main

if __name__ == "__main__":
    sys.exit(main())
