from __future__ import annotations

import sys
import ctypes
from spoof.platform.base import PlatformAdapter

if sys.platform == "win32":
    from spoof.platform.windows import WindowsAdapter
    _platform = WindowsAdapter()
else:
    from spoof.platform.linux import LinuxAdapter
    _platform = LinuxAdapter()


def get_platform() -> PlatformAdapter:
    return _platform
