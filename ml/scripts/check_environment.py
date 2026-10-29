"""Report the local runtime without changing the machine."""

from __future__ import annotations

import importlib.metadata
import os
import platform
import sys
from pathlib import Path

PACKAGES = ("numpy", "pandas", "psutil", "PyYAML", "scikit-learn", "pytest")


def main() -> int:
    print(f"Python: {platform.python_version()}")
    print(f"Implementation: {platform.python_implementation()}")
    print(f"Platform: {platform.platform()}")
    print(f"Architecture: {platform.machine() or 'unknown'}")
    print(f"Executable: {Path(sys.executable).resolve()}")
    print(f"Working directory: {Path.cwd().resolve()}")
    print(f"Process ID: {os.getpid()}")
    print("Packages:")
    for package in PACKAGES:
        try:
            version = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            version = "not installed"
        print(f"  {package}: {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
