"""Run sample predictions from a checkout without installing the iotguard package."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from iotguard.inference.sample_prediction import main

if __name__ == "__main__":
    raise SystemExit(main())
