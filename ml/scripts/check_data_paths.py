"""Validate configured dataset roots without recursively scanning or writing them."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_CONFIG = PROJECT_ROOT / "config" / "data_paths.local.yaml"
EXAMPLE_CONFIG = PROJECT_ROOT / "config" / "data_paths.example.yaml"


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    if not isinstance(config, dict) or not isinstance(config.get("datasets"), dict):
        raise ValueError("Configuration must contain a 'datasets' mapping.")
    return config


def directory_is_readable(path: Path) -> bool:
    if not path.is_dir() or not os.access(path, os.R_OK):
        return False
    try:
        iterator = os.scandir(path)
        iterator.close()
    except OSError:
        return False
    return True


def choose_config(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    return LOCAL_CONFIG if LOCAL_CONFIG.exists() else EXAMPLE_CONFIG


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="Local or example YAML configuration.")
    args = parser.parse_args()

    config_path = choose_config(args.config).resolve()
    config = load_config(config_path)
    print(f"Configuration: {config_path}")

    all_ready = True
    for name, settings in config["datasets"].items():
        if not isinstance(settings, dict) or "root" not in settings:
            print(f"{name}: INVALID (missing root)")
            all_ready = False
            continue
        path = Path(str(settings["root"])).expanduser().resolve()
        exists = path.is_dir()
        readable = directory_is_readable(path)
        role = settings.get("role", "missing")
        print(
            f"{name}: path={path} | exists={str(exists).lower()} "
            f"| readable={str(readable).lower()} | role={role}"
        )
        all_ready &= exists and readable

    return 0 if all_ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
