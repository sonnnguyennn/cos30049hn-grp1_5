"""Load the checked-in G2A contracts used by deterministic G2B parsing."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
CONTRACT_DIR = PROJECT_ROOT / "artifacts" / "contracts"


class ContractError(ValueError):
    """Raised when a checked-in contract is absent or internally invalid."""


@cache
def load_json_object(path: Path) -> dict[str, Any]:
    """Load one JSON object and cache it by resolved path."""

    resolved = path.resolve()
    try:
        with resolved.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"Unable to load contract {resolved}: {error}") from error
    if not isinstance(payload, dict):
        raise ContractError(f"Contract must be a JSON object: {resolved}")
    return payload


def load_contract(filename: str) -> dict[str, Any]:
    """Load a v1 G2A contract by its repository filename."""

    payload = load_json_object(CONTRACT_DIR / filename)
    if payload.get("contract_version") != "1.0.0":
        raise ContractError(f"Unsupported contract version in {filename}")
    return payload


def n_baiot_feature_names() -> tuple[str, ...]:
    """Return the authoritative 115-column N-BaIoT source order."""

    contract = load_contract("n_baiot_feature_contract_v1.json")
    names = contract.get("ordered_feature_names")
    if not isinstance(names, list) or len(names) != 115 or not all(
        isinstance(name, str) for name in names
    ):
        raise ContractError("N-BaIoT feature contract must contain 115 ordered names")
    return tuple(names)


def bot_iot_source_columns() -> tuple[str, ...]:
    """Return the authoritative 46-column Bot-IoT All-features order."""

    contract = load_contract("bot_iot_secondary_source_contract_v1.json")
    columns = contract.get("ordered_source_columns")
    if not isinstance(columns, list) or len(columns) != 46 or not all(
        isinstance(name, str) for name in columns
    ):
        raise ContractError("Bot-IoT source contract must contain 46 ordered names")
    return tuple(columns)
