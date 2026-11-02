"""Proposed Bot-IoT transaction-only assembly; no split adoption or model fitting."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from iotguard.data.bot_iot import BotIoTParseError, BotIoTRecord

NUMERIC = ("pkts", "bytes", "dur", "spkts", "dpkts", "sbytes", "dbytes",
           "rate", "srate", "drate")
CATEGORICAL = ("flgs", "proto", "state")
PREDICTORS = NUMERIC + CATEGORICAL
COUNTS = frozenset(("pkts", "bytes", "spkts", "dpkts", "sbytes", "dbytes"))


@dataclass(frozen=True)
class SecondaryRow:
    """Validated pre-encoding X plus separate label, lineage and context."""

    values: tuple[float | str, ...]
    target: int
    metadata: dict
    equivalence_sha256: str


def assemble_secondary(record: BotIoTRecord) -> SecondaryRow:
    """Validate selected fields, preserve excluded context, normalize numeric equivalence."""
    fields = {k: v for group in record.fields_by_role.values() for k, v in group.items()}
    values: list[float | str] = []
    for name in NUMERIC:
        try:
            value = float(fields[name])
        except (ValueError, KeyError) as error:
            raise BotIoTParseError(f"Invalid numeric field {name}") from error
        if not np.isfinite(value) or value < 0 or (name in COUNTS and not value.is_integer()):
            raise BotIoTParseError(f"Invalid nonnegative numeric field {name}: {fields[name]!r}")
        if name in COUNTS:
            try:
                exact = Decimal(fields[name])
            except InvalidOperation as error:
                raise BotIoTParseError(f"Invalid exact count: {name}") from error
            if exact > 2**53 or exact != exact.to_integral_value():
                raise BotIoTParseError(f"Count not an exact float64 integer: {name}")
        values.append(0.0 if value == 0 else value)
    for name in CATEGORICAL:
        value = fields[name]
        if not value or value != value.strip() or value.lower() in {"nan", "null", "none"}:
            raise BotIoTParseError(f"Missing/invalid categorical field {name}: {value!r}")
        values.append(value)  # Exact case and flag syntax retained; no ordinal code assumption.
    attack = record.target_metadata["attack"]
    if attack not in {"0", "1"}:
        raise BotIoTParseError(f"Invalid attack target: {attack!r}")
    metadata = {
        **record.target_metadata, **record.identifier_metadata,
        "source_shard": record.source_shard, "data_row_index": record.data_row_index,
        "excluded_context": {name: fields[name] for name in
                             ("stime", "ltime", "seq", "saddr", "daddr")},
        "ports": {name: {"raw": port.raw, "kind": port.kind, "value": port.value}
                  for name, port in record.ports.items()},
    }
    payload = json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode()
    return SecondaryRow(tuple(values), int(attack), metadata, hashlib.sha256(payload).hexdigest())


def feature_frame(rows: list[SecondaryRow]) -> pd.DataFrame:
    """Create exact ordered assembly frame, with float64 numeric columns."""
    frame = pd.DataFrame([row.values for row in rows], columns=PREDICTORS)
    return frame.astype(dict.fromkeys(NUMERIC, "float64"))


class SecondaryPreprocessor:
    """Fit numeric scaling and category vocabulary on an explicitly named TRAIN only."""

    def __init__(self) -> None:
        self.transformer = ColumnTransformer([
            ("numeric", StandardScaler(), list(NUMERIC)),
            ("categorical", OneHotEncoder(handle_unknown="error", dtype=np.float64),
             list(CATEGORICAL)),
        ])
        self.fitted = False

    @staticmethod
    def _check(frame: pd.DataFrame) -> None:
        if tuple(frame.columns) != PREDICTORS:
            raise ValueError("Feature order must exactly match candidate predictors")
        numeric = frame[list(NUMERIC)].to_numpy(dtype=np.float64)
        if not np.isfinite(numeric).all() or (numeric < 0).any():
            raise ValueError("Invalid numeric input")
        for name in COUNTS:
            column = frame[name].to_numpy(dtype=np.float64)
            if (column > 2**53).any() or (column != np.floor(column)).any():
                raise ValueError(f"Invalid count: {name}")
        for name in CATEGORICAL:
            if not frame[name].map(lambda x: isinstance(x, str) and bool(x)
                                   and x == x.strip()
                                   and x.lower() not in {"nan", "null", "none"}).all():
                raise ValueError(f"Invalid categorical input: {name}")

    def fit(self, frame: pd.DataFrame, *, partition: str) -> SecondaryPreprocessor:
        if partition != "TRAIN" or self.fitted:
            raise ValueError("Fit once on TRAIN; VALIDATION/TEST are transform-only")
        self._check(frame)
        self.transformer.fit(frame)
        self.fitted = True
        return self

    def transform(self, frame: pd.DataFrame):
        if not self.fitted:
            raise ValueError("TRAIN preprocessing has not been fitted")
        self._check(frame)
        return self.transformer.transform(frame)
