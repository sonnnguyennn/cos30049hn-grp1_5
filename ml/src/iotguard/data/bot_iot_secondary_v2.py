"""TRAIN-only sklearn reference fit; serialized inference travels without sklearn."""

from __future__ import annotations

import numpy as np
from sklearn.preprocessing import StandardScaler

from iotguard.data.bot_iot_package_v2 import CATEGORICAL, PREDICTORS, feature_names, validate_inputs


class V2Preprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.vocabulary = {f: set() for f in CATEGORICAL}
        self.finalized = False
        self.samples = 0

    def fit_chunk(self, numeric, categorical, *, partition):
        if partition != "TRAIN" or self.finalized:
            raise ValueError("Fit TRAIN only, before finalize")
        numeric, cats = validate_inputs(numeric, categorical)
        self.scaler.partial_fit(numeric)
        self.samples += len(numeric)
        for j, field in enumerate(CATEGORICAL):
            self.vocabulary[field].update(cats[:, j])
        return self

    def finalize(self):
        if self.finalized or not self.samples:
            raise ValueError("Finalize exactly once after TRAIN")
        vocabulary = {f: sorted(self.vocabulary[f]) for f in CATEGORICAL}
        if any(len(v) >= 65535 for v in vocabulary.values()):
            raise ValueError("Vocabulary exceeds uint16 package schema")
        self.finalized = True
        self.state = {
            "schema": "bot_iot_preprocessor_v2", "fit_partition": "TRAIN", "drop": None,
            "predictors": list(PREDICTORS), "n_samples_seen": self.samples,
            "mean": self.scaler.mean_.tolist(), "var": self.scaler.var_.tolist(),
            "scale": self.scaler.scale_.tolist(), "vocabulary": vocabulary,
            "unknown": {f: {"kind": "reserved_unknown", "field": f, "index": len(vocabulary[f])}
                        for f in CATEGORICAL},
            "encoded_features": feature_names(vocabulary),
        }
        return self.state

    def transform(self, numeric, categorical):
        if not self.finalized:
            raise ValueError("Finalize TRAIN state before transform")
        numeric, cats = validate_inputs(numeric, categorical)
        blocks = [self.scaler.transform(numeric)]
        for j, field in enumerate(CATEGORICAL):
            values = self.state["vocabulary"][field]
            # Reference equality comparisons, separate from portable dictionary indexing.
            known = np.column_stack([cats[:, j] == v for v in values])
            blocks.append(np.column_stack([known, ~known.any(axis=1)]).astype(np.float64))
        return np.concatenate(blocks, axis=1)
