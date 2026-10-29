"""Architectural boundary for transforms that will be fitted only after G3."""

from __future__ import annotations

from typing import Protocol, TypeVar

T = TypeVar("T")


class TrainFittedTransform(Protocol[T]):
    """Minimal later-phase transform contract.

    ``fit`` may receive the training partition only, after G3 fixes evaluation boundaries.
    ``transform`` may then process training, validation, or test features. Fitting on the full
    corpus or before the G3 split is prohibited. G2B provides no fitted implementation.
    """

    def fit(self, training_features: T) -> TrainFittedTransform[T]: ...

    def transform(self, features: T) -> T: ...
