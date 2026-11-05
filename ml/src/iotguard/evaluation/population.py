"""Exact actual TRAIN membership, compatible with the package metadata identity."""

import hashlib

import numpy as np


class _HashSink:
    def __init__(self):
        self.digest = hashlib.sha256()

    def write(self, data):
        self.digest.update(data)
        return len(data)


def selected_population(metadata, indices, *, chunk_size=100_000):
    """Hash a NumPy v1 metadata array in selected order without materializing it."""
    idx = np.asarray(indices)
    if (
        idx.ndim != 1
        or not len(idx)
        or idx.dtype.kind not in "iu"
        or idx[0] < 0
        or idx[-1] >= len(metadata)
        or np.any(idx[1:] <= idx[:-1])
    ):
        raise ValueError("TRAIN indices must be sorted, unique, integral and in range")
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    sink = _HashSink()
    np.lib.format.write_array_header_1_0(
        sink,
        {
            "descr": np.lib.format.dtype_to_descr(metadata.dtype),
            "fortran_order": False,
            "shape": (len(idx),),
        },
    )
    for start in range(0, len(idx), chunk_size):
        sink.write(np.asarray(metadata[idx[start : start + chunk_size]]).tobytes(order="C"))
    full = len(idx) == len(metadata)  # strict sorted range check implies arange
    return {
        "kind": "full" if full else "subset",
        "rows": len(idx),
        "rows_in_train": len(metadata),
        "indices_sha256": hashlib.sha256(idx.astype("<i8").tobytes()).hexdigest(),
        "indices_representation": "sorted unique little-endian int64 bytes",
        "train_population_sha256": sink.digest.hexdigest(),
        "population_representation": "sha256 of NumPy v1 selected metadata array",
    }
