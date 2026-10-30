"""Shared binary reporting and validation-only selection, protocol revision 1."""

import math
from copy import deepcopy
from pathlib import Path

import numpy as np
import yaml


def resolve_configuration(*, input_view, parameters, seed_file=None):
    """Resolve the checked-in seed defaults for each future training run."""
    if input_view not in {"raw", "scaled"}:
        raise ValueError("Choose raw or scaled inputs")
    path = (Path(seed_file) if seed_file else
            Path(__file__).resolve().parents[3] / "config/seeds.yaml")
    seeds = yaml.safe_load(path.read_text())["random_seeds"]
    return {"seeds": seeds, "parameters": deepcopy(parameters), "input_view": input_view,
            "threshold": 0.5, "protocol_revision": "primary_experiments_v1"}


def _experiment_identity(result):
    required = ("package_version", "package_manifest_sha256", "protocol_revision",
                "train_population_sha256", "validation_population_sha256", "dirty_worktree")
    if any(key not in result for key in required):
        raise ValueError("Missing required experiment identity")
    for key in ("package_version", "protocol_revision"):
        if not isinstance(result[key], str) or not result[key].strip():
            raise ValueError(f"Invalid {key}")
    for key in ("package_manifest_sha256", "train_population_sha256",
                "validation_population_sha256"):
        value = result[key]
        if (not isinstance(value, str) or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)):
            raise ValueError(f"{key} must be SHA-256 hex")
    if type(result["dirty_worktree"]) is not bool:
        raise ValueError("dirty_worktree must be an explicit boolean")
    if result.get("resolved_configuration", {}).get("protocol_revision") != result[
            "protocol_revision"]:
        raise ValueError("Protocol revision must match resolved configuration")
    return tuple(result[key] for key in required if key != "dirty_worktree")


def experiment_result(run_id, metrics, *, configuration, code_revision, package_version,
                      package_manifest_sha256, dirty_worktree,
                      train_population_sha256, validation_population_sha256):
    """Construct the shared JSON result envelope with explicit resolved configuration."""
    if not run_id or not code_revision or not configuration.get("seeds"):
        raise ValueError("Run identity, code revision and resolved seeds are required")
    if metrics.get("schema_version") != "primary_metrics_v1":
        raise ValueError("Incompatible metrics")
    if configuration.get("protocol_revision") != "primary_experiments_v1":
        raise ValueError("Unsupported primary experiment protocol revision")
    result = {"schema_version": "primary_result_v1", "run_id": run_id,
            "protocol_revision": configuration.get("protocol_revision"),
            "code_revision": code_revision, "package_version": package_version,
            "package_manifest_sha256": package_manifest_sha256,
            "dirty_worktree": dirty_worktree,
            "resolved_configuration": deepcopy(configuration), "metrics": deepcopy(metrics),
            "train_population_sha256": train_population_sha256,
            "validation_population_sha256": validation_population_sha256}
    _experiment_identity(result)
    return result


def binary_metrics(y_true, probabilities, *, partition="VALIDATION", threshold=0.5):
    """Undefined rates are JSON null, never invented zeroes."""
    if partition not in {"TRAIN", "VALIDATION"}:
        raise ValueError("TEST evaluation is sealed in G3B")
    y = np.asarray(y_true)
    p = np.asarray(probabilities, dtype=np.float64)
    if (y.ndim != 1 or p.shape != y.shape or not len(y)
            or not np.isin(y, [0, 1]).all() or not np.isfinite(p).all()
            or ((p < 0) | (p > 1)).any() or threshold != 0.5):
        raise ValueError("Require nonempty aligned binary targets, probabilities and threshold 0.5")
    pred = p >= threshold
    tn = int(((y == 0) & ~pred).sum())
    fp = int(((y == 0) & pred).sum())
    fn = int(((y == 1) & ~pred).sum())
    tp = int(((y == 1) & pred).sum())

    def rate(a, b):
        return a / b if b else None

    per_class = {}
    for label, a, b, c in (("benign", tn, fn, fp), ("malicious", tp, fp, fn)):
        per_class[label] = {"precision": rate(a, a + b), "recall": rate(a, a + c),
                            "f1": rate(2 * a, 2 * a + b + c), "support": a + c}
    scores = [x["f1"] for x in per_class.values()]
    return {"schema_version": "primary_metrics_v1", "partition": partition,
            "threshold": threshold, "positive_class": "malicious",
            "confusion_order": ["benign", "malicious"],
            "TN": tn, "FP": fp, "FN": fn, "TP": tp,
            "accuracy": (tn + tp) / len(y), "per_class": per_class,
            "macro_f1": sum(scores) / 2 if all(x is not None for x in scores) else None,
            "fpr": rate(fp, fp + tn), "undefined_policy": "null"}


def select_validation(results):
    """Require package/protocol/population identity; apply 1e-6 macro-F1 tolerance."""
    if not results:
        raise ValueError("No candidates")
    population = None
    for r in results:
        identity = _experiment_identity(r)
        if population is not None and identity != population:
            raise ValueError("Comparisons must use identical package, protocol and populations")
        population = identity
        m = r["metrics"]
        if m["schema_version"] != "primary_metrics_v1" or m["partition"] != "VALIDATION":
            raise ValueError("Only validation metrics select models")
        for score in (m["macro_f1"], m["fpr"], m["per_class"]["malicious"]["recall"]):
            if score is None or not math.isfinite(score) or not 0 <= score <= 1:
                raise ValueError("Selection needs defined rates in [0, 1]")
    best_f1 = max(r["metrics"]["macro_f1"] for r in results)
    tied = [r for r in results if best_f1 - r["metrics"]["macro_f1"] <= 1e-6]
    return min(tied, key=lambda r: (r["metrics"]["fpr"],
                                   -r["metrics"]["per_class"]["malicious"]["recall"]))
