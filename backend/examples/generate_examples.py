"""Regenerate the sample files in this folder with the real frozen model.

Run from the repository root:  python backend/examples/generate_examples.py

The 3 input rows are SYNTHETIC (deterministic random numbers), chosen only to show the
JSON/CSV shape and both labels. They are not real N-BaIoT traffic and their outputs say
nothing about model quality. Real VALIDATION samples: ml/scripts/sample_prediction.py.
"""

import csv
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.app import live_schemas as s  # noqa: E402
from backend.app.predictor import get_predictor  # noqa: E402

OUT = Path(__file__).resolve().parent


def write(name, data):
    (OUT / name).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main():
    predictor = get_predictor()
    rng = np.random.default_rng(0)
    pool = [rng.exponential(scale=10 ** rng.integers(0, 4), size=115) for _ in range(6)]
    rows = [np.zeros(115), pool[0], pool[3]]          # benign, benign (low score), malicious
    rows = [[float(f"{v:.6g}") for v in row] for row in rows]
    names = ["Synthetic all-zero row", "Synthetic low-score row", "Synthetic attack-like row"]
    truth = [None, None, None]

    # 1. Prediction input/output (same JSON the upload API and the Pi accept)
    write("predict_input.json", {
        "feature_order": predictor.feature_order,
        "rows": rows,
        "sample_metadata": [{"sample_name": n} for n in names],
    })
    with (OUT / "predict_input.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(predictor.feature_order + ["sample_name"])
        for row, name in zip(rows, names, strict=True):
            writer.writerow([repr(v) for v in row] + [name])
    result = predictor.predict(rows)
    write("predict_output.json", result)

    # 2. Live contract examples, filled with the real outputs above
    sha = predictor.model_sha256
    base = "2026-11-21T09:00:00Z"
    write("live_session_create.json", {"source_name": "raspberry-pi-4"})
    session = {"session_id": "ses_01", "source_name": "raspberry-pi-4", "state": "active",
               "created_at": base, "stopped_at": None, "model_id": predictor.model_id,
               "model_sha256": sha}
    write("live_session.json", session)
    events = [{
        "event_id": f"pi4-000{i}", "pi_seq": i, "sample_name": names[i], "source_row": i,
        "label": result["labels"][i], "probability_malicious": result["probabilities"][i],
        "ground_truth": truth[i], "predicted_at": f"2026-11-21T09:00:0{i + 1}Z",
        "inference_ms": 1.8,
    } for i in range(3)]
    write("live_event_batch.json", {"model_sha256": sha, "events": events})
    write("live_event_batch_result.json", {"accepted": 3, "duplicates": 0, "dropped_from_history": 0,
                                           "last_pi_seq": 2, "gap_detected": False})
    write("live_event_batch_result_resend.json", {"accepted": 0, "duplicates": 3,
                                                  "dropped_from_history": 0, "last_pi_seq": 2,
                                                  "gap_detected": False})
    write("live_heartbeat.json", {"model_sha256": sha, "pi_seq": 2, "sent_at": "2026-11-21T09:00:04Z"})
    stored = [{**e, "server_seq": i + 1, "received_at": "2026-11-21T09:00:05Z",
               "correct": None} for i, e in enumerate(events)]
    write("live_event_page.json", {"events": stored, "next_after_seq": 3})
    write("live_status.json", {
        "session": session, "connection": "connected", "last_seen_at": "2026-11-21T09:00:05Z",
        "seconds_since_last_seen": 2.0, "total_received": 3,
        "benign": result["labels"].count("benign"), "malicious": result["labels"].count("malicious"),
        "labelled": 0, "correct": 0, "duplicates_ignored": 0, "dropped_from_history": 0,
        "gaps_detected": 0, "history_limit": s.MAX_HISTORY_PER_SESSION,
    })
    write("live_model_info.json", {
        "model_id": predictor.model_id, "model_sha256": sha, "algorithm": "XGBoost",
        "objective": "binary:logistic", "threshold": 0.5, "feature_count": 115,
        "feature_order": predictor.feature_order, "input_view": "raw", "scaling_applied": False,
        "runtime": {"numpy": np.__version__, "xgboost": __import__("xgboost").__version__},
    })
    write("live_limits.json", s.LiveLimits().model_dump())
    write("live_error_model_mismatch.json", {
        "code": "model_mismatch",
        "message": "Pi model hash differs from the backend's frozen model; events were not stored.",
        "detail": ["expected " + sha, "received 0000..."]})
    write("live_error_validation.json", {
        "code": "validation_error", "message": "Invalid event batch",
        "detail": ["events[1].probability_malicious: must be between 0 and 1"]})
    print(f"Wrote examples to {OUT}")


if __name__ == "__main__":
    main()
