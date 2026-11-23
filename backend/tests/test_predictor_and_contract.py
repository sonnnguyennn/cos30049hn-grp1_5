"""Shared predictor, sample files and live data contract (no training, no network)."""

import json
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.app import analyze_csv as analyzer
from backend.app import live_schemas as s
from backend.app.main import app
from backend.app.predictor import FrozenPredictor, get_predictor, predict

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def load(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def test_predictor_matches_frozen_contract():
    p = get_predictor()
    assert len(p.feature_order) == 115 and p.feature_order == analyzer.feature_names()
    assert p.model_sha256 == json.loads(analyzer.FREEZE.read_text())["model"]["sha256"]


def test_example_output_is_reproduced_exactly():
    data = load("predict_input.json")
    assert data["feature_order"] == get_predictor().feature_order
    expected = load("predict_output.json")
    actual = predict(data["rows"])
    assert actual["labels"] == expected["labels"] == ["benign", "benign", "malicious"]
    assert actual["predictions"] == expected["predictions"]
    np.testing.assert_allclose(actual["probabilities"], expected["probabilities"], rtol=0, atol=1e-12)


def test_threshold_is_inclusive_and_labels_follow_probabilities():
    out = predict(load("predict_input.json")["rows"])
    for prob, pred, label in zip(out["probabilities"], out["predictions"], out["labels"]):
        assert pred == int(prob >= 0.5)
        assert label == ("malicious" if prob >= 0.5 else "benign")


def test_prediction_is_deterministic_and_batch_independent():
    rows = load("predict_input.json")["rows"]
    together = predict(rows)["probabilities"]
    one_by_one = [predict([r])["probabilities"][0] for r in rows]
    assert together == predict(rows)["probabilities"]
    np.testing.assert_allclose(together, one_by_one, atol=1e-7)


@pytest.mark.parametrize("rows", [
    [], [[]], [[0] * 114], [[0] * 116], [[float("nan")] + [0] * 114],
    [[float("inf")] + [0] * 114], [["a"] + [0] * 114], [[1e100] + [0] * 114], 5, None,
    pytest.param([[True] + [0] * 114], id="boolean_feature"),
    pytest.param([["12.5"] + [0] * 114], id="numeric_string_feature"),
])
def test_invalid_rows_rejected(rows):
    with pytest.raises(ValueError):
        predict(rows)


def test_wrong_model_file_is_rejected(tmp_path):
    fake = tmp_path / "model.json"
    fake.write_bytes(b"{}")
    with pytest.raises(RuntimeError, match="frozen"):
        FrozenPredictor(model_path=fake)


def test_predictor_agrees_with_upload_pipeline():
    """Server upload flow and the shared function must give identical scores."""
    data = load("predict_input.json")
    api = analyzer.analyze_json(json.dumps(data))
    shared = predict(data["rows"])
    np.testing.assert_allclose([r["probability_malicious"] for r in api["results"]],
                               shared["probabilities"], atol=1e-12)
    assert [r["label"] for r in api["results"]] == shared["labels"]


def test_existing_predict_endpoint_still_works_with_json_and_csv():
    client = TestClient(app)
    for name, mime in (("predict_input.json", "application/json"), ("predict_input.csv", "text/csv")):
        body = (EXAMPLES / name).read_bytes()
        response = client.post("/predict", files={"file": (name, body, mime)})
        assert response.status_code == 200, response.text
        assert [r["label"] for r in response.json()["results"]] == ["benign", "benign", "malicious"]


# --- live data contract ------------------------------------------------------------------

@pytest.mark.parametrize("file, model", [
    ("live_session_create.json", s.SessionCreate), ("live_session.json", s.Session),
    ("live_event_batch.json", s.EventBatch), ("live_event_batch_result.json", s.EventBatchResult),
    ("live_event_batch_result_resend.json", s.EventBatchResult), ("live_heartbeat.json", s.Heartbeat),
    ("live_event_page.json", s.EventPage), ("live_status.json", s.SessionStatus),
    ("live_model_info.json", s.ModelInfo), ("live_limits.json", s.LiveLimits),
    ("live_error_model_mismatch.json", s.ApiError), ("live_error_validation.json", s.ApiError),
])
def test_examples_validate_against_schemas(file, model):
    model.model_validate(load(file))


def test_live_example_uses_the_real_model_hash_and_outputs():
    batch = s.EventBatch.model_validate(load("live_event_batch.json"))
    assert batch.model_sha256 == get_predictor().model_sha256
    expected = load("predict_output.json")
    assert [e.label for e in batch.events] == expected["labels"]


def test_event_label_must_match_threshold():
    event = load("live_event_batch.json")["events"][0]
    with pytest.raises(ValidationError, match="threshold"):
        s.LiveEvent.model_validate({**event, "label": "malicious"})


@pytest.mark.parametrize("patch", [
    {"probability_malicious": 1.5}, {"pi_seq": -1}, {"event_id": ""},
    {"unexpected": 1}, {"ground_truth": "unknown"},
])
def test_bad_events_rejected(patch):
    event = load("live_event_batch.json")["events"][0]
    with pytest.raises(ValidationError):
        s.LiveEvent.model_validate({**event, **patch})


def test_batch_size_limit():
    event = load("live_event_batch.json")["events"][0]
    too_many = [event] * (s.MAX_EVENTS_PER_BATCH + 1)
    with pytest.raises(ValidationError):
        s.EventBatch(model_sha256="x", events=too_many)
    with pytest.raises(ValidationError):
        s.EventBatch(model_sha256="x", events=[])
