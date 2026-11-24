import hashlib
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from backend.app import analyze_csv as analyzer, predictor
from backend.app.main import app


def input_file():
    return json.dumps({"feature_order": analyzer.feature_names(), "rows": [[0]*115]}).encode()


@pytest.mark.parametrize("failure", [FileNotFoundError("private/path"), RuntimeError("tampered")])
def test_resource_failure_is_503_without_path_disclosure(monkeypatch, failure):
    content = input_file()
    def fail():
        raise failure
    monkeypatch.setattr(analyzer, "load_model", fail)
    response = TestClient(app).post("/predict", files={"file": ("data.json", content)})
    assert response.status_code == 503
    assert "private" not in response.text and "tampered" not in response.text


def test_openapi_declares_success_schema():
    schema = app.openapi()["paths"]["/predict"]["post"]["responses"]
    assert schema["200"]["content"]["application/json"]["schema"]["$ref"].endswith("AnalysisResponse")
    assert {"400", "413", "503"} <= schema.keys()


@pytest.mark.parametrize("condition", ["missing", "tampered", "unreadable_by_xgboost"])
def test_unavailable_shared_model_returns_503(tmp_path, monkeypatch, condition):
    content = input_file()
    model_path = tmp_path / "private-model.json"
    freeze_path = analyzer.FREEZE
    if condition != "missing":
        model_path.write_bytes(b"{}")
    if condition == "unreadable_by_xgboost":
        # A matching digest lets the corrupt payload reach the actual XGBoost loader.
        freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
        freeze["model"]["sha256"] = hashlib.sha256(model_path.read_bytes()).hexdigest()
        freeze_path = tmp_path / "freeze.json"
        freeze_path.write_text(json.dumps(freeze), encoding="utf-8")

    original = predictor.FrozenPredictor
    monkeypatch.setattr(predictor, "FrozenPredictor", lambda: original(model_path, freeze_path))
    predictor.get_predictor.cache_clear()
    try:
        result = TestClient(app).post("/predict", files={"file": ("data.json", content)})
    finally:
        predictor.get_predictor.cache_clear()
    assert result.status_code == 503
    assert result.json() == {"detail": "The prediction model is unavailable; contact the operator"}


def test_invalid_frozen_feature_order_returns_503(tmp_path, monkeypatch):
    content = input_file()
    freeze = json.loads(analyzer.FREEZE.read_text(encoding="utf-8"))
    freeze["input_contract"]["feature_order"] = None
    path = tmp_path / "freeze.json"
    path.write_text(json.dumps(freeze), encoding="utf-8")
    monkeypatch.setattr(analyzer, "FREEZE", path)
    result = TestClient(app).post("/predict", files={"file": ("data.json", content)})
    assert result.status_code == 503
    assert result.json() == {"detail": "The prediction model is unavailable; contact the operator"}


def test_startup_inspection_and_logs_use_isolated_database(tmp_path, monkeypatch):
    from backend.app import log_store
    monkeypatch.setattr(log_store, "DB_PATH", tmp_path / "traffic.db")
    with TestClient(app) as client:
        assert client.get("/logs").json() == []
        result = client.post("/files/inspect", files={"file": ("sample.csv", b"a,b\n")})
        assert result.status_code == 200 and result.json()["size_bytes"] == 4
        assert client.get("/logs").json()[0]["event"] == "upload_inspected"


def test_xgboost_prediction_failure_is_service_error(monkeypatch):
    class BrokenModel:
        def predict(self, _data):
            raise analyzer.xgb.core.XGBoostError("internal/private-runtime")

    content = input_file()
    shared = SimpleNamespace(booster=BrokenModel(), feature_order=analyzer.feature_names())
    monkeypatch.setattr(analyzer, "load_model", lambda: shared)
    result = TestClient(app).post("/predict", files={"file": ("data.json", content)})
    assert result.status_code == 503
    assert "private-runtime" not in result.text
