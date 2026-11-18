import json

import pytest
from fastapi.testclient import TestClient

from backend.app import analyze_csv as analyzer
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


def test_tampered_model_rejected_before_loading(tmp_path, monkeypatch):
    model = tmp_path / "model.json"
    model.write_text("{}")
    monkeypatch.setattr(analyzer, "MODEL", model)
    analyzer.load_model.cache_clear()
    with pytest.raises(RuntimeError, match="frozen model"):
        analyzer.load_model()


def test_missing_model_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(analyzer, "MODEL", tmp_path / "absent.json")
    analyzer.load_model.cache_clear()
    with pytest.raises(FileNotFoundError):
        analyzer.load_model()
