"""Live (Replay Monitoring) endpoints: sessions, events, heartbeat, status."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import analyze_csv as analyzer
from backend.app import live
from backend.app import live_schemas as s
from backend.app.main import app
from backend.app.predictor import get_predictor

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
SHA = get_predictor().model_sha256


def load(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


class Clock:
    def __init__(self):
        self.t = datetime(2026, 11, 25, 9, 0, 0, tzinfo=timezone.utc)

    def now(self):
        return self.t

    def advance(self, seconds):
        self.t += timedelta(seconds=seconds)


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    fake = Clock()
    monkeypatch.setattr(live, "_now", fake.now)
    live.reset()
    yield fake
    live.reset()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def session_id(client):
    response = client.post("/live/sessions", json={"source_name": "raspberry-pi-4"})
    assert response.status_code == 201
    return response.json()["session_id"]


def event(i, p=0.01, ground_truth=None):
    return {
        "event_id": f"e{i}", "pi_seq": i,
        "label": "malicious" if p >= 0.5 else "benign",
        "probability_malicious": p, "ground_truth": ground_truth,
        "predicted_at": "2026-11-21T09:00:01Z",
    }


def batch(*events, sha=SHA):
    return {"model_sha256": sha, "events": list(events)}


def post_events(client, sid, body):
    return client.post(f"/live/sessions/{sid}/events", json=body)


def status(client, sid):
    response = client.get(f"/live/sessions/{sid}/status")
    assert response.status_code == 200
    return response.json()


def test_limits_match_the_documented_example(client):
    response = client.get("/live/limits")
    assert response.status_code == 200
    assert response.json() == load("live_limits.json")


def test_create_session_returns_the_frozen_model(client):
    response = client.post("/live/sessions", json={"source_name": "raspberry-pi-4"})
    assert response.status_code == 201
    session = s.Session.model_validate(response.json())
    assert session.state == "active" and session.stopped_at is None
    assert session.model_sha256 == SHA and session.model_id == get_predictor().model_id


def test_example_batch_then_resend_matches_documented_results(client, session_id):
    body = load("live_event_batch.json")
    first = post_events(client, session_id, body)
    assert first.status_code == 200
    assert first.json() == load("live_event_batch_result.json")
    resend = post_events(client, session_id, body)
    assert resend.status_code == 200
    assert resend.json() == load("live_event_batch_result_resend.json")
    current = status(client, session_id)
    assert current["total_received"] == 3 and current["duplicates_ignored"] == 3


def test_poll_with_cursor_returns_only_unseen_events(client, session_id):
    post_events(client, session_id, batch(event(0), event(1), event(2)))
    page = client.get(f"/live/sessions/{session_id}/events?after_seq=0").json()
    s.EventPage.model_validate(page)
    assert [e["server_seq"] for e in page["events"]] == [1, 2, 3]
    assert page["next_after_seq"] == 3

    empty = client.get(f"/live/sessions/{session_id}/events?after_seq=3").json()
    assert empty["events"] == [] and empty["next_after_seq"] == 3

    post_events(client, session_id, batch(event(3)))
    newest = client.get(f"/live/sessions/{session_id}/events?after_seq=3").json()
    assert [e["event_id"] for e in newest["events"]] == ["e3"]
    assert newest["next_after_seq"] == 4


def test_duplicate_inside_one_batch_is_counted_once(client, session_id):
    result = post_events(client, session_id, batch(event(0), event(0))).json()
    assert result["accepted"] == 1 and result["duplicates"] == 1


def test_model_mismatch_rejects_the_whole_batch(client, session_id):
    response = post_events(client, session_id, batch(event(0), sha="0" * 64))
    assert response.status_code == 409
    error = s.ApiError.model_validate(response.json())
    assert error.code == "model_mismatch"
    assert status(client, session_id)["total_received"] == 0


def test_label_that_disagrees_with_probability_is_422(client, session_id):
    bad = event(0, p=0.9)
    bad["label"] = "benign"
    response = post_events(client, session_id, batch(bad))
    assert response.status_code == 422
    error = s.ApiError.model_validate(response.json())
    assert error.code == "validation_error" and error.detail
    assert status(client, session_id)["total_received"] == 0


def test_out_of_range_probability_is_422_with_event_path(client, session_id):
    bad = event(1)
    bad["probability_malicious"] = 1.5
    response = post_events(client, session_id, batch(event(0), bad))
    assert response.status_code == 422
    assert any("events[1].probability_malicious" in line for line in response.json()["detail"])


def test_invalid_json_body_is_422(client, session_id):
    response = client.post(f"/live/sessions/{session_id}/events", content=b"not json",
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"


def test_oversized_batch_is_413(client, session_id):
    events = [event(i) for i in range(s.MAX_EVENTS_PER_BATCH + 1)]
    response = post_events(client, session_id, batch(*events))
    assert response.status_code == 413
    assert response.json()["code"] == "payload_too_large"
    assert status(client, session_id)["total_received"] == 0


def test_max_size_batch_is_accepted(client, session_id):
    events = [event(i) for i in range(s.MAX_EVENTS_PER_BATCH)]
    result = post_events(client, session_id, batch(*events)).json()
    assert result["accepted"] == s.MAX_EVENTS_PER_BATCH


def test_empty_batch_is_422(client, session_id):
    assert post_events(client, session_id, batch()).status_code == 422


def test_unknown_fields_are_rejected(client, session_id):
    body = batch(event(0))
    body["extra"] = 1
    assert post_events(client, session_id, body).status_code == 422


@pytest.mark.parametrize("method, path, body", [
    ("post", "/live/sessions/nope/stop", None),
    ("post", "/live/sessions/nope/events", batch(event(0))),
    ("post", "/live/sessions/nope/heartbeat",
     {"model_sha256": SHA, "pi_seq": 0, "sent_at": "2026-11-21T09:00:04Z"}),
    ("get", "/live/sessions/nope/events", None),
    ("get", "/live/sessions/nope/status", None),
])
def test_unknown_session_is_404(client, method, path, body):
    response = getattr(client, method)(path, **({"json": body} if body is not None else {}))
    assert response.status_code == 404
    assert response.json()["code"] == "session_not_found"


def test_stopped_session_rejects_events_and_heartbeats(client, session_id):
    stopped = client.post(f"/live/sessions/{session_id}/stop")
    assert stopped.status_code == 200
    assert stopped.json()["state"] == "stopped" and stopped.json()["stopped_at"]

    again = client.post(f"/live/sessions/{session_id}/stop")
    assert again.status_code == 200 and again.json() == stopped.json()

    rejected = post_events(client, session_id, batch(event(0)))
    assert rejected.status_code == 409 and rejected.json()["code"] == "session_stopped"
    beat = client.post(f"/live/sessions/{session_id}/heartbeat", json={
        "model_sha256": SHA, "pi_seq": 0, "sent_at": "2026-11-21T09:00:04Z"})
    assert beat.status_code == 409 and beat.json()["code"] == "session_stopped"


def test_gap_in_pi_seq_is_reported_not_hidden(client, session_id):
    first = post_events(client, session_id, batch(event(0), event(1))).json()
    assert first["gap_detected"] is False
    second = post_events(client, session_id, batch(event(5))).json()
    assert second["gap_detected"] is True and second["last_pi_seq"] == 5
    assert status(client, session_id)["gaps_detected"] == 1


def test_resend_after_a_gap_does_not_report_a_second_gap(client, session_id):
    body = batch(event(0), event(5))
    post_events(client, session_id, body)
    resend = post_events(client, session_id, body).json()
    assert resend["gap_detected"] is False and resend["duplicates"] == 2
    assert status(client, session_id)["gaps_detected"] == 1


def test_history_is_bounded_and_drops_are_reported(monkeypatch, client, session_id):
    monkeypatch.setattr(live, "MAX_HISTORY_PER_SESSION", 3)
    result = post_events(client, session_id, batch(*[event(i) for i in range(5)])).json()
    assert result["accepted"] == 5 and result["dropped_from_history"] == 2
    page = client.get(f"/live/sessions/{session_id}/events").json()
    assert [e["server_seq"] for e in page["events"]] == [3, 4, 5]
    current = status(client, session_id)
    assert current["total_received"] == 5 and current["dropped_from_history"] == 2
    assert current["history_limit"] == 3
    # An evicted event is still recognised as a duplicate.
    resend = post_events(client, session_id, batch(event(0))).json()
    assert resend["duplicates"] == 1 and resend["accepted"] == 0


def test_connection_state_follows_last_seen(client, session_id, clock):
    assert status(client, session_id)["connection"] == "connecting"
    post_events(client, session_id, batch(event(0)))
    assert status(client, session_id)["connection"] == "connected"

    clock.advance(s.STALE_AFTER_SECONDS - 1)
    assert status(client, session_id)["connection"] == "connected"
    clock.advance(1)
    assert status(client, session_id)["connection"] == "stale"
    clock.advance(s.OFFLINE_AFTER_SECONDS - s.STALE_AFTER_SECONDS)
    current = status(client, session_id)
    assert current["connection"] == "offline"
    assert current["seconds_since_last_seen"] == s.OFFLINE_AFTER_SECONDS

    beat = client.post(f"/live/sessions/{session_id}/heartbeat", json={
        "model_sha256": SHA, "pi_seq": 0, "sent_at": "2026-11-21T09:01:00Z"})
    assert beat.status_code == 204 and beat.content == b""
    assert status(client, session_id)["connection"] == "connected"


def test_heartbeat_with_wrong_model_is_409_and_does_not_refresh(client, session_id, clock):
    post_events(client, session_id, batch(event(0)))
    clock.advance(s.STALE_AFTER_SECONDS)
    beat = client.post(f"/live/sessions/{session_id}/heartbeat", json={
        "model_sha256": "f" * 64, "pi_seq": 0, "sent_at": "2026-11-21T09:00:20Z"})
    assert beat.status_code == 409 and beat.json()["code"] == "model_mismatch"
    assert status(client, session_id)["connection"] == "stale"


def test_accuracy_counts_only_labelled_events(client, session_id):
    events = [
        event(0, p=0.9, ground_truth="malicious"),   # correct
        event(1, p=0.1, ground_truth="malicious"),   # incorrect
        event(2, p=0.2),                             # unlabelled
    ]
    post_events(client, session_id, batch(*events))
    current = status(client, session_id)
    assert (current["benign"], current["malicious"]) == (2, 1)
    assert (current["labelled"], current["correct"]) == (2, 1)
    stored = client.get(f"/live/sessions/{session_id}/events").json()["events"]
    assert [e["correct"] for e in stored] == [True, False, None]


def test_status_matches_the_documented_shape(client, session_id):
    post_events(client, session_id, batch(event(0)))
    shape = s.SessionStatus.model_validate(status(client, session_id))
    assert shape.session.session_id == session_id and shape.total_received == 1


def test_unavailable_model_is_503_for_sessions_events_and_heartbeats(
        monkeypatch, client, session_id):
    def fail():
        raise RuntimeError("private/path tampered")
    monkeypatch.setattr(analyzer, "load_model", fail)
    responses = [
        client.post("/live/sessions", json={"source_name": "pi"}),
        post_events(client, session_id, batch(event(0))),
        client.post(f"/live/sessions/{session_id}/heartbeat", json={
            "model_sha256": SHA, "pi_seq": 0, "sent_at": "2026-11-21T09:00:04Z"}),
    ]
    for response in responses:
        assert response.status_code == 503
        assert "private" not in response.text and "tampered" not in response.text


def test_session_create_validation_uses_the_live_error_body(client):
    response = client.post("/live/sessions", json={"source_name": ""})
    assert response.status_code == 422
    error = s.ApiError.model_validate(response.json())
    assert error.code == "validation_error" and any("source_name" in d for d in error.detail)


def test_existing_endpoints_keep_the_standard_422_body(client):
    response = client.post("/predict")
    assert response.status_code == 422
    assert isinstance(response.json()["detail"], list)


def test_openapi_lists_the_live_endpoints():
    paths = app.openapi()["paths"]
    for path in ["/live/limits", "/live/sessions", "/live/sessions/{session_id}/stop",
                 "/live/sessions/{session_id}/events",
                 "/live/sessions/{session_id}/heartbeat",
                 "/live/sessions/{session_id}/status"]:
        assert path in paths