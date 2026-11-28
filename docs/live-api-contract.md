# Live monitoring API contract

The live routes, [schemas](../backend/app/live_schemas.py), examples and tests are on `main` through [PR #30](https://github.com/sonnnguyennn/cos30049hn-grp1_5/pull/30). Use the [API and installation guide](api-and-install-guide.md) for runnable requests. The backend API has been checked independently; a Pi client and Replay UI still need an end-to-end integration check.

## Prediction on the Pi

The [shared predictor](../backend/app/predictor.py) takes rows of 115 raw features in the [frozen order](../ml/docs/architecture/inference_contract.md). It verifies the model SHA-256 and returns `probabilities`, `predictions`, `labels`, `model_id`, `model_sha256` and `threshold`. For a relocated copy, set `IOTGUARD_MODEL_PATH` and `IOTGUARD_FREEZE_PATH` before import.

```python
from backend.app.predictor import predict

result = predict(rows)
```

## Session flow

The intended client flow is as follows. The frontend starts a session. The Pi sends [event batches](../backend/examples/live_event_batch.json) and heartbeats. The frontend polls events and status, then stops the session. The backend stores the predictions sent by the Pi. [Manual Analysis](csv-upload-api-guide.md) works independently.

| Method and path | Request | Success | Contract errors |
| --- | --- | --- | --- |
| `GET /model/info` | None | [`ModelInfo`](../backend/examples/live_model_info.json) | 503 |
| `GET /live/limits` | None | [`LiveLimits`](../backend/examples/live_limits.json) | |
| `POST /live/sessions` | [`SessionCreate`](../backend/examples/live_session_create.json) | 201 `Session` | 422 `validation_error`, 503 |
| `POST /live/sessions/{session_id}/events` | [`EventBatch`](../backend/examples/live_event_batch.json) | `EventBatchResult` | 404, 409 `session_stopped` or `model_mismatch`, 413 `payload_too_large`, 422, 503 |
| `POST /live/sessions/{session_id}/heartbeat` | [`Heartbeat`](../backend/examples/live_heartbeat.json) | 204 | 404, 409 `session_stopped` or `model_mismatch`, 422, 503 |
| `GET /live/sessions/{session_id}/events?after_seq=0&limit=100` | Query | [`EventPage`](../backend/examples/live_event_page.json) | 404, 422 for invalid query values |
| `GET /live/sessions/{session_id}/status` | None | [`SessionStatus`](../backend/examples/live_status.json) | 404 |
| `POST /live/sessions/{session_id}/stop` | None | `Session` with `state: stopped` | 404 |

The `ApiError` schema has `code`, `message` and optional `detail`. An unknown session returns `session_not_found`. A model-unavailable response uses HTTP 503 with FastAPI's `{"detail": "..."}` body.

Sessions and their event history are held in memory. Run one backend worker. A restart or development reload clears every session; clients must create a new session after that.

## Event rules

- **Retries.** `(session_id, event_id)` identifies a unique event. Resending a stored batch reports duplicates and accepts zero new events. See the [resend response](../backend/examples/live_event_batch_result_resend.json).
- **Gaps.** The Pi increments `pi_seq` by one per record. A jump sets `gap_detected` and increments `gaps_detected` in the session status.
- **Model identity.** A mismatched `model_sha256` rejects the batch with 409. Each event's label must agree with the 0.5 probability threshold.
- **Ground truth.** Use the label supplied by the replay source, or `null`. The backend calculates agreement for labeled events only.
- **History.** The implemented limits are 100 events per batch and 1,000 stored events per session. Evictions are counted in `dropped_from_history`. Poll with `after_seq=next_after_seq` to continue from the backend's `server_seq`.
- **Connection.** The backend uses the last event or heartbeat to report `connecting`, `connected`, `stale` after 15 s or `offline` after 45 s. Read these limits with `GET /live/limits`.

The current API has no authentication and is intended for the agreed demo environment. It does not enforce one active session per source. Frontend polling every 1–2 s remains a client design choice. The `inference_ms` in the fixtures is example data.

## Verify the contract

From the repository root with the backend environment active:

```bash
python -m pytest backend/tests -q
```

To regenerate the fixtures, run `python backend/examples/generate_examples.py`.
