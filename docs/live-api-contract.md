# Prediction function and live data contract (CODE 2.1, milestone 21/11)

Status: **contract for review**. Schemas are implemented in
`backend/app/live_schemas.py`; the live endpoints themselves are due 26/11.
Every JSON below exists as a file in `backend/examples/` and is checked against the
schemas by `backend/tests/test_predictor_and_contract.py`.

## 1. One prediction function (server and Raspberry Pi)

`backend/app/predictor.py` is the only place that loads the model and applies the rules:

| Rule | Value |
| --- | --- |
| Model | `xgb_frac1_seed42_lr01`, SHA-256 `cb090afa…4455e6`, checked on first load |
| Input | `n x 115` raw numbers in the frozen feature order; no scaling; cast to float32 |
| Rejected | wrong shape, text, booleans, NaN/inf, float32 overflow (`ValueError`) |
| Decision | `probability_malicious >= 0.5` means `malicious` |
| Output | `probabilities`, `predictions` (0/1), `labels`, plus `model_id`, `model_sha256`, `threshold` |

```python
from backend.app.predictor import predict
out = predict(rows)          # rows: list of 115-number lists
```

Needs only NumPy and XGBoost. For the Pi, copy `predictor.py`, `model.json` and the
freeze manifest, and set `IOTGUARD_MODEL_PATH` / `IOTGUARD_FREEZE_PATH` instead of
relying on the repository layout. `analyze_csv.py` now loads the model through the same
predictor, so the CSV/JSON upload flow and the Pi cannot drift apart.

**Samples** (`backend/examples/`): `predict_input.json`, `predict_input.csv`,
`predict_output.json`. The three rows are **synthetic**, only for showing shape and both
labels. For real VALIDATION rows run `ml/scripts/sample_prediction.py`.

## 2. Live flow

```
Frontend --POST /live/sessions-------------------------> Backend   (start; returns session_id)
Pi -------POST /live/sessions/{id}/events (batch)------> Backend   (Pi already predicted; no re-inference)
Pi -------POST /live/sessions/{id}/heartbeat-----------> Backend   (when idle)
Frontend --GET  /live/sessions/{id}/events?after_seq=N-> Backend   (poll new records)
Frontend --GET  /live/sessions/{id}/status-------------> Backend   (connection + counters)
Frontend --POST /live/sessions/{id}/stop---------------> Backend
```

| Method and path | Request | Success | Errors |
| --- | --- | --- | --- |
| `GET /model/info` | none | `ModelInfo` (`live_model_info.json`) | none |
| `GET /live/limits` | none | `LiveLimits` | none |
| `POST /live/sessions` | `SessionCreate` | 201 `Session` | 422 `validation_error` |
| `POST /live/sessions/{id}/stop` | none | `Session` with `state: stopped` | 404 `session_not_found` |
| `POST /live/sessions/{id}/events` | `EventBatch` | `EventBatchResult` | 404, 409 `session_stopped` or `model_mismatch`, 413 `payload_too_large`, 422 |
| `POST /live/sessions/{id}/heartbeat` | `Heartbeat` | 204 | 404, 409 `model_mismatch` |
| `GET /live/sessions/{id}/events?after_seq=0&limit=100` | query | `EventPage` | 404 |
| `GET /live/sessions/{id}/status` | none | `SessionStatus` | 404 |

All error bodies are `ApiError` (`code`, `message`, optional `detail` list).
The existing `POST /predict` (CSV/JSON upload), `/files/inspect` and `/logs` are unchanged.

## 3. Rules that matter for correctness

- **No double counting.** `(session_id, event_id)` is unique. A resend returns
  `duplicates > 0` and `accepted = 0` for those events (`live_event_batch_result_resend.json`).
  The Pi may therefore retry a whole batch after a dropped connection.
- **Gaps are reported, not hidden.** `pi_seq` increases by 1 on the Pi. If the backend sees
  a jump, `gap_detected = true` and `gaps_detected` in the status increases.
- **No re-inference.** The backend stores `label` and `probability_malicious` as sent, but
  rejects an event whose label disagrees with the 0.5 threshold, and rejects the whole batch
  if `model_sha256` differs from the frozen model (409).
- **Ground truth is never inferred.** `ground_truth` is `null` unless the replayed labelled
  file supplied it. `correct` is only set when it is present, so accuracy covers labelled
  events only (NFR-12).
- **Bounded history.** At most 100 events per batch and 1000 stored events per session;
  older ones are evicted and counted in `dropped_from_history` (FR-12, NFR-11).
- **Cursor, not timestamps.** The frontend polls with `after_seq = next_after_seq`
  (the backend's `server_seq`), which avoids clock differences between the Pi and the server.
- **Connection state** (computed by the backend from last event/heartbeat):
  `connecting` (session created, nothing received), `connected`, `stale` after 15 s,
  `offline` after 45 s. Manual Analysis does not depend on any of this (NFR-01).

## 4. Proposals to confirm with the team

These values are my proposals, not decisions anyone has agreed yet:

1. Stale/offline thresholds (15 s / 45 s), batch size (100) and history size (1000).
2. A single active session per source at a time.
3. No authentication on the Pi endpoint for the demo (LAN only). If we want a token,
   it needs one more header and one more error code.
4. Polling by the frontend (e.g. every 1-2 s) rather than WebSocket/SSE, so Duy needs no
   new infrastructure. The `after_seq` cursor keeps polling cheap.

`inference_ms` in the examples (1.8) is a placeholder, not a measured Pi value.

## 5. Regenerate and check

```bash
python backend/examples/generate_examples.py      # rewrites backend/examples/*
python -m pytest backend/tests -q                 # 97 tests, includes contract checks
```
