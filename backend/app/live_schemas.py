"""Data contract for Replay/Live Monitoring (Pi -> backend -> frontend).

This file is the single source of truth for the shapes in docs/live-api-contract.md.
The Pi runs inference locally; the backend stores what it receives and never
re-predicts these events. Ground truth comes only from the replayed dataset,
never from predictions.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Label = Literal["benign", "malicious"]
SessionState = Literal["active", "stopped"]
ConnectionState = Literal["connecting", "connected", "stale", "offline"]

# Proposed limits (override in the backend config; frontend should read them from /live/limits).
MAX_EVENTS_PER_BATCH = 100
MAX_HISTORY_PER_SESSION = 1000   # oldest events are dropped beyond this (FR-12 / NFR-11)
STALE_AFTER_SECONDS = 15         # no heartbeat/event for this long -> "stale"
OFFLINE_AFTER_SECONDS = 45       # ... -> "offline"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- Session management (frontend -> backend) -------------------------------------------

class SessionCreate(Strict):
    source_name: str = Field(min_length=1, max_length=100, description="e.g. 'raspberry-pi-4'")


class Session(Strict):
    session_id: str
    source_name: str
    state: SessionState
    created_at: datetime
    stopped_at: datetime | None = None
    model_id: str
    model_sha256: str


# --- Pi -> backend ----------------------------------------------------------------------

class LiveEvent(Strict):
    """One prediction made on the Pi. (session_id, event_id) must be unique: resends are ignored."""

    event_id: str = Field(min_length=1, max_length=64, description="Unique per Pi record; used for de-duplication")
    pi_seq: int = Field(ge=0, description="Monotonic counter on the Pi, to detect gaps after reconnects")
    sample_name: str | None = Field(default=None, max_length=200)
    source_row: int | None = Field(default=None, ge=0, description="Row index in the replayed dataset")
    label: Label
    probability_malicious: float = Field(ge=0, le=1)
    ground_truth: Label | None = Field(default=None, description="From the labelled replay file; null if unknown")
    predicted_at: datetime = Field(description="Pi clock, UTC ISO 8601")
    inference_ms: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def label_matches_threshold(self):
        expected = "malicious" if self.probability_malicious >= 0.5 else "benign"
        if self.label != expected:
            raise ValueError("label must match probability_malicious with threshold 0.5")
        return self


class EventBatch(Strict):
    model_sha256: str = Field(description="Must equal the backend's frozen model hash, else HTTP 409")
    events: list[LiveEvent] = Field(min_length=1, max_length=MAX_EVENTS_PER_BATCH)


class EventBatchResult(Strict):
    accepted: int
    duplicates: int = Field(description="Already stored; ignored, not counted twice")
    dropped_from_history: int = Field(description="Older events evicted by the history limit")
    last_pi_seq: int | None
    gap_detected: bool = Field(description="True if pi_seq skipped values (events lost on the Pi side)")


class Heartbeat(Strict):
    model_sha256: str
    pi_seq: int = Field(ge=0, description="Last pi_seq the Pi has produced so far")
    sent_at: datetime


# --- Backend -> frontend ----------------------------------------------------------------

class StoredEvent(LiveEvent):
    server_seq: int = Field(ge=1, description="Backend-assigned, increasing; use as 'after_seq' cursor")
    received_at: datetime
    correct: bool | None = Field(default=None, description="label == ground_truth, null when unlabelled")


class EventPage(Strict):
    events: list[StoredEvent]
    next_after_seq: int = Field(ge=0, description="Pass as after_seq next time; unchanged when no new events")


class SessionStatus(Strict):
    session: Session
    connection: ConnectionState
    last_seen_at: datetime | None
    seconds_since_last_seen: float | None
    total_received: int
    benign: int
    malicious: int
    labelled: int
    correct: int
    duplicates_ignored: int
    dropped_from_history: int
    gaps_detected: int
    history_limit: int = MAX_HISTORY_PER_SESSION


class ModelInfo(Strict):
    model_id: str
    model_sha256: str
    algorithm: str
    objective: str
    threshold: float
    feature_count: int
    feature_order: list[str]
    input_view: Literal["raw"]
    scaling_applied: bool
    runtime: dict[str, str]


class LiveLimits(Strict):
    max_events_per_batch: int = MAX_EVENTS_PER_BATCH
    max_history_per_session: int = MAX_HISTORY_PER_SESSION
    stale_after_seconds: int = STALE_AFTER_SECONDS
    offline_after_seconds: int = OFFLINE_AFTER_SECONDS


class ApiError(Strict):
    """Every non-2xx response from the new endpoints uses this shape."""

    code: Literal[
        "validation_error", "model_mismatch", "session_not_found",
        "session_stopped", "payload_too_large", "rate_limited",
    ]
    message: str
    detail: list[str] | None = None
