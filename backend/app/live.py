"""Live (Replay Monitoring) endpoints: Pi -> backend -> frontend.

Implements the contract in docs/live-api-contract.md using the schemas in
live_schemas.py. The Pi predicts locally; this module only stores the events it
receives and never runs inference again. Sessions live in memory, so they are
lost when the server restarts (acceptable for the demo; Manual Analysis does
not depend on them).
"""

import logging
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from . import analyze_csv as _analyzer
from .live_schemas import (
    ApiError,
    EventBatch,
    EventBatchResult,
    EventPage,
    Heartbeat,
    LiveLimits,
    MAX_EVENTS_PER_BATCH,
    MAX_HISTORY_PER_SESSION,
    OFFLINE_AFTER_SECONDS,
    STALE_AFTER_SECONDS,
    Session,
    SessionCreate,
    SessionStatus,
    StoredEvent,
)

MODEL_UNAVAILABLE_MESSAGE = "The prediction model is unavailable; contact the operator"

router = APIRouter(prefix="/live", tags=["live"])


# --- Errors -----------------------------------------------------------------------------

class LiveError(Exception):
    """Raised by live endpoints; rendered as the ApiError body."""

    def __init__(self, status_code, code, message, detail=None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.detail = detail


def _error_response(status_code, code, message, detail=None):
    body = ApiError(code=code, message=message, detail=detail).model_dump(mode="json")
    return JSONResponse(status_code=status_code, content=body)


def _path(loc):
    text = ""
    for part in loc:
        if isinstance(part, int):
            text += f"[{part}]"
        else:
            text += ("." if text else "") + str(part)
    return text


def format_errors(errors, *, drop_source=False):
    """Turn pydantic/FastAPI error dicts into short human-readable strings."""
    details = []
    for error in errors[:20]:
        loc = tuple(error.get("loc", ()))
        if drop_source and loc and loc[0] in ("body", "query", "path"):
            loc = loc[1:]
        message = str(error.get("msg", "invalid value"))
        if message.startswith("Value error, "):
            message = message[len("Value error, "):]
        where = _path(loc)
        details.append(f"{where}: {message}" if where else message)
    return details


async def _live_error_handler(request: Request, error: LiveError):
    return _error_response(error.status_code, error.code, error.message, error.detail)


async def _validation_handler(request: Request, error: RequestValidationError):
    # Only the live endpoints use the {code, message, detail} body; /predict and the
    # other existing endpoints keep FastAPI's standard 422 response.
    if request.url.path.startswith("/live"):
        return _error_response(
            422, "validation_error", "Invalid request",
            format_errors(error.errors(), drop_source=True))
    return await request_validation_exception_handler(request, error)


def register_live(app: FastAPI) -> None:
    app.include_router(router)
    app.add_exception_handler(LiveError, _live_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_handler)


# --- Session store ----------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class _SessionState:
    session: Session
    events: list = field(default_factory=list)       # retained StoredEvent objects
    seen_ids: set = field(default_factory=set)        # every event_id ever accepted
    next_server_seq: int = 1
    last_pi_seq: int | None = None
    last_seen_at: datetime | None = None
    total_received: int = 0
    benign: int = 0
    malicious: int = 0
    labelled: int = 0
    correct: int = 0
    duplicates_ignored: int = 0
    dropped_from_history: int = 0
    gaps_detected: int = 0


_SESSIONS: dict[str, _SessionState] = {}
_LOCK = threading.RLock()


def reset() -> None:
    """Forget all sessions (used by tests)."""
    with _LOCK:
        _SESSIONS.clear()


def _backend_model():
    try:
        return _analyzer.load_model()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        logging.getLogger(__name__).error("Live model check unavailable: %s", error)
        raise HTTPException(503, MODEL_UNAVAILABLE_MESSAGE) from error


def _get(session_id: str) -> _SessionState:
    state = _SESSIONS.get(session_id)
    if state is None:
        raise LiveError(404, "session_not_found", "Unknown session")
    return state


def _check_hash(received: str, expected: str, what: str) -> None:
    if received != expected:
        raise LiveError(
            409, "model_mismatch",
            f"Pi model hash differs from the backend's frozen model; {what} were not stored.",
            [f"expected {expected}", f"received {received[:64]}"])


def _connection(state: _SessionState, now: datetime):
    if state.last_seen_at is None:
        return "connecting", None
    age = max((now - state.last_seen_at).total_seconds(), 0.0)
    if age >= OFFLINE_AFTER_SECONDS:
        return "offline", age
    if age >= STALE_AFTER_SECONDS:
        return "stale", age
    return "connected", age


_ERRORS = {
    404: {"model": ApiError, "description": "session_not_found"},
    409: {"model": ApiError, "description": "session_stopped or model_mismatch"},
    422: {"model": ApiError, "description": "validation_error"},
    503: {"description": "Frozen model unavailable"},
}


# --- Endpoints --------------------------------------------------------------------------

@router.get("/limits", response_model=LiveLimits)
def get_limits():
    """Batch size, history size and connection-state thresholds."""
    return LiveLimits(
        max_events_per_batch=MAX_EVENTS_PER_BATCH,
        max_history_per_session=MAX_HISTORY_PER_SESSION,
        stale_after_seconds=STALE_AFTER_SECONDS,
        offline_after_seconds=OFFLINE_AFTER_SECONDS)


@router.post("/sessions", response_model=Session, status_code=201,
             responses={422: _ERRORS[422], 503: _ERRORS[503]})
def create_session(body: SessionCreate):
    """Start a live session (frontend). Returns the session_id the Pi must use."""
    predictor = _backend_model()
    session = Session(
        session_id=f"ses_{secrets.token_hex(4)}",
        source_name=body.source_name,
        state="active",
        created_at=_now(),
        stopped_at=None,
        model_id=predictor.model_id,
        model_sha256=predictor.model_sha256)
    with _LOCK:
        _SESSIONS[session.session_id] = _SessionState(session=session)
    return session


@router.post("/sessions/{session_id}/stop", response_model=Session,
             responses={404: _ERRORS[404]})
def stop_session(session_id: str):
    """Stop a session. Stopping an already stopped session returns it unchanged."""
    with _LOCK:
        state = _get(session_id)
        if state.session.state == "active":
            state.session = state.session.model_copy(
                update={"state": "stopped", "stopped_at": _now()})
        return state.session


@router.post("/sessions/{session_id}/events", response_model=EventBatchResult,
             responses={k: _ERRORS[k] for k in (404, 409, 422, 503)}
             | {413: {"model": ApiError, "description": "payload_too_large"}})
async def post_events(session_id: str, request: Request):
    """Receive a batch of 1-100 events already predicted on the Pi (see EventBatch).

    The body is parsed here rather than by FastAPI so that an oversized batch is
    answered with 413 payload_too_large instead of a generic 422.
    """
    with _LOCK:
        _get(session_id)
    try:
        payload = await request.json()
    except ValueError:
        raise LiveError(422, "validation_error", "Invalid event batch",
                        ["body must be valid JSON"])
    if (isinstance(payload, dict) and isinstance(payload.get("events"), list)
            and len(payload["events"]) > MAX_EVENTS_PER_BATCH):
        raise LiveError(
            413, "payload_too_large",
            f"A batch can hold at most {MAX_EVENTS_PER_BATCH} events",
            [f"received {len(payload['events'])} events"])
    try:
        batch = EventBatch.model_validate(payload)
    except ValidationError as error:
        raise LiveError(422, "validation_error", "Invalid event batch",
                        format_errors(error.errors()))

    predictor = _backend_model()
    with _LOCK:
        state = _get(session_id)
        if state.session.state == "stopped":
            raise LiveError(409, "session_stopped", "The session has been stopped")
        _check_hash(batch.model_sha256, predictor.model_sha256, "events")

        received_at = _now()
        accepted = duplicates = 0
        gap = False
        for event in batch.events:
            if event.event_id in state.seen_ids:
                duplicates += 1
                continue
            if state.last_pi_seq is not None and event.pi_seq > state.last_pi_seq + 1:
                gap = True
                state.gaps_detected += 1
            state.seen_ids.add(event.event_id)
            is_correct = (None if event.ground_truth is None
                          else event.label == event.ground_truth)
            state.events.append(StoredEvent(
                **event.model_dump(),
                server_seq=state.next_server_seq,
                received_at=received_at,
                correct=is_correct))
            state.next_server_seq += 1
            state.last_pi_seq = (event.pi_seq if state.last_pi_seq is None
                                 else max(state.last_pi_seq, event.pi_seq))
            state.total_received += 1
            if event.label == "malicious":
                state.malicious += 1
            else:
                state.benign += 1
            if is_correct is not None:
                state.labelled += 1
                state.correct += int(is_correct)
            accepted += 1

        dropped = max(len(state.events) - MAX_HISTORY_PER_SESSION, 0)
        if dropped:
            del state.events[:dropped]
        state.dropped_from_history += dropped
        state.duplicates_ignored += duplicates
        state.last_seen_at = received_at

        return EventBatchResult(
            accepted=accepted, duplicates=duplicates, dropped_from_history=dropped,
            last_pi_seq=state.last_pi_seq, gap_detected=gap)


@router.post("/sessions/{session_id}/heartbeat", status_code=204,
             responses={k: _ERRORS[k] for k in (404, 409, 422, 503)})
def post_heartbeat(session_id: str, body: Heartbeat):
    """Keep the connection state 'connected' while the Pi has nothing to send."""
    predictor = _backend_model()
    with _LOCK:
        state = _get(session_id)
        if state.session.state == "stopped":
            raise LiveError(409, "session_stopped", "The session has been stopped")
        _check_hash(body.model_sha256, predictor.model_sha256, "heartbeats")
        state.last_seen_at = _now()
    return Response(status_code=204)


@router.get("/sessions/{session_id}/events", response_model=EventPage,
            responses={404: _ERRORS[404]})
def get_events(session_id: str,
               after_seq: int = Query(0, ge=0),
               limit: int = Query(100, ge=1, le=MAX_HISTORY_PER_SESSION)):
    """Return stored events with server_seq > after_seq (oldest first)."""
    with _LOCK:
        state = _get(session_id)
        page = [event for event in state.events if event.server_seq > after_seq][:limit]
        next_after = page[-1].server_seq if page else after_seq
        return EventPage(events=page, next_after_seq=next_after)


@router.get("/sessions/{session_id}/status", response_model=SessionStatus,
            responses={404: _ERRORS[404]})
def get_status(session_id: str):
    """Connection state and counters. Accuracy counters cover labelled events only."""
    with _LOCK:
        state = _get(session_id)
        now = _now()
        connection, age = _connection(state, now)
        return SessionStatus(
            session=state.session,
            connection=connection,
            last_seen_at=state.last_seen_at,
            seconds_since_last_seen=None if age is None else round(age, 3),
            total_received=state.total_received,
            benign=state.benign,
            malicious=state.malicious,
            labelled=state.labelled,
            correct=state.correct,
            duplicates_ignored=state.duplicates_ignored,
            dropped_from_history=state.dropped_from_history,
            gaps_detected=state.gaps_detected,
            history_limit=MAX_HISTORY_PER_SESSION)