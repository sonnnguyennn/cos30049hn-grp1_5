import json
import logging

import numpy as np
import xgboost as xgb
from fastapi import FastAPI, HTTPException, UploadFile, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager
from starlette.concurrency import run_in_threadpool
from .log_store import init_db, read_logs, write_log
from .responses import AnalysisResponse
from .upload_limits import MAX_UPLOAD_BYTES, UPLOAD_LIMIT_MESSAGE
from .analyze_csv import analyze_file, load_model
from .live import register_live
from .live_schemas import ModelInfo
from .predictor import N_FEATURES, THRESHOLD

@asynccontextmanager
async def lifespan(app: FastAPI):
    await run_in_threadpool(init_db)
    yield

app = FastAPI(title="Goon Cave", lifespan=lifespan)
register_live(app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

CHUNK_BYTES = 64 * 1024
MODEL_UNAVAILABLE_MESSAGE = "The prediction model is unavailable; contact the operator"

class GoonRequest(BaseModel):
    name: str = Field(min_length=1, max_length=67)

class GoonResponse(BaseModel):
    message: str

class FileInfo(BaseModel):
    filename: str
    size_bytes: int
    content_type: str | None

class LogEntry(BaseModel):
    id: int
    created_at: str
    event: str
    message: str
    filename: str | None

@app.post("/goon")
def goon(body: GoonRequest) -> GoonResponse:
    return GoonResponse(message=f"Message from server: Currently gooning {body.name} at the moment :3")


@app.get("/model/info", response_model=ModelInfo,
         responses={503: {"description": "Frozen model unavailable"}})
def get_model_info():
    """Describe the frozen model the backend serves (name, hash, 115-column input order)."""
    try:
        predictor = load_model()
        objective = json.loads(predictor.booster.save_config())["learner"]["objective"]["name"]
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        logging.getLogger(__name__).error("Model information unavailable: %s", error)
        raise HTTPException(503, MODEL_UNAVAILABLE_MESSAGE) from error
    return ModelInfo(
        model_id=predictor.model_id,
        model_sha256=predictor.model_sha256,
        algorithm="XGBoost",
        objective=objective,
        threshold=THRESHOLD,
        feature_count=N_FEATURES,
        feature_order=predictor.feature_order,
        input_view="raw",
        scaling_applied=False,
        runtime={"numpy": np.__version__, "xgboost": xgb.__version__},
    )


@app.get("/logs", response_model=list[LogEntry])
def get_logs(limit: int = Query(default=50, ge=1, le=200)):
    return read_logs(limit)

@app.post("/files/inspect")
async def inspect_file(file: UploadFile) -> FileInfo:
    filename = file.filename or "unnamed"
    content_type = file.content_type
    size = 0

    try:
        while chunk := await file.read(CHUNK_BYTES):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=UPLOAD_LIMIT_MESSAGE,
                )

        if size == 0:
            raise HTTPException(
                status_code=400,
                detail="The uploaded file is empty",
            )
    finally:
        await file.close()

    await run_in_threadpool(
        write_log,
        "upload_inspected",
        f"Inspected {size} bytes",
        filename,
    )

    return FileInfo(
        filename=filename,
        size_bytes=size,
        content_type=content_type,
    )


@app.post("/predict", response_model=AnalysisResponse,
          responses={400: {"description": "Invalid feature input"},
                     413: {"description": "Upload exceeds limit"},
                     503: {"description": "Frozen model unavailable"}})
async def predict_file(file: UploadFile):
    # Read in chunks so an oversized upload is rejected early.
    content = bytearray()
    try:
        while chunk := await file.read(CHUNK_BYTES):
            content.extend(chunk)
            if len(content) > MAX_UPLOAD_BYTES:
                raise HTTPException(413, UPLOAD_LIMIT_MESSAGE)
    finally:
        await file.close()

    try:
        return await run_in_threadpool(analyze_file, content, file.filename or "")
    except ValueError as error:
        raise HTTPException(400, str(error))
    except (OSError, RuntimeError) as error:
        import logging
        logging.getLogger(__name__).error("Prediction resource unavailable: %s", error)
        raise HTTPException(503, "The prediction model is unavailable; contact the operator") from error
