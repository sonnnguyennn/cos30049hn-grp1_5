from fastapi import FastAPI, HTTPException, UploadFile, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager
from starlette.concurrency import run_in_threadpool
from log_store import init_db, read_logs, write_log

@asynccontextmanager
async def lifespan(app: FastAPI):
    await run_in_threadpool(init_db)
    yield

app = FastAPI(title="Goon Cave")

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

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
CHUNK_BYTES = 64 * 1024

class GoonRequest(BaseModel):
    name: str = Field(min_length=1, max_length=67)

class GoonResponse(BaseModel):
    message: str

@app.post("/goon")
def goon(body: GoonRequest) -> GoonResponse:
    return GoonResponse(message=f"Message from server: Currently gooning {body.name} at the moment :3")

class LogEntry(BaseModel):
    id: int
    created_at: str
    event: str
    message: str
    filename: str | None

@app.get("/logs", response_model=list[LogEntry])
def get_logs(limit: int = Query(default=50, ge=1, le=200)):
    return read_logs(limit)
