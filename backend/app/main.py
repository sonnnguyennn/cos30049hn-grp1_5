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

app = FastAPI(title="Goon Cave", lifespan=lifespan)

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
                    detail="Choose a file no larger than 10 MiB",
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
