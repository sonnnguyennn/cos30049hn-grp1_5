from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

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

class GoonRequest(BaseModel):
    name: str = Field(min_length=1, max_length=67)

class GoonResponse(BaseModel):
    message: str

@app.post("/goon")
def goon(body: GoonRequest) -> GoonResponse:
    return GoonResponse(message=f"Currently stroking {body.name} at the moment :3")
