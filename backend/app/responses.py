"""Versioned public prediction schema; unknown fields are rejected."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Prediction(ResponseModel):
    row: int = Field(ge=1)
    sample_name: str
    label: Literal["benign", "malicious"]
    score: float = Field(ge=0, le=1)
    probability_malicious: float = Field(ge=0, le=1)
    probability_benign: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)
    ground_truth: Literal["benign", "malicious"] | None
    correct: bool | None


class AnalysisSummaryModel(ResponseModel):
    id: str
    name: str
    algorithm: str
    objective: str
    sha256: str


class AnalysisSummaryPreprocessor(ResponseModel):
    name: str
    feature_count: int
    input_dtype: str
    model_dtype: str
    scaling_applied: bool
    steps: list[str]


class AnalysisSummaryGroundTruth(ResponseModel):
    source: str | None
    provided_rows: int
    missing_rows: int
    correct: int
    incorrect: int
    accuracy: float | None


class AnalysisSummary(ResponseModel):
    rows: int
    features: int
    benign: int
    malicious: int
    file_name: str | None
    input_format: str | None
    file_size_bytes: int | None
    mode: str
    started_at: str
    inference_ms: float
    malicious_rate: float
    mean_score: float
    mean_confidence: float
    score_type: str
    threshold: float
    model: AnalysisSummaryModel
    preprocessor: AnalysisSummaryPreprocessor
    ground_truth: AnalysisSummaryGroundTruth
    completed_at: str
    processing_ms: float


class AnalysisResponse(ResponseModel):
    schema_version: Literal["traffic_analysis_v2"]
    model: str
    threshold: float
    runtime: dict[str, str]
    summary: AnalysisSummary
    results: list[Prediction]
    feature_stats: list[dict[str, str | float]]
