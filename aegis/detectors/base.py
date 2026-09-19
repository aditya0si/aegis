from __future__ import annotations

from pydantic import BaseModel


class DetectionResult(BaseModel):
    is_malicious: bool
    confidence: float
    detector: str
    details: dict = {}
