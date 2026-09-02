from __future__ import annotations
from abc import ABC, abstractmethod
from pydantic import BaseModel

class DetectionResult(BaseModel):
    is_malicious: bool
    confidence: float
    detector: str
    details: dict = {}
