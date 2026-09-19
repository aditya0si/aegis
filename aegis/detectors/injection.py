"""Prompt Injection Detector — 3 layers: heuristic, lexical, LLM-judge fallback."""
from __future__ import annotations

import base64
import math
import re
from collections import Counter
from typing import Any

from pydantic import BaseModel, Field

HEURISTIC_PATTERNS: list[tuple[str, str, float]] = [
    (r"ignore\s+(all\s+)?previous\s+instructions", "ignore_previous", 0.95),
    (r"disregard\s+(all\s+)?(previous|above|prior)\s+(instructions|prompt|rules)", "disregard_previous", 0.92),
    (r"forget\s+(everything|all)\s+(you\s+)?(know|were\s+told)", "forget_instructions", 0.88),
    (r"you\s+are\s+now\s+(a\s+)?(DAN|evil|hacker|uncensored)", "dan_role", 0.95),
    (r"do\s+anything\s+now", "dan_trigger", 0.90),
    (r"jailbreak", "jailbreak_keyword", 0.85),
    (r"system\s*:\s*you\s+are", "fake_system", 0.90),
    (r"\[SYSTEM\]|\[INST\]|<<SYS>>", "system_tag", 0.93),
    (r"override\s+(safety|security|policy|guardrail)", "override_safety", 0.88),
    (r"reveal\s+(your\s+)?(system\s+prompt|instructions|secret|private)", "reveal_system", 0.87),
    (r"act\s+as\s+if\s+you\s+(have\s+)?no\s+(rules|limits|restrictions)", "act_no_limits", 0.86),
    (r"developer\s+mode", "developer_mode", 0.84),
    (r"sudo\s+mode|admin\s+override", "admin_override", 0.85),
    (r"execute\s+(this|the\s+following)\s+code", "execute_code_instruction", 0.75),
    (r"exfiltrate|send\s+(data|secrets)\s+to", "exfiltrate", 0.82),
    (r"base64|atob\(|btoa\(", "base64_keyword", 0.6),
    (r"tool_call.*hidden|hidden\s+tool\s+call", "hidden_tool", 0.80),
    (r"ignore\s+safety|bypass\s+filter", "bypass_filter", 0.88),
    (r"pretend\s+you\s+are\s+not\s+(an\s+)?AI", "pretend_not_ai", 0.82),
    (r"confidential|internal\s+only.*reveal", "confidential_reveal", 0.75),
]

INSTRUCTION_VERBS = {
    "ignore","disregard","forget","reveal","execute","run","delete","send","exfiltrate",
    "bypass","override","act","pretend","assume","simulate","output","print","disclose",
    "leak","dump","extract","decode","decrypt","grant","give","provide","show"
}

class InjectionResult(BaseModel):
    is_injection: bool
    confidence: float = Field(ge=0.0, le=1.0)
    layer_scores: dict[str, float] = Field(default_factory=dict)
    triggered_patterns: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    verdict: str = "allow"

class InjectionDetector:
    def __init__(self, threshold: float = 0.58, enable_llm_judge: bool = False):
        self.threshold = threshold
        self.enable_llm_judge = enable_llm_judge
        self._compiled = [(re.compile(p, re.IGNORECASE), name, w) for p, name, w in HEURISTIC_PATTERNS]

    def _heuristic_score(self, text: str) -> tuple[float, list[str]]:
        triggered: list[str] = []
        max_score = 0.0
        for pat, name, weight in self._compiled:
            if pat.search(text):
                triggered.append(name)
                max_score = max(max_score, weight)
        b64_candidates = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
        for cand in b64_candidates:
            try:
                decoded = base64.b64decode(cand, validate=True).decode("utf-8", errors="ignore")
                if any(v in decoded.lower() for v in INSTRUCTION_VERBS):
                    triggered.append("base64_encoded_instruction")
                    max_score = max(max_score, 0.88)
                    break
            except Exception:
                continue
        if text.count("[") > 5 and "SYSTEM" in text:
            triggered.append("bracket_system_injection")
            max_score = max(max_score, 0.85)
        return max_score, triggered

    def _lexical_score(self, text: str) -> tuple[float, dict]:
        details: dict[str, Any] = {}
        words = re.findall(r"\b\w+\b", text.lower())
        total = len(words) if words else 1
        instr_count = sum(1 for w in words if w in INSTRUCTION_VERBS)
        instr_density = instr_count / total
        details["instruction_density"] = round(instr_density, 4)
        details["instruction_count"] = instr_count
        if text:
            freq = Counter(text)
            length = len(text)
            entropy = -sum((c/length) * math.log2(c/length) for c in freq.values())
            norm_entropy = min(entropy / 8.0, 1.0)
        else:
            entropy = 0.0
            norm_entropy = 0.0
        details["char_entropy"] = round(entropy, 3)
        details["norm_entropy"] = round(norm_entropy, 3)
        b64_score = 0.0
        if re.search(r"[A-Za-z0-9+/]{60,}", text):
            b64_score = 0.7
            details["has_long_b64_blob"] = True
        lexical = 0.0
        if instr_density > 0.08 and instr_count >= 2:
            lexical = max(lexical, 0.75 + min(instr_density * 2, 0.2))
        elif instr_density > 0.04 and instr_count >= 2:
            lexical = max(lexical, 0.55)
        # single instruction verb alone is not strong signal unless accompanied by heuristic
        elif instr_count == 1 and instr_density > 0.08:
            lexical = max(lexical, 0.35)
        if norm_entropy > 0.72 and instr_count > 2:
            lexical = max(lexical, 0.68)
        if b64_score > 0:
            lexical = max(lexical, b64_score)
        if len(text) > 800 and instr_count > 5:
            lexical = max(lexical, 0.62)
        details["lexical_score"] = round(lexical, 3)
        return lexical, details

    def _llm_judge_score(self, text: str) -> float | None:
        if not self.enable_llm_judge:
            return None
        suspicious_phrases = ["ignore previous", "system prompt", "DAN", "jailbreak", "override"]
        hits = sum(1 for p in suspicious_phrases if p.lower() in text.lower())
        if hits >= 2:
            return 0.92
        if hits == 1:
            return 0.65
        return 0.15

    def detect(self, text: str) -> InjectionResult:
        if not text or not text.strip():
            return InjectionResult(is_injection=False, confidence=0.05, layer_scores={"heuristic":0.0,"lexical":0.0}, triggered_patterns=[], details={"empty": True}, verdict="allow")
        heuristic_score, triggered = self._heuristic_score(text)
        lexical_score, lexical_details = self._lexical_score(text)
        llm_score = self._llm_judge_score(text)
        layer_scores = {"heuristic": round(heuristic_score,3), "lexical": round(lexical_score,3)}
        if llm_score is not None:
            layer_scores["llm_judge"] = round(llm_score,3)
        combined = max(heuristic_score, lexical_score)
        if heuristic_score > 0.7 and lexical_score > 0.5:
            combined = min(0.99, combined + 0.08)
        if llm_score is not None:
            combined = max(combined, llm_score * 0.9)
        if heuristic_score < 0.3 and lexical_score < 0.6:
            combined = lexical_score * 0.85
        is_injection = combined >= self.threshold
        verdict = "block" if is_injection else "allow"
        details = {**lexical_details, "text_length": len(text)}
        if llm_score is not None:
            details["llm_judge_score"] = llm_score
        return InjectionResult(
            is_injection=is_injection,
            confidence=round(combined,3),
            layer_scores=layer_scores,
            triggered_patterns=triggered,
            details=details,
            verdict=verdict,
        )

    async def adetect(self, text: str) -> InjectionResult:
        return self.detect(text)
