"""Boundary helpers for target/tool output entering an LLM prompt.

Tool output is evidence, never an instruction channel. This module removes
control characters and prompt-shaped instruction lines while preserving useful
observations. The original raw output remains available in the session record;
only the prompt projection is sanitized.
"""

import re
from typing import Dict, List

_INJECTION_RE = re.compile(
    r"ignore\s+(?:all\s+)?previous|disregard\s+(?:all\s+)?instructions|"
    r"(?:^|\s)(?:system|developer|assistant)\s*:|follow\s+these\s+instructions|"
    r"new\s+system\s+message|tool\s*call|override\s+the\s+policy",
    re.IGNORECASE,
)
_DELIMITER_RE = re.compile(r"<<<\s*/?(?:TOOL_OUTPUT|SYSTEM|USER|ASSISTANT)[^>]*>>>", re.I)


def project_untrusted_output(text: str, max_chars: int = 4000) -> Dict:
    """Return a bounded, labeled observation projection for an LLM prompt."""
    raw = text or ""
    indicators: List[str] = []
    lines: List[str] = []
    for line in raw.replace("\x00", "").splitlines():
        clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line)
        clean = "".join(ch for ch in clean if ch in "\t" or ord(ch) >= 32)
        if _INJECTION_RE.search(clean):
            indicators.append("prompt_injection_like_text")
            lines.append("[UNTRUSTED_INSTRUCTION_REDACTED]")
            continue
        lines.append(_DELIMITER_RE.sub("[UNTRUSTED_DELIMITER_REDACTED]", clean))
    projected = "\n".join(lines)
    if len(projected) > max_chars:
        projected = projected[:max_chars] + "\n[UNTRUSTED_OUTPUT_TRUNCATED]"
    return {
        "text": projected,
        "indicators": sorted(set(indicators)),
        "truncated": len(projected) >= max_chars,
    }


def prompt_observation(text: str, max_chars: int = 4000) -> str:
    """Render one explicitly non-instructional observation block."""
    projected = project_untrusted_output(text, max_chars=max_chars)
    indicators = ",".join(projected["indicators"]) or "none"
    return (
        "<<<UNTRUSTED_OBSERVATION_START>>>\n"
        f"injection_indicators={indicators}\n"
        f"{projected['text']}\n"
        "<<<UNTRUSTED_OBSERVATION_END>>>"
    )
