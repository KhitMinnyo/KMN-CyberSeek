"""
KMN-CyberSeek Structured AI Action Model

Instead of returning a plain command string, the AI response should include
structured metadata that the orchestrator needs to route, verify, and fall back
safely.  This module defines the schema and a JSON/text parser that extracts
the structured fields from AI responses that may contain both prose and JSON.

Expected AI response format (JSON block inside markdown or raw):
{
  "command":            "msfconsole -q -x ...",
  "execution_channel":  "console" | "rpc_meterpreter" | "rpc_shell" | "local_shell",
  "handler_id":         "a1b2c3d4",           // optional
  "msf_id":             3,                    // MSF session id, optional
  "target_host":        "10.0.1.5",
  "target_port":        8080,
  "action_type":        "exploit" | "recon" | "post_exploit" | "pivot" | "brute",
  "expected_result":    "meterpreter session opened on 10.0.1.5",
  "verification_method": "msf_session" | "ssh" | "web_rce" | "root_priv" | ...,
  "fallback_action":    "try linux/x86/meterpreter/reverse_tcp instead",
  "rationale":          "optional free-text"
}
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# Valid values for enum fields (loose — AI may produce minor variations)
EXECUTION_CHANNELS = {"console", "rpc_meterpreter", "rpc_shell", "local_shell", "msf"}
ACTION_TYPES = {"exploit", "recon", "post_exploit", "pivot", "brute", "scan",
                "validate", "cleanup", "report", "other"}
VERIFICATION_METHODS = {
    "msf_session", "ssh", "winrm", "smb", "web_rce", "sql",
    "ftp", "root_priv", "credential", "callback", "manual", "none",
}


@dataclass
class StructuredAction:
    """One AI-directed action with full routing and verification metadata."""

    # Core command
    command:              str  = ""

    # Routing
    execution_channel:    str  = "console"       # where to run
    handler_id:           str  = ""              # which ShellManager handler
    msf_id:               int  = 0               # MSF session id (0 = no session)

    # Target
    target_host:          str  = ""
    target_port:          int  = 0

    # Semantics
    action_type:          str  = "other"
    expected_result:      str  = ""
    verification_method:  str  = "none"
    fallback_action:      str  = ""
    rationale:            str  = ""

    # Raw source (not sent to tools)
    _raw_json:            Optional[Dict] = field(default=None, repr=False)

    def is_valid(self) -> bool:
        return bool(self.command and self.command.strip())

    def to_dict(self) -> Dict:
        d = asdict(self)
        d.pop("_raw_json", None)
        return d

    def needs_session(self) -> bool:
        return self.execution_channel in ("rpc_meterpreter", "rpc_shell") or self.msf_id > 0

    def verification_tool(self) -> str:
        """Return the validator key for tool_validate()."""
        return self.verification_method if self.verification_method in VERIFICATION_METHODS else "none"


# ── JSON extraction from AI response ─────────────────────────────────────────

# Match the FIRST ```json ... ``` or { ... } block in AI output
_FENCE_RE = re.compile(
    r"```(?:json)?\s*(\{.*?\})\s*```",
    re.DOTALL | re.IGNORECASE,
)
_BARE_JSON_RE = re.compile(r"(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})", re.DOTALL)

_CHANNEL_ALIASES = {
    "msf":       "console",
    "msfconsole":"console",
    "rpc":       "rpc_meterpreter",
    "meterpreter": "rpc_meterpreter",
    "shell":     "rpc_shell",
    "local":     "local_shell",
}


def _normalise_channel(raw: str) -> str:
    s = (raw or "").strip().lower()
    return _CHANNEL_ALIASES.get(s, s if s in EXECUTION_CHANNELS else "console")


def _normalise_action_type(raw: str) -> str:
    s = (raw or "").strip().lower()
    if s in ACTION_TYPES:
        return s
    for at in ACTION_TYPES:
        if at in s:
            return at
    return "other"


def _normalise_verify(raw: str) -> str:
    s = (raw or "").strip().lower()
    if s in VERIFICATION_METHODS:
        return s
    for v in VERIFICATION_METHODS:
        if v in s:
            return v
    return "none"


def _try_parse_json(text: str) -> Optional[Dict]:
    """Try fenced block first, then first bare JSON object."""
    m = _FENCE_RE.search(text)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    for m in _BARE_JSON_RE.finditer(text):
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
    return None


def parse_structured_action(ai_response: str,
                              fallback_command: str = "") -> StructuredAction:
    """Parse an AI response into a StructuredAction.

    Accepts:
    - A JSON block (fenced or bare) with the structured fields
    - Plain text — treated as command only, all other fields default

    Args:
        ai_response:      raw AI output string
        fallback_command: plain command extracted by the legacy parser (used
                          when the JSON block has no "command" key)
    """
    raw = _try_parse_json(ai_response or "")
    if not raw or not isinstance(raw, dict):
        # Legacy path: no structured JSON found
        cmd = fallback_command or ai_response.strip()
        return StructuredAction(command=cmd)

    cmd = raw.get("command") or raw.get("cmd") or fallback_command or ""
    action = StructuredAction(
        command             = cmd.strip(),
        execution_channel   = _normalise_channel(raw.get("execution_channel", "console")),
        handler_id          = str(raw.get("handler_id") or ""),
        msf_id              = int(raw.get("msf_id") or 0),
        target_host         = str(raw.get("target_host") or ""),
        target_port         = int(raw.get("target_port") or 0),
        action_type         = _normalise_action_type(raw.get("action_type", "")),
        expected_result     = str(raw.get("expected_result") or ""),
        verification_method = _normalise_verify(raw.get("verification_method", "")),
        fallback_action     = str(raw.get("fallback_action") or ""),
        rationale           = str(raw.get("rationale") or ""),
        _raw_json           = raw,
    )
    return action


def extract_all_actions(ai_response: str) -> List[StructuredAction]:
    """Extract every structured action JSON block from a multi-step AI response."""
    actions = []
    for m in _FENCE_RE.finditer(ai_response or ""):
        try:
            d = json.loads(m.group(1))
            if isinstance(d, dict) and ("command" in d or "cmd" in d):
                actions.append(parse_structured_action(m.group(1)))
        except json.JSONDecodeError:
            pass
    if not actions:
        actions.append(parse_structured_action(ai_response))
    return actions


# ── Prompt snippet that tells the AI to use structured actions ────────────────

STRUCTURED_ACTION_PROMPT = """
When proposing a command, respond with a JSON block inside a markdown fence:

```json
{
  "command":             "<full shell or MSF command>",
  "execution_channel":   "console | rpc_meterpreter | rpc_shell | local_shell",
  "handler_id":          "<handler id if applicable, else omit>",
  "msf_id":              <MSF session id integer, 0 if none>,
  "target_host":         "<IP or hostname>",
  "target_port":         <port integer, 0 if not applicable>,
  "action_type":         "exploit | recon | post_exploit | pivot | brute | scan | validate",
  "expected_result":     "<what a successful result looks like>",
  "verification_method": "msf_session | ssh | winrm | smb | web_rce | sql | ftp | root_priv | credential | callback | none",
  "fallback_action":     "<next command if this fails>",
  "rationale":           "<one line: why this action now>"
}
```

Do NOT return a plain command string. Always use the JSON structure above.
""".strip()
