"""Tests for core/ai_action.py structured AI action parsing — no live target."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import json
from core.ai_action import (
    parse_structured_action, extract_all_actions,
    StructuredAction, STRUCTURED_ACTION_PROMPT,
)


def test_parse_fenced_json():
    ai_resp = """Let me exploit this service.

```json
{
  "command": "nmap -sV 10.0.0.1",
  "execution_channel": "local_shell",
  "target_host": "10.0.0.1",
  "target_port": 80,
  "action_type": "scan",
  "expected_result": "open ports listed",
  "verification_method": "none",
  "fallback_action": "use masscan instead"
}
```
"""
    action = parse_structured_action(ai_resp)
    assert action.command == "nmap -sV 10.0.0.1"
    assert action.execution_channel == "local_shell"
    assert action.target_host == "10.0.0.1"
    assert action.target_port == 80
    assert action.action_type == "scan"
    assert action.fallback_action == "use masscan instead"


def test_parse_plain_text_fallback():
    action = parse_structured_action("nmap -sV 10.0.0.5", fallback_command="nmap -sV 10.0.0.5")
    assert action.command == "nmap -sV 10.0.0.5"
    assert action.execution_channel == "console"


def test_channel_alias_meterpreter():
    ai_resp = '{"command": "run hashdump", "execution_channel": "meterpreter"}'
    action = parse_structured_action(ai_resp)
    assert action.execution_channel == "rpc_meterpreter"


def test_channel_alias_msf():
    ai_resp = '{"command": "set RHOSTS 10.0.0.1", "execution_channel": "msf"}'
    action = parse_structured_action(ai_resp)
    assert action.execution_channel == "console"


def test_action_type_normalise():
    ai_resp = '{"command": "id", "action_type": "post exploitation"}'
    action = parse_structured_action(ai_resp)
    assert action.action_type == "post_exploit"


def test_to_dict_excludes_raw():
    ai_resp = '{"command": "id", "action_type": "recon"}'
    action = parse_structured_action(ai_resp)
    d = action.to_dict()
    assert "_raw_json" not in d
    assert d["command"] == "id"


def test_needs_session():
    a = StructuredAction(command="run hashdump", execution_channel="rpc_meterpreter")
    assert a.needs_session()
    b = StructuredAction(command="nmap -sV x", execution_channel="console")
    assert not b.needs_session()


def test_extract_all_actions_multiple():
    ai_resp = """
Step 1:
```json
{"command": "nmap 10.0.0.1", "action_type": "scan"}
```
Step 2:
```json
{"command": "gobuster dir -u http://10.0.0.1", "action_type": "recon"}
```
"""
    actions = extract_all_actions(ai_resp)
    assert len(actions) == 2
    assert actions[0].command == "nmap 10.0.0.1"
    assert actions[1].action_type == "recon"


def test_prompt_contains_required_fields():
    for field in ("execution_channel", "verification_method", "fallback_action",
                  "target_host", "action_type"):
        assert field in STRUCTURED_ACTION_PROMPT


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS  {name}")
    print("All structured_action tests passed.")
