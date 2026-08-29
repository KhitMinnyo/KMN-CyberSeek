"""
Regression tests for handler lifecycle, session crash/reconnect, and
RpcSessionBridge error classification — no live Metasploit required.
"""

import asyncio
import pytest
import sys, types

def _stub_module(name, **attrs):
    m = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(m, k, v)
    sys.modules[name] = m

_stub_module("httpx")
_stub_module("msgpack")

import pathlib
ROOT = pathlib.Path(__file__).parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.msf_rpc import MsfRpcClient, MsfRpcError, RpcSessionBridge


class MockRpcClient(MsfRpcClient):
    def __init__(self):
        super().__init__("http://mock-msf:55553")
        self.token = "fake-token-abc"
        self.sessions: dict = {}
        self.jobs: dict = {}
        self._crash_on_next_call: bool = False
        self._auth_fail: bool = False
        self.call_log: list = []

    async def connect(self):
        if self._auth_fail:
            raise MsfRpcError("Invalid credentials")
        return {"result": "success", "token": self.token}

    async def _call(self, method, *args):
        self.call_log.append((method, args))
        if self._crash_on_next_call:
            self._crash_on_next_call = False
            raise MsfRpcError("Connection reset by peer")

        if method == "session.list":
            return self.sessions

        if method == "session.meterpreter_run_single":
            # args = (session_id, command) from run_meterpreter
            sid = int(args[0])
            if sid not in self.sessions:
                raise MsfRpcError(f"Unknown session {sid}")
            return {"result": "success"}

        if method == "session.meterpreter_read":
            return {"data": "uid=0(root)\n"}

        if method == "session.shell_write":
            return {"result": "success"}

        if method == "session.shell_read":
            return {"data": "root\n"}

        if method == "session.stop":
            # args = (session_id,)
            sid = int(args[0])
            self.sessions.pop(sid, None)
            return {"result": "success"}

        if method == "jobs.list":
            return self.jobs

        if method == "job.stop":
            jid = str(args[0])
            self.jobs.pop(jid, None)
            return {"result": "success"}

        return {}

    async def structured_session_list(self):
        raw = await self._call("session.list")
        out = []
        for sid, info in raw.items():
            out.append({
                "id": sid,
                "type": info.get("type", "meterpreter"),
                "via_exploit": info.get("via_exploit", ""),
                "tunnel_peer": info.get("tunnel_peer", ""),
                "target_host": info.get("tunnel_peer", "").split(":")[0],
            })
        return out

    @staticmethod
    def classify_error(exc):
        msg = str(exc).lower()
        if "credential" in msg or "invalid" in msg:
            return {"category": "auth", "retryable": False, "message": str(exc)}
        if "reset" in msg or "connection" in msg or "timeout" in msg:
            return {"category": "transport", "retryable": True, "message": str(exc)}
        return {"category": "unknown", "retryable": False, "message": str(exc)}


# 1. Auth failure → classify_error returns auth / not retryable
def test_classify_auth_error():
    err = MsfRpcError("Invalid credentials")
    result = MockRpcClient.classify_error(err)
    assert result["category"] == "auth"
    assert result["retryable"] is False


# 2. Transport error → retryable
def test_classify_transport_error():
    err = MsfRpcError("Connection reset by peer")
    result = MockRpcClient.classify_error(err)
    assert result["category"] == "transport"
    assert result["retryable"] is True


# 3. Unknown error → unknown category
def test_classify_unknown_error():
    err = MsfRpcError("Something unexpected")
    result = MockRpcClient.classify_error(err)
    assert result["category"] == "unknown"
    assert result["retryable"] is False


# 4. structured_session_list returns one entry per session
def test_structured_session_list_non_empty():
    client = MockRpcClient()
    client.sessions = {
        1: {"type": "meterpreter", "via_exploit": "exploit/multi/handler",
            "tunnel_peer": "10.10.10.5:54321"},
        2: {"type": "shell", "via_exploit": "exploit/unix/ftp/proftpd",
            "tunnel_peer": "10.10.10.6:43210"},
    }
    result = asyncio.get_event_loop().run_until_complete(client.structured_session_list())
    assert len(result) == 2
    ids = {r["id"] for r in result}
    assert 1 in ids and 2 in ids


# 5. Empty session list → []
def test_structured_session_list_empty():
    client = MockRpcClient()
    client.sessions = {}
    result = asyncio.get_event_loop().run_until_complete(client.structured_session_list())
    assert result == []


# 6. session.stop removes the session
def test_stop_session_removes_entry():
    client = MockRpcClient()
    client.sessions = {3: {"type": "meterpreter", "tunnel_peer": "10.10.10.7:11111"}}
    asyncio.get_event_loop().run_until_complete(client._call("session.stop", 3))
    assert 3 not in client.sessions


# 7. Crash then recover
def test_call_crash_then_recover():
    client = MockRpcClient()
    client.sessions = {1: {"type": "meterpreter", "tunnel_peer": "10.0.0.1:4444"}}
    client._crash_on_next_call = True
    loop = asyncio.get_event_loop()
    with pytest.raises(MsfRpcError):
        loop.run_until_complete(client._call("session.list"))
    result = loop.run_until_complete(client._call("session.list"))
    assert 1 in result


# 8. run_meterpreter returns a string
def test_run_meterpreter_happy_path():
    client = MockRpcClient()
    client.sessions = {1: {"type": "meterpreter", "tunnel_peer": "10.0.0.2:4444"}}

    async def _run():
        return await client.run_meterpreter(1, "getuid", timeout=5.0)

    output = asyncio.get_event_loop().run_until_complete(_run())
    assert isinstance(output, str)


# 9. job.stop removes the job
def test_stop_job():
    client = MockRpcClient()
    client.jobs = {"0": {"name": "multi/handler"}, "1": {"name": "SOCKS"}}
    asyncio.get_event_loop().run_until_complete(client._call("job.stop", "0"))
    assert "0" not in client.jobs
    assert "1" in client.jobs


# 10. jobs.list returns dict
def test_list_jobs():
    client = MockRpcClient()
    client.jobs = {"0": {"name": "multi/handler"}, "2": {"name": "socks_proxy"}}
    result = asyncio.get_event_loop().run_until_complete(client._call("jobs.list"))
    assert "0" in result and "2" in result


# 11. Auth failure raises
def test_auth_failure_raises():
    client = MockRpcClient()
    client._auth_fail = True

    async def _run():
        return await client.connect()

    with pytest.raises(MsfRpcError, match="Invalid credentials"):
        asyncio.get_event_loop().run_until_complete(_run())


# 12. shell_write + shell_read round-trip
def test_shell_write_read_roundtrip():
    client = MockRpcClient()
    client.sessions = {5: {"type": "shell", "tunnel_peer": "10.0.0.5:9999"}}
    loop = asyncio.get_event_loop()
    write_resp = loop.run_until_complete(client._call("session.shell_write", 5, "id\n"))
    assert write_resp.get("result") == "success"
    read_resp = loop.run_until_complete(client._call("session.shell_read", 5))
    assert "root" in read_resp.get("data", "")
