"""Mock tests for core/msf_rpc.py — no live Metasploit required."""
import sys, os, asyncio, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.msf_rpc import MsfRpcClient, MsfRpcError, RpcSessionBridge


class MockRpcClient(MsfRpcClient):
    """Subclass that returns canned responses without network I/O."""
    def __init__(self, sessions=None, fail_connect=False, fail_auth=False):
        super().__init__("http://mock:55553", username="msf", password="pass")
        self.token = "mock_token"
        self._sessions = sessions or {}
        self._fail_connect = fail_connect
        self._fail_auth = fail_auth

    async def connect(self):
        if self._fail_auth:
            raise MsfRpcError("401 Unauthorized authentication failure")
        if self._fail_connect:
            raise MsfRpcError("Connection refused")
        return {"result": "success", "token": self.token}

    async def list_sessions(self):
        return self._sessions

    async def structured_session_list(self):
        sessions = []
        for sid, meta in self._sessions.items():
            sessions.append({
                "id":          sid,
                "type":        meta.get("type", "meterpreter"),
                "tunnel_peer": meta.get("tunnel_peer", ""),
                "target_host": meta.get("tunnel_peer", "").split(":")[0],
                "via_exploit": meta.get("via_exploit", ""),
                "status":      "open",
                "source":      "rpc",
            })
        return sessions

    async def stop_session(self, session_id):
        self._sessions.pop(str(session_id), None)
        return {"result": "success"}


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_structured_session_list():
    client = MockRpcClient(sessions={
        "1": {"type": "meterpreter", "tunnel_peer": "10.0.0.5:4444",
              "via_exploit": "exploit/multi/handler"},
    })
    sessions = run(client.structured_session_list())
    assert len(sessions) == 1
    assert sessions[0]["target_host"] == "10.0.0.5"
    assert sessions[0]["source"] == "rpc"


def test_classify_error_auth():
    err = MsfRpcError("401 Unauthorized authentication failure")
    d = MsfRpcClient.classify_error(err)
    assert d["category"] == "auth_failure"
    assert "MSFRPC_USER" in d["hint"]


def test_classify_error_timeout():
    err = MsfRpcError("timed out waiting for response")
    d = MsfRpcClient.classify_error(err)
    assert d["category"] == "timeout"


def test_classify_error_refused():
    err = MsfRpcError("Connection refused")
    d = MsfRpcClient.classify_error(err)
    assert d["category"] == "connection_refused"


def test_bridge_probe_success():
    bridge = RpcSessionBridge(MockRpcClient())
    ok = run(bridge.probe())
    assert ok
    assert bridge.rpc_available


def test_bridge_probe_fail_auth():
    bridge = RpcSessionBridge(MockRpcClient(fail_auth=True))
    ok = run(bridge.probe())
    assert not ok
    assert not bridge.rpc_available
    err = bridge.error_summary()
    assert err is not None
    assert err["category"] == "auth_failure"


def test_bridge_probe_fail_connect():
    bridge = RpcSessionBridge(MockRpcClient(fail_connect=True))
    run(bridge.probe())
    err = bridge.error_summary()
    assert err["category"] == "connection_refused"


def test_bridge_get_sessions_for_ui():
    client = MockRpcClient(sessions={
        "2": {"type": "shell", "tunnel_peer": "10.0.0.9:5555", "via_exploit": "manual"},
    })
    bridge = RpcSessionBridge(client)
    run(bridge.probe())
    sessions = run(bridge.get_sessions_for_ui())
    assert len(sessions) == 1
    assert sessions[0]["type"] == "shell"


def test_bridge_no_rpc_returns_empty():
    bridge = RpcSessionBridge(None)
    sessions = run(bridge.get_sessions_for_ui())
    assert sessions == []


def test_bridge_close_session():
    client = MockRpcClient(sessions={"3": {"type": "meterpreter"}})
    bridge = RpcSessionBridge(client)
    run(bridge.probe())
    ok = run(bridge.close_session(3))
    assert ok


def test_restore_session_metadata():
    client = MockRpcClient(sessions={
        "1": {"type": "meterpreter", "tunnel_peer": "10.0.0.5:4444"},
    })
    bridge = RpcSessionBridge(client)
    run(bridge.probe())
    meta = run(bridge.restore_session_metadata())
    assert len(meta) == 1
    assert meta[0]["target_host"] == "10.0.0.5"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS  {name}")
    print("All msf_rpc mock tests passed.")
