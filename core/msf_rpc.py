"""Optional Metasploit MessagePack RPC client.

The console-based handler remains the default because many Kali installs do
not run ``msgrpc``. When ``MSFRPC_URL`` is configured, this client provides a
session-aware transport that does not depend on parsing a shared console.
It is deliberately dependency-lazy: importing KMN-CyberSeek still works when
the optional ``msgpack`` package is not installed.
"""

import os
from typing import Any, Dict, Optional


class MsfRpcError(RuntimeError):
    pass


class MsfRpcClient:
    def __init__(self, url: str, username: str = "msf", password: str = "",
                 token: str = "", timeout: float = 15.0, verify: bool = False):
        self.url = (url or "").rstrip("/")
        self.username = username
        self.password = password
        self.token = token
        self.timeout = timeout
        self.verify = verify
        self._client = None

    @classmethod
    def from_env(cls) -> Optional["MsfRpcClient"]:
        url = os.getenv("MSFRPC_URL", "").strip()
        if not url:
            return None
        return cls(
            url,
            username=os.getenv("MSFRPC_USER", "msf"),
            password=os.getenv("MSFRPC_PASSWORD", ""),
            token=os.getenv("MSFRPC_TOKEN", ""),
            timeout=float(os.getenv("MSFRPC_TIMEOUT", "15")),
            verify=os.getenv("MSFRPC_VERIFY_TLS", "false").lower() == "true",
        )

    @staticmethod
    def _msgpack():
        try:
            import msgpack
            return msgpack
        except ImportError as exc:
            raise MsfRpcError(
                "MSFRPC_URL is configured but msgpack is not installed; "
                "install the optional msgpack dependency"
            ) from exc

    async def _call(self, method: str, *args: Any) -> Dict:
        import httpx

        msgpack = self._msgpack()
        params = [method, *args]
        if self.token and method != "auth.login":
            params = [method, self.token, *args]
        async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify) as client:
            response = await client.post(
                self.url,
                content=msgpack.packb(params, use_bin_type=True),
                headers={"Content-Type": "application/x-msgpack"},
            )
        if response.status_code >= 400:
            raise MsfRpcError(f"MSFRPC HTTP {response.status_code}")
        result = msgpack.unpackb(response.content, raw=False)
        if isinstance(result, dict) and result.get("error"):
            raise MsfRpcError(str(result.get("error_message") or result["error"]))
        if not isinstance(result, dict):
            raise MsfRpcError("Invalid MSFRPC response")
        return result

    async def connect(self) -> Dict:
        """Authenticate if needed and return the auth response."""
        if self.token:
            return {"result": "success", "token": self.token}
        if not self.username or not self.password:
            raise MsfRpcError("MSFRPC_USER/MSFRPC_PASSWORD or MSFRPC_TOKEN is required")
        result = await self._call("auth.login", self.username, self.password)
        self.token = str(result.get("token") or "")
        if not self.token:
            raise MsfRpcError("MSFRPC authentication returned no token")
        return result

    async def list_sessions(self) -> Dict:
        await self.connect()
        return await self._call("session.list")

    async def run_session_command(self, session_id: int, command: str) -> Dict:
        """Run one command through the RPC session API."""
        await self.connect()
        sid = int(session_id)
        # Meterpreter sessions support meterpreter_run_single. Plain command
        # shells use shell_write/shell_read and are exposed separately because
        # their read completion semantics differ.
        return await self._call("session.meterpreter_run_single", sid, command)

    async def write_shell(self, session_id: int, command: str) -> Dict:
        await self.connect()
        return await self._call("session.shell_write", int(session_id), command + "\n")

    async def read_shell(self, session_id: int) -> Dict:
        await self.connect()
        return await self._call("session.shell_read", int(session_id))

    async def run_console_command(self, console_id: int, command: str) -> Dict:
        await self.connect()
        return await self._call("console.write", int(console_id), command + "\n")


    async def stop_job(self, job_id: int) -> Dict:
        await self.connect()
        return await self._call("job.stop", int(job_id))

    async def list_jobs(self) -> Dict:
        await self.connect()
        return await self._call("job.list")

    async def stop_session(self, session_id: int) -> Dict:
        await self.connect()
        return await self._call("session.stop", int(session_id))

    async def run_meterpreter(self, session_id: int, command: str,
                               timeout: float = 30.0) -> str:
        import asyncio, time as _t
        await self.connect()
        sid = int(session_id)
        await self._call("session.meterpreter_run_single", sid, command)
        deadline = _t.monotonic() + timeout
        collected = []
        while _t.monotonic() < deadline:
            try:
                r = await self._call("session.meterpreter_read", sid)
                data = (r.get("data") or "").strip()
                if data:
                    collected.append(data)
                    if data.endswith(">") or "meterpreter >" in data:
                        break
            except MsfRpcError:
                break
            await asyncio.sleep(0.5)
        return "\n".join(collected)

    async def run_shell_command(self, session_id: int, command: str,
                                 timeout: float = 30.0) -> str:
        import asyncio, time as _t
        await self.write_shell(session_id, command)
        deadline = _t.monotonic() + timeout
        collected = []
        while _t.monotonic() < deadline:
            try:
                r = await self.read_shell(session_id)
                data = (r.get("data") or "").strip()
                if data:
                    collected.append(data)
            except MsfRpcError:
                break
            await asyncio.sleep(0.4)
        return "\n".join(collected)

    async def structured_session_list(self) -> list:
        """Return sessions as list of dicts for the Shells tab UI."""
        await self.connect()
        raw = await self._call("session.list")
        sessions = []
        for sid, meta in (raw.items() if isinstance(raw, dict) else []):
            if not isinstance(meta, dict):
                continue
            tunnel = meta.get("tunnel_peer", "") or ""
            target = tunnel.split(":")[0] if tunnel else ""
            sessions.append({
                "id":           sid,
                "type":         meta.get("type", "unknown"),
                "tunnel_local": meta.get("tunnel_local", ""),
                "tunnel_peer":  tunnel,
                "target_host":  target,
                "via_exploit":  meta.get("via_exploit", ""),
                "via_payload":  meta.get("via_payload", ""),
                "info":         meta.get("info", ""),
                "status":       "open",
                "source":       "rpc",
            })
        return sessions

    @staticmethod
    def classify_error(exc: Exception) -> Dict:
        msg = str(exc)
        if "401" in msg or "authentication" in msg.lower():
            return {"category": "auth_failure", "message": msg,
                    "hint": "Check MSFRPC_USER / MSFRPC_PASSWORD / MSFRPC_TOKEN in .env"}
        if "timed out" in msg.lower() or "timeout" in msg.lower():
            return {"category": "timeout", "message": msg,
                    "hint": "Metasploit RPC not responding. Is msgrpc running?"}
        if "refused" in msg.lower() or "connect" in msg.lower():
            return {"category": "connection_refused", "message": msg,
                    "hint": "Cannot reach MSFRPC_URL. "
                            "Start: load msgrpc Pass=yourpassword ServerPort=55553"}
        if "msgpack" in msg.lower():
            return {"category": "missing_dependency", "message": msg,
                    "hint": "pip install msgpack"}
        return {"category": "rpc_error", "message": msg, "hint": msg}


# ── RPC-aware session bridge ───────────────────────────────────────────────────

class RpcSessionBridge:
    """Routes session commands through RPC when available; signals console fallback.

    Priority: RPC first (better meterpreter output capture), console as fallback.
    Never raises — callers always get a (str, bool) result tuple or empty list.
    """

    def __init__(self, rpc: "Optional[MsfRpcClient]" = None):
        self._rpc           = rpc
        self._available     = None   # None=not probed, True=ok, False=unavailable
        self._error_info    = None

    @property
    def rpc_available(self) -> bool:
        return self._available is True

    async def probe(self) -> bool:
        if self._rpc is None:
            self._available = False
            return False
        try:
            await self._rpc.connect()
            self._available = True
            self._error_info = None
            return True
        except Exception as exc:
            self._available = False
            self._error_info = MsfRpcClient.classify_error(exc)
            return False

    def error_summary(self):
        if self._available is False and self._error_info:
            return self._error_info
        return None

    async def run_command(self, session_id: int, command: str,
                          session_type: str = "meterpreter",
                          timeout: float = 30.0):
        """Run via RPC if available; return (output, used_rpc).
        Caller uses console transport when used_rpc is False."""
        if self._available and self._rpc:
            try:
                if session_type == "meterpreter":
                    out = await self._rpc.run_meterpreter(session_id, command, timeout)
                else:
                    out = await self._rpc.run_shell_command(session_id, command, timeout)
                return out, True
            except Exception as exc:
                self._error_info = MsfRpcClient.classify_error(exc)
        return "", False

    async def get_sessions_for_ui(self) -> list:
        if not self._available or not self._rpc:
            return []
        try:
            return await self._rpc.structured_session_list()
        except Exception:
            return []

    async def restore_session_metadata(self) -> list:
        """Recover live session metadata after backend restart."""
        if not self._available or not self._rpc:
            return []
        try:
            return await self._rpc.structured_session_list()
        except Exception:
            return []

    async def close_session(self, session_id: int) -> bool:
        if not self._available or not self._rpc:
            return False
        try:
            await self._rpc.stop_session(session_id)
            return True
        except Exception:
            return False
