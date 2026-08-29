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
