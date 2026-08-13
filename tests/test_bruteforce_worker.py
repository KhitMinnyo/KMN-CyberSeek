"""Tests for the decoupled brute-force worker (core/bruteforce_worker.py) — M5.
The real attack invocation is injected, so the queue/tiering/producer contract is
verified without running hydra. Async driven via asyncio.run()."""

import asyncio
from unittest.mock import AsyncMock

from core.bruteforce_worker import BruteforceWorker


def _run(coro):
    return asyncio.run(coro)


def test_supported_services():
    w = BruteforceWorker(on_credential=lambda c: None)
    assert w.supported("ssh")
    assert w.supported("microsoft-ds")   # -> smb
    assert w.supported("ms-wbt-server")  # -> rdp
    assert not w.supported("http")       # not an auth-brute target here


def test_hit_is_produced_to_callback():
    async def scenario():
        produced = []
        runner = AsyncMock(return_value=[{"username": "root", "secret": "toor",
                                          "service": "ssh", "host": "10.0.0.5", "port": 22}])
        w = BruteforceWorker(on_credential=lambda c: produced.append(c),
                             attack_runner=runner)
        key = w.submit("ssh", "10.0.0.5", 22)
        assert key == "ssh:10.0.0.5:22"
        # let the spawned task run
        await asyncio.sleep(0.05)
        assert produced and produced[0]["username"] == "root"
        assert w.jobs[key]["status"] == "done"
        assert w.jobs[key]["creds_found"] == 1
    _run(scenario())


def test_submit_is_idempotent_and_scope_gated():
    async def scenario():
        runner = AsyncMock(return_value=[])
        w = BruteforceWorker(on_credential=lambda c: None, attack_runner=runner,
                             in_scope=lambda host: host == "10.0.0.5")
        k1 = w.submit("ssh", "10.0.0.5", 22)
        k2 = w.submit("ssh", "10.0.0.5", 22)   # duplicate
        assert k1 == k2 and len(w.jobs) == 1
        # out of scope → rejected
        assert w.submit("ssh", "8.8.8.8", 22) is None
        await asyncio.sleep(0.02)
    _run(scenario())


def test_unsupported_service_rejected():
    w = BruteforceWorker(on_credential=lambda c: None, attack_runner=AsyncMock(return_value=[]))
    assert w.submit("http", "10.0.0.5", 80) is None


def test_parse_hits_hydra_and_nxc():
    hydra = "[22][ssh] host: 10.0.0.5   login: backup   password: 123456"
    hits = BruteforceWorker._parse_hits(hydra, "ssh", "10.0.0.5", 22)
    assert hits and hits[0]["username"] == "backup" and hits[0]["secret"] == "123456"

    nxc = "SMB  10.0.0.5  445  [+] WORKGROUP\\admin:P@ssw0rd!"
    hits2 = BruteforceWorker._parse_hits(nxc, "smb", "10.0.0.5", 445)
    assert hits2 and hits2[0]["username"] == "admin"
