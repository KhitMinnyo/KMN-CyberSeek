"""Tests for reverse-shell callback resolution (core/callback.py).

Covers private/public classification and the env-driven resolution modes that do
not require network I/O (local / manual / auto->local). ngrok and public-IP
modes hit the network and are exercised manually, not here.
"""

import os

from core import callback as cb


def _clear_env(monkeypatch):
    for k in ("CALLBACK_MODE", "EXPLOIT_LHOST", "EXPLOIT_LPORT", "NGROK_AUTHTOKEN"):
        monkeypatch.delenv(k, raising=False)


def test_is_private_ip():
    assert cb.is_private_ip("192.168.1.10") is True
    assert cb.is_private_ip("10.0.0.5") is True
    assert cb.is_private_ip("172.16.4.4") is True
    assert cb.is_private_ip("127.0.0.1") is True
    assert cb.is_private_ip("8.8.8.8") is False
    assert cb.is_private_ip("example.com") is False   # hostname -> treated public
    assert cb.is_private_ip("") is False


def test_manual_mode_uses_explicit_lhost(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("CALLBACK_MODE", "manual")
    monkeypatch.setenv("EXPLOIT_LHOST", "203.0.113.9")
    monkeypatch.setenv("EXPLOIT_LPORT", "4444")
    c = cb.resolve_callback("45.33.32.156")
    assert c.mode == "manual"
    assert c.advertised_host == "203.0.113.9"
    assert c.advertised_port == 4444
    assert (c.bind_host, c.bind_port) == ("127.0.0.1", 4444)
    assert c.needs_bind_override is True   # tunnel: bind local, advertise public
    assert c.reachable is True


def test_auto_with_explicit_lhost_is_manual(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_LHOST", "198.51.100.7")   # CALLBACK_MODE defaults to auto
    c = cb.resolve_callback("8.8.8.8")
    assert c.mode == "manual"
    assert c.advertised_host == "198.51.100.7"


def test_local_mode_advertises_and_binds_same(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("CALLBACK_MODE", "local")
    c = cb.resolve_callback("192.168.1.50")   # LAN target
    assert c.mode == "local"
    assert c.advertised_host == c.bind_host
    assert c.advertised_port == c.bind_port
    assert c.needs_bind_override is False
    assert c.reachable is True   # same-network target


def test_auto_private_target_resolves_local(monkeypatch):
    _clear_env(monkeypatch)
    # No EXPLOIT_LHOST, private target -> auto should pick 'local' with no network.
    c = cb.resolve_callback("192.168.56.101")
    assert c.mode == "local"
    assert c.reachable is True


def test_default_lport_from_env(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("CALLBACK_MODE", "local")
    monkeypatch.setenv("EXPLOIT_LPORT", "9001")
    c = cb.resolve_callback("10.10.10.10")
    assert c.advertised_port == 9001
