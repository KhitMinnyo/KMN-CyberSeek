"""
Shared test configuration for the KMN-CyberSeek suite.

Two jobs:

  1. Make the package importable from the repo root regardless of where pytest
     is invoked from.
  2. Provide lightweight stand-ins for optional heavy third-party dependencies
     (httpx, pydantic, python-nmap, aiohttp, bs4) so the pure-logic units under
     test — the orchestrator's reasoning helpers, validators, memory index — can
     be imported and exercised in a minimal environment (CI, a fresh venv)
     WITHOUT installing the full offensive-security toolchain. When the real
     packages ARE installed they are used unchanged; the stubs only fill gaps.

These stubs never touch the network and never fake security behaviour — they
exist purely to satisfy module-level imports for offline unit testing.
"""

import os
import sys
import types

# --- 1. repo root on sys.path ------------------------------------------------
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# Keep scope unrestricted during tests unless a test sets it explicitly.
os.environ.setdefault("SCOPE_ALLOWLIST", "")


# --- 2. optional-dependency stubs -------------------------------------------
def _ensure(name, builder):
    try:
        __import__(name)
    except Exception:
        sys.modules[name] = builder()


def _httpx():
    m = types.ModuleType("httpx")
    m.RequestError = type("RequestError", (Exception,), {})
    m.AsyncClient = object
    return m


def _pydantic():
    m = types.ModuleType("pydantic")

    def Field(default=None, **kwargs):
        # `...` (Ellipsis) marks a required field in pydantic; for the stub we
        # simply treat it as "no default".
        return None if default is ... else default

    class BaseModel:
        def __init__(self, **data):
            for k, v in data.items():
                setattr(self, k, v)

    m.BaseModel = BaseModel
    m.Field = Field
    return m


def _nmap():
    m = types.ModuleType("nmap")
    m.PortScanner = object
    return m


def _simple(name):
    return lambda: types.ModuleType(name)


_ensure("httpx", _httpx)
_ensure("pydantic", _pydantic)
_ensure("nmap", _nmap)
_ensure("aiohttp", _simple("aiohttp"))
_ensure("bs4", _simple("bs4"))
