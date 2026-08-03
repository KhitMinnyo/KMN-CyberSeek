#!/usr/bin/env python3
"""Dependency-free test runner for environments without pytest.

Discovers every `test_*` function in the `tests/test_*.py` modules and runs them,
reporting pass/fail counts. Use `pytest tests/` when pytest is installed — this
runner exists so the suite is verifiable in a minimal environment too.

    python3 tests/run_tests.py
"""

import importlib
import os
import sys
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

# Apply the same optional-dependency stubs + sys.path setup pytest would via conftest.
import tests.conftest  # noqa: F401,E402


def main() -> int:
    modules = sorted(
        f[:-3] for f in os.listdir(_HERE)
        if f.startswith("test_") and f.endswith(".py")
    )
    passed = failed = 0
    failures = []

    for modname in modules:
        mod = importlib.import_module(f"tests.{modname}")
        for name in sorted(dir(mod)):
            if not name.startswith("test_"):
                continue
            fn = getattr(mod, name)
            if not callable(fn):
                continue
            try:
                fn()
                passed += 1
                print(f"  PASS  {modname}.{name}")
            except Exception as e:  # noqa: BLE001
                failed += 1
                failures.append((modname, name, e, traceback.format_exc()))
                print(f"  FAIL  {modname}.{name}: {e}")

    print(f"\n{'=' * 60}\n{passed} passed, {failed} failed")
    if failures:
        print(f"{'=' * 60}\nFAILURE DETAIL:")
        for modname, name, _e, tb in failures:
            print(f"\n--- {modname}.{name} ---\n{tb}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
