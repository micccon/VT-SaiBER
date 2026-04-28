"""Deprecated live-test shim kept only to avoid stale imports during collection."""

from __future__ import annotations

import pytest


pytestmark = [
    pytest.mark.live,
    pytest.mark.skip(reason="Deprecated: use tests/agent_tests/test_live_striker.py"),
]


def test_striker_automotive_live_deprecated() -> None:
    pytest.skip("Deprecated: use tests/agent_tests/test_live_striker.py")
