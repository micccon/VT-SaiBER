from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from src.config import get_runtime_config
from src.main import build_runtime_graph


def _config(**overrides):
    return replace(get_runtime_config(), **overrides)


def test_graph_version_reads_saiber_env(monkeypatch):
    monkeypatch.setenv("SAIBER_GRAPH_VERSION", "v2")
    get_runtime_config.cache_clear()
    try:
        assert get_runtime_config().graph_version == "v2"
    finally:
        get_runtime_config.cache_clear()


def test_graph_selection_defaults_to_legacy(monkeypatch):
    captured: dict[str, object] = {}

    def fake_build_graph(*, checkpointer=None):
        captured["legacy"] = checkpointer
        return SimpleNamespace(name="legacy")

    monkeypatch.setattr("src.main.build_graph", fake_build_graph)

    graph = build_runtime_graph(_config(graph_version="legacy"), checkpointer="cp")

    assert graph.name == "legacy"
    assert captured["legacy"] == "cp"


def test_graph_selection_uses_v2_when_configured(monkeypatch):
    captured: dict[str, object] = {}

    def fake_build_supervisor_v2_graph(*, checkpointer=None):
        captured["v2"] = checkpointer
        return SimpleNamespace(name="v2")

    import src.v2.graph as graph_mod

    monkeypatch.setattr(graph_mod, "build_supervisor_v2_graph", fake_build_supervisor_v2_graph)

    graph = build_runtime_graph(_config(graph_version="v2"), checkpointer="cp")

    assert graph.name == "v2"
    assert captured["v2"] == "cp"


def test_graph_selection_rejects_invalid_version():
    with pytest.raises(ValueError, match="Unsupported SAIBER_GRAPH_VERSION"):
        build_runtime_graph(_config(graph_version="experimental"))
