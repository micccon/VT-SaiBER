from __future__ import annotations

import asyncio
from types import SimpleNamespace

import src.mcp.metasploit_rpc as metasploit_rpc


def _run(coro):
    return asyncio.run(coro)


def test_get_module_options_normalizes_bool_shapes(monkeypatch):
    fake_module = SimpleNamespace(
        fullname="exploit/multi/http/werkzeug_debug_rce",
        options=["RHOSTS", "RPORT", "SSL"],
        optioninfo=True,
        required=True,
        missing_required=False,
    )

    async def fake_get_module_object(module_type: str, module_name: str):
        assert module_type == "exploit"
        assert module_name == "multi/http/werkzeug_debug_rce"
        return fake_module

    monkeypatch.setattr(metasploit_rpc, "_get_module_object", fake_get_module_object)

    result = _run(
        metasploit_rpc.get_module_options(
            module_type="exploit",
            module_name="multi/http/werkzeug_debug_rce",
        )
    )

    assert result["status"] == "success"
    assert result["module"] == "exploit/multi/http/werkzeug_debug_rce"
    assert result["count"] == 3
    assert result["required_count"] == 0
    assert result["missing_required"] == []


def test_get_module_info_normalizes_targets_payloads_and_required(monkeypatch):
    fake_module = SimpleNamespace(
        fullname="exploit/multi/http/werkzeug_debug_rce",
        name="werkzeug_debug_rce",
        description="Werkzeug debug console RCE",
        rank="excellent",
        disclosure_date="2024-01-01",
        license="MSF_LICENSE",
        platform="python",
        arch=False,
        references=True,
        targets=True,
        target=False,
        payloads=True,
        options=["RHOSTS", "RPORT"],
        optioninfo=False,
        required=True,
    )

    async def fake_get_module_object(module_type: str, module_name: str):
        assert module_type == "exploit"
        assert module_name == "multi/http/werkzeug_debug_rce"
        return fake_module

    monkeypatch.setattr(metasploit_rpc, "_get_module_object", fake_get_module_object)

    result = _run(
        metasploit_rpc.get_module_info(
            module_type="exploit",
            module_name="multi/http/werkzeug_debug_rce",
        )
    )

    assert result["status"] == "success"
    assert result["module"] == "exploit/multi/http/werkzeug_debug_rce"
    assert result["targets"] == []
    assert result["compatible_payloads"] == []
    assert result["required_options"] == []
    assert result["required_count"] == 0


def test_get_module_options_handles_attribute_getter_failures(monkeypatch):
    class ExplosiveModule:
        fullname = "auxiliary/scanner/http/http_version"

        @property
        def options(self):
            return ["RHOSTS"]

        @property
        def optioninfo(self):
            raise TypeError("'bool' object is not subscriptable")

        @property
        def required(self):
            raise TypeError("'bool' object is not subscriptable")

        @property
        def missing_required(self):
            raise TypeError("'bool' object is not subscriptable")

    async def fake_get_module_object(module_type: str, module_name: str):
        assert module_type == "auxiliary"
        assert module_name == "scanner/http/http_version"
        return ExplosiveModule()

    monkeypatch.setattr(metasploit_rpc, "_get_module_object", fake_get_module_object)

    result = _run(
        metasploit_rpc.get_module_options(
            module_type="auxiliary",
            module_name="scanner/http/http_version",
        )
    )

    assert result["status"] == "success"
    assert result["module"] == "auxiliary/scanner/http/http_version"
    assert result["count"] == 1
    assert result["required_count"] == 0


def test_get_module_options_surfaces_raw_backend_error_when_module_object_construction_breaks(monkeypatch):
    async def fake_get_module_object(module_type: str, module_name: str):
        raise TypeError("'bool' object is not subscriptable")

    async def fake_rpc_module_details(module_type: str, module_name: str):
        return {}, {
            "error": True,
            "error_class": "RuntimeError",
            "error_string": "backend exploded while loading module metadata",
        }

    monkeypatch.setattr(metasploit_rpc, "_get_module_object", fake_get_module_object)
    monkeypatch.setattr(metasploit_rpc, "_rpc_module_details", fake_rpc_module_details)

    result = _run(
        metasploit_rpc.get_module_options(
            module_type="auxiliary",
            module_name="scanner/http/http_version",
        )
    )

    assert result["status"] == "error"
    assert "Metasploit backend error retrieving module options" in result["message"]
    assert "RuntimeError: backend exploded while loading module metadata" in result["message"]
