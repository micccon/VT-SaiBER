from __future__ import annotations

import asyncio
import inspect


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "live: tests that require live LLM, MCP, Docker, or networked services",
    )
    config.addinivalue_line(
        "markers",
        "asyncio: async tests run by the local asyncio pytest hook",
    )


def pytest_pyfunc_call(pyfuncitem):
    if not inspect.iscoroutinefunction(pyfuncitem.obj):
        return None

    kwargs = {
        name: pyfuncitem.funcargs[name]
        for name in pyfuncitem._fixtureinfo.argnames
    }
    asyncio.run(pyfuncitem.obj(**kwargs))
    return True
