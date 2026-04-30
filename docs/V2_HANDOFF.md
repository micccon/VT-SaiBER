# VT-SaiBER V2 Handoff

## Current State
The repo now has a parallel v2 architecture beside the legacy runtime. Legacy remains the default production path. V2 is selectable with:

```bash
SAIBER_GRAPH_VERSION=v2
```

The CLI command shape does not change. `SAIBER_GRAPH_VERSION=legacy` or an unset value keeps using the old graph.

## What Was Built
- V2 execution lane: `src/v2/execution/` wraps OpenAI Agents SDK style execution, direct MCP server access, tool allowlists, approval telemetry, and structured outcomes.
- V2 chat/synthesis lane: `src/v2/chat/` runs structured non-tool agents such as librarian and supervisor.
- V2 agents: `scout_v2`, `fuzzer_v2`, `librarian_v2`, `striker_v2`, `resident_v2`, and `supervisor_v2`.
- V2 graph: `build_supervisor_v2_graph()` runs `supervisor_v2` as the entrypoint and routes only to v2 node names.
- V2 router: `src/v2/graph/router.py` validates v2-only routing and applies hard graph safety checks.
- Runtime graph selector: `src.main.build_runtime_graph()` chooses legacy or v2 from `RuntimeConfig.graph_version`.

## What Still Uses Legacy
- Legacy is still the default graph.
- `src/agents/*` and `BaseAgent` remain in place for the old graph.
- The old tool loop and old MCP bridge remain for legacy agents.
- `librarian_v2` still reuses retrieval helpers from the old `LibrarianAgent`; these should move to a neutral retrieval service before deleting the old librarian.
- `src/agents/striker_v2.py` is a compatibility shim to the new `src/v2/agents/striker` package.

## Test Layout
- `tests/agent_tests/`: focused unit-style tests for v2 agents, runners, and graph pieces.
- `tests/v2_non_live/`: promotion tests with no real OpenRouter calls and no real MCP calls.
- `tests/v2_live/`: opt-in live tests that run real OpenRouter-backed v2 agents, with MCP-backed graph smoke tests behind an extra MCP opt-in.

## VM Commands
Run non-live promotion tests:

```bash
python -m pytest tests/v2_non_live -q
```

Run live OpenRouter tests:

```bash
RUN_V2_LIVE_TESTS=1 python -m pytest tests/v2_live -q
```

Run live OpenRouter plus MCP graph smoke tests:

```bash
RUN_V2_LIVE_TESTS=1 RUN_V2_LIVE_MCP_TESTS=1 python -m pytest tests/v2_live -q
```

Run the app through the full v2 graph:

```bash
SAIBER_GRAPH_VERSION=v2 python -m src.main --mission-goal "..." --target-scope "..."
```

Run the focused v2 unit slice:

```bash
python -m pytest tests/agent_tests/test_supervisor_v2.py tests/agent_tests/test_v2_router.py tests/agent_tests/test_v2_graph.py tests/agent_tests/test_v2_chat_synthesis.py tests/agent_tests/test_librarian_v2.py tests/agent_tests/test_v2_agent_helpers.py tests/agent_tests/test_v2_execution_framework.py tests/agent_tests/test_scout_v2.py tests/agent_tests/test_fuzzer_v2.py tests/agent_tests/test_striker_v2.py tests/agent_tests/test_resident_v2.py -q
```

## Replacement Checklist
- Pass `tests/v2_non_live` locally and in the VM.
- Pass selected `tests/v2_live` in the VM with `OPENROUTER_API_KEY`.
- Pass MCP-backed live graph smoke tests with Docker MCP servers reachable.
- Verify rollback by switching `SAIBER_GRAPH_VERSION` back to `legacy`.
- Extract librarian retrieval helpers out of old `LibrarianAgent`.
- Add captured/live coverage for MCP-backed specialist agents.
- Only after stable v2 runs should legacy graph, router, agents, tool loop, and MCP bridge be removed.
