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
- V2 production tracing: `src/v2/observability/` emits opt-in, redacted log summaries for execution and chat/synthesis runs.

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
Run one live agent directly:

```bash
bash tests/v2_live/run_supervisor_live.sh
bash tests/v2_live/run_librarian_live.sh
bash tests/v2_live/run_scout_live.sh
bash tests/v2_live/run_fuzzer_live.sh
bash tests/v2_live/run_striker_live.sh
bash tests/v2_live/run_resident_live.sh
```

Run non-live promotion tests:

```bash
bash tests/v2_non_live/run_v2_non_live.sh
```

Each live runner streams v2 trace logs by default with `V2_TRACE_ENABLED=true` and `V2_TRACE_INCLUDE_RAW=false`, so successful tests should show redacted agent outcomes, tool calls, approvals, and artifact counts.

`resident_v2` auto-detects an existing Metasploit session and skips cleanly if none exists.

Run the app through the full v2 graph:

```bash
docker exec -t \
  -e SAIBER_GRAPH_VERSION=v2 \
  -e V2_TRACE_ENABLED=true \
  -e OPENROUTER_API_KEY="$OPENROUTER_API_KEY" \
  -e OPENROUTER_MODEL="$OPENROUTER_MODEL" \
  vt-saiber-agents sh -lc \
  'cd /app && python3 -m src.main --mission-goal "..." --target-scope "..."'
```

Enable v2 tracing in Docker logs:

```bash
V2_TRACE_ENABLED=true
V2_TRACE_INCLUDE_RAW=false
V2_TRACE_MAX_CHARS=2000
```

`V2_TRACE_INCLUDE_RAW=false` is the safe default. It logs structured outcomes, tool names, tool statuses, approval events, and artifact counts while redacting sensitive keys and hiding raw SDK/model payloads.

If you run pytest directly instead of the shell script, add log streaming flags:

```bash
V2_TRACE_ENABLED=true V2_TRACE_INCLUDE_RAW=false \
python3 -m pytest tests/v2_live/test_fuzzer_live.py -q --log-cli-level=INFO
```

Run the focused v2 unit slice:

```bash
docker exec -t vt-saiber-agents sh -lc 'cd /app && python3 -m pytest tests/agent_tests/test_supervisor_v2.py tests/agent_tests/test_v2_router.py tests/agent_tests/test_v2_graph.py tests/agent_tests/test_v2_chat_synthesis.py tests/agent_tests/test_librarian_v2.py tests/agent_tests/test_v2_agent_helpers.py tests/agent_tests/test_v2_execution_framework.py tests/agent_tests/test_scout_v2.py tests/agent_tests/test_fuzzer_v2.py tests/agent_tests/test_striker_v2.py tests/agent_tests/test_resident_v2.py -q'
```

## Replacement Checklist
- Pass `tests/v2_non_live` locally and in the VM.
- Pass `tests/v2_live` in the VM with `OPENROUTER_API_KEY` and `OPENROUTER_MODEL`.
- Pass MCP-backed live agent tests with Docker MCP servers reachable.
- Pass resident live test with an intentionally seeded session fixture.
- Use `V2_TRACE_ENABLED=true` during VM validation to inspect tool calls, approval blocks, and structured agent outcomes.
- Verify rollback by switching `SAIBER_GRAPH_VERSION` back to `legacy`.
- Extract librarian retrieval helpers out of old `LibrarianAgent`.
- Add captured/live coverage for MCP-backed specialist agents.
- Promote v2 names to regular names after validation: `supervisor_v2` becomes `supervisor`, `scout_v2` becomes `scout`, etc.
- Only after stable promoted runs should legacy graph, router, agents, tool loop, and MCP bridge be removed.
