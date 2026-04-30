# V2 Promotion Prep with Separate Non-Live and Live Tests

## Summary
Prepare v2 for VM validation by adding a controlled v2 graph entrypoint, splitting promotion tests into non-live and live folders, and writing a handoff markdown file for a new chat.

Legacy remains the default path until v2 passes non-live and selected live validation.

## Implemented Plan
- Add `RuntimeConfig.graph_version`.
- Add `SAIBER_GRAPH_VERSION=legacy|v2`.
- Keep default graph version as `legacy`.
- Add `src.main.build_runtime_graph()`:
  - `legacy` uses `src.graph.builder.build_graph`.
  - `v2` uses `src.v2.graph.builder.build_supervisor_v2_graph`.
  - invalid values raise a clear `ValueError`.
- Do not add a CLI flag.
- Do not delete or replace the legacy graph.

## Test Layout
- `tests/v2_non_live/`: fake/monkeypatched tests only. These must not call OpenRouter or MCP.
- `tests/v2_live/`: opt-in tests that run live OpenRouter-backed v2 agents. MCP graph smoke tests require a second opt-in.
- `tests/agent_tests/`: existing focused v2 unit tests remain in place.
- Production v2 tracing is available through `V2_TRACE_ENABLED=true`, with raw payloads hidden unless `V2_TRACE_INCLUDE_RAW=true`.

## Test Commands
Non-live:

```bash
bash tests/v2_non_live/run_v2_non_live.sh
```

Live OpenRouter:

```bash
RUN_V2_LIVE_TESTS=1 bash tests/v2_live/run_v2_live.sh
```

The live runner now streams redacted v2 trace logs by default. For direct pytest runs, use `--log-cli-level=INFO`.

Live OpenRouter plus MCP-backed agent tests:

```bash
RUN_V2_LIVE_TESTS=1 RUN_V2_LIVE_MCP_TESTS=1 bash tests/v2_live/run_v2_live.sh
```

Resident seeded-session live validation:

```bash
RUN_V2_LIVE_TESTS=1 RUN_V2_LIVE_MCP_TESTS=1 LIVE_RESIDENT_SESSION_ID=1 LIVE_RESIDENT_TARGET=10.0.0.5 bash tests/v2_live/run_v2_live.sh
```

Striker approved execution validation:

```bash
RUN_V2_LIVE_TESTS=1 RUN_V2_LIVE_MCP_TESTS=1 LIVE_STRIKER_EXECUTE=true bash tests/v2_live/run_v2_live.sh
```

Focused v2 unit slice:

```bash
docker exec -t vt-saiber-agents sh -lc 'cd /app && python3 -m pytest tests/agent_tests/test_supervisor_v2.py tests/agent_tests/test_v2_router.py tests/agent_tests/test_v2_graph.py tests/agent_tests/test_v2_chat_synthesis.py tests/agent_tests/test_librarian_v2.py tests/agent_tests/test_v2_agent_helpers.py tests/agent_tests/test_v2_execution_framework.py tests/agent_tests/test_scout_v2.py tests/agent_tests/test_fuzzer_v2.py tests/agent_tests/test_striker_v2.py tests/agent_tests/test_resident_v2.py -q'
```

V2 trace-enabled app run:

```bash
SAIBER_GRAPH_VERSION=v2 V2_TRACE_ENABLED=true V2_TRACE_INCLUDE_RAW=false python -m src.main --mission-goal "..." --target-scope "..."
```

## VM Handoff
Use `docs/V2_HANDOFF.md` as the catch-up document for a new chat or VM validation session.

## Remaining Before Legacy Replacement
- Run non-live promotion tests.
- Run one live test per v2 agent in the VM.
- Verify direct SDK MCP path against Docker MCP servers.
- Validate v2 tool/output logs with `V2_TRACE_ENABLED=true`.
- Verify rollback with `SAIBER_GRAPH_VERSION=legacy`.
- Extract librarian retrieval helpers away from old `LibrarianAgent`.
- Promote v2 modules and node names to regular names after validation.
- Reorganize tests so v2 tests become the normal agent tests.
- Remove legacy graph/router/agents/runtime only after promoted names are stable.
