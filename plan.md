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

## Test Commands
Non-live:

```bash
bash tests/v2_non_live/run_v2_non_live.sh
```

Live OpenRouter:

```bash
RUN_V2_LIVE_TESTS=1 bash tests/v2_live/run_v2_live.sh
```

Live OpenRouter plus MCP graph smoke:

```bash
RUN_V2_LIVE_TESTS=1 RUN_V2_LIVE_MCP_TESTS=1 bash tests/v2_live/run_v2_live.sh
```

Focused v2 unit slice:

```bash
docker exec -t vt-saiber-agents sh -lc 'cd /app && python3 -m pytest tests/agent_tests/test_supervisor_v2.py tests/agent_tests/test_v2_router.py tests/agent_tests/test_v2_graph.py tests/agent_tests/test_v2_chat_synthesis.py tests/agent_tests/test_librarian_v2.py tests/agent_tests/test_v2_agent_helpers.py tests/agent_tests/test_v2_execution_framework.py tests/agent_tests/test_scout_v2.py tests/agent_tests/test_fuzzer_v2.py tests/agent_tests/test_striker_v2.py tests/agent_tests/test_resident_v2.py -q'
```

## VM Handoff
Use `docs/V2_HANDOFF.md` as the catch-up document for a new chat or VM validation session.

## Remaining Before Legacy Replacement
- Run non-live promotion tests.
- Run selected live tests in the VM.
- Verify direct SDK MCP path against Docker MCP servers.
- Verify rollback with `SAIBER_GRAPH_VERSION=legacy`.
- Extract librarian retrieval helpers away from old `LibrarianAgent`.
- Add captured/live coverage for MCP-backed specialists.
- Remove legacy graph/router/agents/runtime only after v2 is stable.
