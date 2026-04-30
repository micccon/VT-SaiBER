# VT-SaiBER Architecture Handoff

## Current State
The Agents SDK architecture has been promoted into the regular source tree. The legacy graph selector is removed: `src.graph.builder.build_graph()` now builds the supervisor-led production graph directly.

## Architecture
- Runtime namespace: `src/runtime/` owns the promoted runtime surface.
- Execution lane: `src/runtime/execution.py` runs tool-using specialist agents through the OpenAI Agents SDK with direct MCP server access, allowlists, approvals, and telemetry.
- Chat/synthesis lane: `src/runtime/chat.py` runs non-tool agents such as supervisor and librarian with structured outputs.
- Shared contracts: `src/runtime/contracts.py` owns typed execution and chat result models.
- Observability: `src/runtime/tracing.py` emits opt-in redacted trace logs using `SAIBER_TRACE_*` env vars.
- Agents: `src/agents/{supervisor,scout,fuzzer,librarian,striker,resident}/` are the promoted implementations. Public entrypoint is `run(state)` plus one LangGraph node wrapper per agent.
- State: `CyberState` remains the canonical mission-state contract.

## Runtime
Production graph:

```text
supervisor -> scout/fuzzer/librarian/striker/resident -> supervisor -> ... -> END
```

There are no per-agent production graphs. Individual agents should be tested by calling `agent.run(state)` directly.

## Tests
- Non-live promotion tests: `tests/non_live/`
- Live opt-in tests: `tests/live/`
- Focused unit tests: `tests/agent_tests/`

Useful commands inside the agents container:

```bash
python3 -m pytest tests/agent_tests tests/non_live -q
bash tests/live/run_supervisor_live.sh
bash tests/live/run_librarian_live.sh
bash tests/live/run_scout_live.sh
bash tests/live/run_fuzzer_live.sh
bash tests/live/run_striker_live.sh
bash tests/live/run_resident_live.sh
bash tests/live/run_full_graph_live.sh
```

Enable tracing:

```bash
SAIBER_TRACE_ENABLED=true
SAIBER_TRACE_INCLUDE_RAW=false
SAIBER_TRACE_MAX_CHARS=4000
```

## Removed Legacy Paths
The old `BaseAgent` runtime, old tool loop, old MCP bridge, old skills prompt system, and legacy agent modules have been removed or replaced by the promoted architecture.

## Remaining Follow-Up
- Run full non-live tests in `vt-saiber-agents`.
- Run selected live tests in the VM with OpenRouter and Docker MCP services.
- Keep improving agent behavior from live output, but do not reintroduce the old tool loop or skills layer.
