# VT-SaiBER Architecture

VT-SaiBER is a LangGraph-orchestrated, multi-agent security validation system. The promoted architecture uses two runtime lanes: an Agents SDK execution lane for tool-using specialists and a chat/synthesis lane for routing and research agents.

## Production Graph
`src/graph/builder.py` builds one supervisor-led graph:

```text
supervisor -> scout/fuzzer/librarian/striker/resident -> supervisor -> ... -> END
```

`src/graph/router.py` enforces hard safety checks before dispatching a specialist.

## Agents
Agents live under package directories in `src/agents/`:
- `supervisor`: structured route decisions, no tools
- `scout`: reconnaissance and service discovery
- `fuzzer`: web surface enumeration
- `librarian`: database/RAG retrieval plus structured synthesis, no tools
- `striker`: exploitation planning and approved exploit attempts
- `resident`: live-session objective execution

Each agent exposes `run(state: CyberState) -> dict[str, Any]` and a LangGraph node wrapper.

## Runtime Lanes
- `src/execution/`: OpenAI Agents SDK orchestration, direct MCP wiring, allowlists, approval telemetry, and structured tool outcomes
- `src/chat/`: structured non-tool chat/synthesis runner
- `src/contracts/`: typed execution/chat contracts
- `src/core/`: neutral shared helpers for parsing, validation, approval, logging, and OpenRouter client setup
- `src/observability/`: opt-in redacted tracing

## State and Persistence
`CyberState` remains the canonical mission state. Agents return LangGraph state deltas, and node wrappers persist updates through the existing database persistence layer.

## MCP
The Docker attackbox MCP server remains the tooling backend. Agents connect directly through the execution runner; there is no separate MCP bridge layer.