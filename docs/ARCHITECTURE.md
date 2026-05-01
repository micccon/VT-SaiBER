# Architecture

VT-SaiBER is built around a supervisor-led orchestration graph, shared mission state, a promoted runtime layer, and PostgreSQL-backed persistence/reporting.

## Main Flow

1. `src.main` builds a mission request and initial `CyberState`
2. `src.graph.builder` assembles the workflow
3. the supervisor routes to the next specialist agent
4. agents update shared state through the runtime lanes
5. persistence hooks write best-effort mission data into PostgreSQL
6. reporting exports read persisted mission data

## Agents

- `supervisor`: routing and mission control
- `scout`: reconnaissance and target/service discovery
- `fuzzer`: web testing and web-facing evidence
- `librarian`: KB retrieval, enrichment, and research synthesis
- `striker`: exploit planning and execution paths
- `resident`: session-backed post-exploitation and objective work

## Runtime

The promoted runtime surface lives under `src/runtime/`.

- `src/runtime/chat.py`: tool-less structured synthesis runs
- `src/runtime/execution.py`: tool-using local and MCP execution
- `src/runtime/approval.py`: approval helpers for guarded execution
- `src/runtime/tracing.py`: opt-in redacted tracing
- `src/runtime/contracts.py`: shared runner/result contracts

Chat lane:

- used by supervisor and librarian
- optimized for structured non-tool reasoning

Execution lane:

- used by scout, fuzzer, striker, and resident
- optimized for tool use, MCP access, and policy hooks

## State and Persistence

`CyberState` is the system-wide mission state carried through the graph.

It includes:

- mission metadata
- discovered targets and services
- findings and evidence
- research cache and intelligence findings
- sessions
- agent logs and errors

`src/database/persistence.py` persists mission deltas through isolated handlers for:

- targets and services
- web findings
- intelligence findings
- generic findings
- agent logs
- errors
- sessions

## MCP and Tooling

Execution-lane agents use a unified attackbox MCP surface rather than each agent owning its own tool backend.

Primary endpoint:

```text
ATTACKBOX_MCP_URL=http://attackbox:8080/mcp
```

This centralizes:

- tool discovery
- policy enforcement
- approvals
- result normalization

## Librarian and RAG

The Librarian agent combines:

- KB retrieval from persisted docs
- retrieval from mission findings
- optional CVE and OSINT enrichment
- structured intelligence-brief synthesis

The default KB corpus is loaded from:

```text
src/database/testbed_docs/
```

Important RAG controls include:

- `RAG_KB_TOP_K`
- `RAG_KB_FETCH_K`
- `RAG_FINDINGS_TOP_K`
- `RAG_FINDINGS_FETCH_K`
- `RAG_KB_SIMILARITY_THRESHOLD`
- `RAG_FINDINGS_SIMILARITY_THRESHOLD`
- `RAG_MIN_DOCS`
- `RAG_MIN_SCORE`
- `RAG_MAX_CHUNKS_PER_DOC`
