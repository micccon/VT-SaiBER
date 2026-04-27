# VT-SaiBER Architecture (Current)

This document reflects the current unified `attackbox` architecture and LangGraph orchestration model in `VT-SaiBER`.

## 1. High-Level Overview

VT-SaiBER is a multi-agent penetration testing system with a single execution boundary.

Primary runtime containers:
- `agents`: LangGraph workflow, prompts, orchestration, skills, and persistence logic
- `attackbox`: Kali-based execution plane with offensive tooling, Metasploit, and one MCP server
- `postgres`: mission/state persistence

Core design principles:
- The `supervisor` is the sole orchestration and routing agent.
- `supervisor` decides which specialist agent runs next based on mission state and progress.
- `supervisor` has no offensive tool access.
- Executable workers receive least-privilege attackbox tools through a shared MCP client and worker harness.

## 2. Runtime Topology

Source of truth:
- `docker-compose.yml`
- `docker/agents.Dockerfile`
- `docker/attackbox.Dockerfile`

Container responsibilities:
- `agents`
  - Runs LangGraph nodes and agent code in `src/agents/`
  - Connects only to `ATTACKBOX_MCP_URL` using `src/mcp/mcp_tool_bridge.py`
- `attackbox`
  - Runs a unified MCP server on `8080`
  - Hosts Metasploit RPC on `55553`
  - Executes recon, web, access, and Metasploit workflows locally
- `postgres`
  - Persists mission state, findings, sessions, artifacts, and knowledge records

Environment variable:
- `ATTACKBOX_MCP_URL` (example: `http://attackbox:8080/mcp`)

## 3. Orchestration Model

Key files:
- `src/graph/builder.py`
- `src/graph/router.py`
- `src/agents/supervisor.py`
- `src/state/cyber_state.py`

Execution pattern:
1. Graph enters `supervisor`
2. `supervisor` selects `next_agent`
3. Router enforces safety checks
4. Selected specialist runs
5. Specialist returns state updates
6. Control returns to `supervisor`

Retained specialist topology:
- `supervisor`
- `scout`
- `fuzzer`
- `librarian`
- `striker`
- `resident`

`supervisor` and `librarian` are non-executing.

## 4. MCP Integration Model

Key files:
- `src/mcp/mcp_tool_bridge.py`
- `src/mcp/attackbox_server.py`
- `src/agents/worker_harness.py`

Current behavior:
1. Bridge connects to the unified attackbox server over Streamable HTTP
2. Bridge calls `list_tools()`
3. Bridge converts discovered MCP tools into LangChain `StructuredTool`s
4. Worker harness filters tools by exact allowlist per agent
5. Workers invoke tools and normalize results into consistent envelopes

There is no split `kali-mcp` / `msf-mcp` runtime and no prefix synthesis layer.

## 5. Worker Responsibilities

- `scout`
  - Reconnaissance and service discovery
  - Uses recon-safe attackbox tools
- `fuzzer`
  - Surface enumeration and low-risk web probing
- `librarian`
  - Research and exploit-path synthesis
  - No offensive tool access
- `striker`
  - Exploitation workflows, Metasploit execution, web exploit validation, and credential-driven access
- `resident`
  - Post-exploitation using live sessions and post modules

## 6. Shared State Model

`CyberState` remains the cross-agent contract and now includes broader generic evidence categories such as:
- discovered services
- web findings
- credential findings
- exploit attempts
- active sessions
- protocol observations
- fuzzing runs
- crash indicators
- artifacts
- validations

This keeps state portable across different benchmark or target families.

## 7. Canonical References

For implementation truth, prefer these files first:
- `docker-compose.yml`
- `src/mcp/attackbox_server.py`
- `src/mcp/mcp_tool_bridge.py`
- `src/agents/worker_harness.py`
- `src/agents/supervisor.py`
- `src/agents/scout.py`
- `src/agents/fuzzer.py`
- `src/agents/striker.py`
- `src/agents/resident.py`
