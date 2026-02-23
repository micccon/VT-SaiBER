# VT-SaiBER Architecture (Current)

This document reflects the current architecture in the `VT-SaiBER` codebase, including the newer MCP ToolBridge pattern and LangGraph orchestration.

## 0. Architecture Direction

Architecture direction:
- VT-SaiBER is targeting a **full ReAct agent model across all agents**.
- A hybrid long-term model is **not** the goal.
- Embedded/IoT agent is out of active scope.

## 1. High-Level Overview

VT-SaiBER is a multi-container, multi-agent penetration testing system.

Primary runtime containers:
- `agents`: LangGraph workflow + agent logic
- `kali-mcp`: Kali REST API + Kali MCP server
- `msf-mcp`: Metasploit RPC + Metasploit MCP server
- `postgres`: mission/state persistence

Core design principle:
- The **Supervisor** decides which specialist agent to run next.
- Specialist agents update a shared `CyberState`.
- Tool execution is done through MCP servers, discovered dynamically by the bridge.

## 2. Runtime Topology

Source of truth:
- `docker-compose.yml`
- `docker/agents.Dockerfile`
- `docker/kali_mcp.Dockerfile`
- `docker/msf_mcp.Dockerfile`

Container responsibilities:
- `agents`
  - Runs LangGraph nodes and agent code in `src/agents/`
  - Connects to MCP servers using `src/mcp/mcp_tool_bridge.py`
- `kali-mcp`
  - Runs Kali REST server on `5000`
  - Runs MCP server (SSE endpoint) on `5001`
- `msf-mcp`
  - Runs `msfrpcd` on `55553`
  - Runs MCP HTTP/SSE service on `8085`
- `postgres`
  - Shared persistence backend

Environment variables used by bridge:
- `KALI_MCP_URL` (example: `http://kali-mcp:5001`)
- `MSF_MCP_URL` (example: `http://msf-mcp:8085`)

## 3. Orchestration Model (LangGraph)

Key files:
- `src/graph/builder.py`
- `src/graph/router.py`
- `src/state/cyber_state.py`

Execution pattern:
1. Graph enters `supervisor`
2. Supervisor sets `next_agent`
3. Router enforces safety (iteration cap, scope validation, valid node)
4. Selected specialist node runs
5. Specialist returns state updates
6. Control returns to supervisor and repeats

`CyberState` is the shared state contract across nodes.

## 4. MCP Integration Model (Updated)

Key file:
- `src/mcp/mcp_tool_bridge.py`

The system now uses a dynamic MCP bridge rather than a static hardcoded MCP client router.

Current behavior:
1. Bridge opens SSE sessions to MCP servers (`{url}/sse`)
2. Bridge calls `list_tools()` on each server
3. Bridge converts discovered MCP tools into LangChain `StructuredTool`s
4. Bridge prefixes names with server id:
   - `kali_<tool_name>`
   - `msf_<tool_name>`
5. Agents request filtered tools via `get_tools_for_agent(allowed_tools)`

Important detail:
- Allowlists can use either base names (`run_exploit`) or prefixed names (`msf_run_exploit`).

## 5. Agent Pattern Status

Target pattern (non-hybrid):
- **All agents** should run as ReAct-style workers with MCP ToolBridge-backed tool access.

Reference ReAct implementation:
- `src/agents/striker.py`

In Striker, the ReAct loop:
- receives mission context derived from `CyberState`
- selects tools autonomously from MCP allowlist
- executes exploitation attempts
- parses tool messages back into structured state updates

## 6. Current MCP Tool Surfaces

### Kali MCP (`src/mcp/kali_mcp_server.py`)

Primary tool names:
- `nmap_scan`
- `gobuster_scan`
- `dirb_scan`
- `nikto_scan`
- `sqlmap_scan`
- `metasploit_run`
- `hydra_attack`
- `john_crack`
- `wpscan_analyze`
- `enum4linux_scan`
- `server_health`
- `execute_command`

### Metasploit MCP (`src/mcp/Metasploit.py`)

Primary tool names:
- `list_exploits`
- `list_payloads`
- `generate_payload`
- `run_exploit`
- `run_post_module`
- `run_auxiliary_module`
- `list_active_sessions`
- `send_session_command`
- `list_listeners`
- `start_listener`
- `stop_job`
- `terminate_session`

## 7. Access Control Model

Tool access is least-privilege and agent-specific.

Mechanism:
- Agent defines an allowlist of tool names
- Bridge filters discovered tools to that allowlist
- Agent runs only the filtered set

Example:
- `src/agents/striker.py` allowlist includes:
  - `list_exploits`
  - `run_exploit`
  - `run_auxiliary_module`
  - `list_active_sessions`

## 8. Supervisor Principle (Unchanged)

With full ReAct adoption, the control principle remains:
- Supervisor coordinates mission progression.
- Workers execute specialized tasks.
- Workers return state updates.
- Supervisor decides the next handoff.

This preserves the original supervisor framework while modernizing tool connectivity.

## 9. Canonical References

For implementation truth, prefer these files first:
- `src/mcp/mcp_tool_bridge.py`
- `src/mcp/kali_mcp_server.py`
- `src/mcp/Metasploit.py`
- `src/agents/striker.py`
- `src/graph/builder.py`
- `src/graph/router.py`
