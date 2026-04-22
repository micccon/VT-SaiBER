# MCP Integration (Current)

This document describes how MCP tools are discovered, filtered, guarded, and executed in VT-SaiBER.

## 1. Integration Pattern

Key bridge:
- `src/mcp/mcp_tool_bridge.py`

Bridge lifecycle:
1. Read `KALI_MCP_URL` and `MSF_MCP_URL`.
2. Connect to each MCP server via SSE (`{url}/sse`).
3. Call `list_tools()` and capture schemas.
4. Convert each discovered MCP tool into LangChain `StructuredTool`.
5. Prefix runtime names by server id:
   - `kali_<tool_name>`
   - `msf_<tool_name>`
6. Filter by agent allowlist with `get_tools_for_agent(...)`.

The bridge is dynamic. Tool exposure comes from live server discovery, not static hardcoded HTTP mappings.

## 2. Server Ports and Endpoints

Kali MCP:
- MCP SSE service: `5001`
- Kali REST backend: `5000`
- Typical bridge URL: `http://kali-mcp:5001`

Metasploit MCP:
- MCP service: `8085`
- `msfrpcd`: `55553`
- Typical bridge URL: `http://msf-mcp:8085`

## 3. Tool Naming and Filtering

Native MCP names (server-defined):
- `run_exploit`, `nmap_scan`, etc.

Bridge-exposed names (agent runtime):
- `msf_run_exploit`
- `kali_nmap_scan`

Allowlist matching supports:
- base names (`run_exploit`)
- prefixed names (`msf_run_exploit`)

This allows agent configs to remain readable while still binding to concrete prefixed runtime tools.

## 4. Current Tool Inventory

Kali MCP (`src/mcp/kali_mcp_server.py`):
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

Metasploit MCP (`src/mcp/msf_mcp_server.py`):
- `list_exploits`
- `list_payloads`
- `get_module_options`
- `get_module_info`
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

## 5. Runtime Guardrails Around MCP Tool Calls

Guardrail stack:
1. Router-level mission/scope/iteration controls (`src/graph/router.py`).
2. Per-agent tool allowlists from MCP bridge.
3. Tool-call pre/post guards (`src/utils/tool_guard.py`, `src/utils/tool_guard_profiles.py`).
4. Server-side MCP validations and execution logic.

Striker guard profile currently enforces:
- non-empty `msf_list_exploits.search_term`
- module-info sequencing gates (when enabled)
- payload compatibility checks
- manual confirmation for exploit-class tools
- post-call caching from `msf_get_module_info`

## 6. Tool Call Lifecycle (Striker Example)

1. Striker requests filtered tools from bridge.
2. Tools are wrapped by `wrap_tools_with_rules(...)`.
3. On each call:
   - pre-rules may modify args, skip, or block.
   - if allowed, call executes via MCP bridge.
   - post-rules may cache metadata for later calls.
4. Tool results are parsed into state updates (e.g., `ExploitResult` projection in Striker extractor).

## 7. Error and Result Shape Notes

Bridge normalizes common payload patterns (including `{"result": ...}` envelopes) before handing tool outputs to agents.

Agent-side parsing helpers:
- `src/utils/parsers.py`
  - `normalize_tool_result(...)`
  - `metasploit_module_key(...)`

Common blocked/aborted action payloads:
- `status: "skipped"` for policy skips (e.g., empty search term)
- `status: "aborted"` for manual confirmation denial
- structured error payloads when tool invocation fails

## 8. Practical Add/Change Workflow

When adding a tool:
1. Add MCP tool in server (`kali_mcp_server.py` or `msf_mcp_server.py`).
2. Rebuild/restart target container.
3. Bridge rediscovers tool on startup.
4. Add tool name to specific agent allowlist.
5. Add or adjust guard rules if execution is sensitive.
6. Update docs (`docs/MCP.md`, `docs/visuals/access_control_matrix.txt`).

When changing tool args:
1. Update MCP tool schema.
2. Revalidate agent prompts/usage patterns.
3. Re-run relevant agent tests (for Striker: `tests/agent_tests/striker/...`).

