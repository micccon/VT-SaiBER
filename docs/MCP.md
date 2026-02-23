# MCP Integration (Current)

This document describes how VT-SaiBER agents connect to MCP servers today.

Architecture direction:
- All agents use ReAct loops with MCP ToolBridge-discovered tools.

## 1. Integration Pattern

Key bridge file:
- `src/mcp/mcp_tool_bridge.py`

Flow:
1. Bridge reads `KALI_MCP_URL` and `MSF_MCP_URL`
2. Bridge connects to each server via SSE (`{url}/sse`)
3. Bridge runs `list_tools()`
4. Discovered tools are wrapped as LangChain `StructuredTool`
5. Tools are exposed to agents with server-prefixed names

Prefix convention:
- Kali tools: `kali_<tool_name>`
- Metasploit tools: `msf_<tool_name>`

Example:
- MCP tool `run_exploit` from msf server becomes `msf_run_exploit` in the agent tool list.

## 2. Server Endpoints and Ports

### Kali MCP Container

Runtime files:
- `scripts/docker/start_kali_mcp.sh`
- `src/mcp/kali_mcp_server.py`

Ports:
- `5000`: Kali REST API backend
- `5001`: Kali MCP server (SSE)

Typical internal URL used by bridge:
- `http://kali-mcp:5001`

### Metasploit MCP Container

Runtime files:
- `scripts/docker/start_msf_mcp.sh`
- `src/mcp/Metasploit.py` (project MCP implementation)

Ports:
- `55553`: `msfrpcd`
- `8085`: Metasploit MCP service (bridge target)

Typical internal URL used by bridge:
- `http://msf-mcp:8085`

## 3. Kali MCP Tool Names

From `src/mcp/kali_mcp_server.py`:
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

Bridge-exposed names are prefixed, e.g.:
- `kali_nmap_scan`
- `kali_execute_command`

## 4. Metasploit MCP Tool Names

From `src/mcp/Metasploit.py`:
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

Bridge-exposed names are prefixed, e.g.:
- `msf_list_exploits`
- `msf_run_exploit`
- `msf_list_active_sessions`

## 5. Agent Tool Filtering

Agents do not receive all discovered tools by default.

Pattern:
- Agent defines an allowlist (base names or prefixed names)
- Bridge returns only allowed tools via `get_tools_for_agent(...)`

Example allowlist:
- `list_exploits`, `run_exploit`, `run_auxiliary_module`, `list_active_sessions`
- runtime tool names provided to ReAct are `msf_*`

## 6. Operational Notes

- This is not a static hardcoded HTTP `/tools/<name>` router in the agent process.
- Tool discovery is runtime-driven from MCP servers.
- If a tool name changes at MCP server level, bridge discovery reflects it immediately.
- Access control still requires each agent allowlist to be updated intentionally.
