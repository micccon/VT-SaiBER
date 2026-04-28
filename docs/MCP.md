# MCP Integration (Current)

This document describes how VT-SaiBER discovers, filters, and executes tools through the unified `attackbox` runtime.

## 1. Integration Pattern

Key files:
- `src/mcp/mcp_tool_bridge.py`
- `src/mcp/attackbox_server.py`
- `src/agents/worker_harness.py`

Bridge lifecycle:
1. Read `ATTACKBOX_MCP_URL`.
2. Connect to the unified MCP server over Streamable HTTP.
3. Call `list_tools()` and capture server-advertised schemas.
4. Convert discovered MCP tools into LangChain `StructuredTool` instances.
5. Filter exact tool names by agent allowlist with `get_tools_for_agent(...)`.

The bridge is dynamic. Tool exposure comes from live attackbox discovery rather than static hardcoded wrappers.

## 2. Runtime Endpoint

Attackbox MCP:
- MCP service: `8080`
- `msfrpcd`: `55553`
- Typical bridge URL: `http://attackbox:8080/mcp`

## 3. Tool Naming and Filtering

Tools keep their server-advertised names exactly:
- `recon_service_probe`
- `web_content_enum`
- `msf_run_exploit`
- `msf_session_command`

There is no runtime `kali_` / `msf_` prefix synthesis anymore.

Agent access is controlled by explicit allowlists:
- `supervisor` and `librarian` are non-executing
- `scout`, `fuzzer`, `striker`, and `resident` receive filtered subsets through the shared OpenAI-SDK runtime

## 4. Current Tool Inventory

Unified attackbox MCP (`src/mcp/attackbox_server.py`) exposes a curated workflow surface including:
- Recon: `recon_host_discovery`, `recon_port_scan`, `recon_service_probe`, `recon_banner_grab`, `recon_http_fingerprint`
- Web: `web_content_enum`, `web_vhost_enum`, `web_param_discovery`, `web_waf_detect`, `web_nikto_scan`, `web_http_request`, `web_auth_form_probe`, `web_file_upload_probe`, `web_idor_probe`, `web_sqlmap_scan`, `web_command_injection_probe`, `web_traversal_probe`, `web_wordpress_scan`
- Access: `access_hydra_attack`, `access_john_crack`, `access_ssh_login`, `access_ssh_command`, `access_smb_enum`
- Metasploit: `msf_search_modules`, `msf_get_module_info`, `msf_get_module_options`, `msf_run_exploit`, `msf_run_auxiliary`, `msf_run_post`, `msf_list_sessions`, `msf_session_command`, `msf_start_listener`, `msf_terminate_session`
- Fallback: `system_execute_command`

## 5. Result Contract

Every tool returns the same top-level envelope:
- `status`
- `summary`
- `evidence`
- `artifacts`
- `raw`
- `metadata`

This gives agents one predictable parsing contract across recon, web, Metasploit, and shell-backed tools.

## 6. Guardrails

Guardrail stack:
1. Router-level mission/scope/iteration controls (`src/graph/router.py`)
2. Agent-specific allowlists in the worker harness
3. Striker approval and execution guards in `src/agents/striker.py`
4. Resident approval guards for post-session objective work in `src/agents/resident.py`
5. Server-side command/tool validation in `src/mcp/attackbox_server.py`

Resident-specific guardrails:
- Read-only `msf_session_command` triage can run automatically.
- `system_execute_command` is approval-gated for Resident.
- Mutating `msf_session_command`, sensitive `msf_run_post`, and `msf_terminate_session` are approval-gated for Resident.
- Resident is intentionally narrower than Striker and does not receive the broader exploitation surface.

## 7. Practical Add/Change Workflow

When adding a tool:
1. Add it to `src/mcp/attackbox_server.py`.
2. Rebuild/restart `attackbox`.
3. Let the bridge rediscover it on startup.
4. Add the tool name to the appropriate worker allowlist.
5. Update prompts, skills, and tests if the capability changes agent behavior.
