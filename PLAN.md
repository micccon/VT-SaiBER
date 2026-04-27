# General-Purpose Attackbox Migration

## Summary
Migrate VT-SaiBER to a general-purpose `postgres + agents + attackbox` architecture that can attack many different VM styles, not just the automotive benchmark. The automotive testbed remains a capability benchmark for depth and breadth, but not a product contract.

The core execution substrate is:
- **Kali** for broad offensive tooling
- **Metasploit** for exploit/session workflows
- **skills** for target-family-specific tactics and playbooks
- **one unified MCP boundary** for all execution from the agents side

## Key Changes

### 1. Runtime architecture
- Replace the current `kali-mcp` + `msf-mcp` split with one `attackbox` container and keep `agents` and `postgres`.
- Remove `KALI_MCP_URL` and `MSF_MCP_URL`; add only `ATTACKBOX_MCP_URL=http://attackbox:8080/mcp`.
- Keep KB indexing as a one-shot bootstrap/init job, not a steady-state service.
- Preserve the current LangGraph specialist topology:
  - `supervisor`
  - `scout`
  - `fuzzer`
  - `librarian`
  - `striker`
  - `resident`

### 2. Attackbox design
- Build `attackbox` on Kali and install a curated set of broadly useful offensive tools plus Metasploit.
- Run one MCP server inside `attackbox` over Streamable HTTP.
- Execute tools locally inside `attackbox`; do not proxy normal execution through a second internal REST service.
- Keep Metasploit available as a first-class capability inside the same execution plane.

### 3. Tool-layer philosophy
- The MCP layer should expose **generic workflow tools**, not benchmark-specific helpers and not one wrapper for every single binary.
- First-class tools should cover reusable cross-target workflows:
  - recon and service discovery
  - HTTP fingerprinting and web content discovery
  - auth/credential attacks
  - common web exploitation workflows
  - Metasploit search, option inspection, execution, and session management
  - bounded generic command/script execution
- Skills, not MCP APIs, should carry target-family-specific tactics such as automotive, appliance, AD-heavy Windows, protocol-specific, or vendor-specific playbooks.
- The benchmark VM should never drive fixed core APIs like “unlock doors” or other environment-shaped helpers.

### 4. Curated first-class MCP surface
Expose a stable curated surface such as:

- Recon:
  - `recon_host_discovery`
  - `recon_port_scan`
  - `recon_service_probe`
  - `recon_banner_grab`
  - `recon_http_fingerprint`

- Web enumeration and interaction:
  - `web_content_enum`
  - `web_vhost_enum`
  - `web_param_discovery`
  - `web_waf_detect`
  - `web_nikto_scan`
  - `web_http_request`
  - `web_auth_form_probe`
  - `web_file_upload_probe`
  - `web_idor_probe`

- Web exploitation:
  - `web_sqlmap_scan`
  - `web_command_injection_probe`
  - `web_traversal_probe`
  - `web_wordpress_scan`

- Credential and access:
  - `access_hydra_attack`
  - `access_john_crack`
  - `access_ssh_login`
  - `access_ssh_command`
  - `access_smb_enum`

- Metasploit:
  - `msf_search_modules`
  - `msf_get_module_info`
  - `msf_get_module_options`
  - `msf_run_exploit`
  - `msf_run_auxiliary`
  - `msf_run_post`
  - `msf_list_sessions`
  - `msf_session_command`
  - `msf_start_listener`
  - `msf_terminate_session`

- Controlled fallback:
  - `system_execute_command`

Implementation rule:
- these are workflow contracts
- the underlying engine may be `nmap`, `gobuster`, `ffuf`, `dirsearch`, `whatweb`, `wafw00f`, `arjun`, `nikto`, `sqlmap`, `hydra`, `john`, `enum4linux-ng`, `wpscan`, or Metasploit as appropriate
- specialized tools can be installed in `attackbox` without immediately becoming first-class MCP APIs

### 5. Skills as the specialization layer
- Expand skill coverage so the system can adapt to many VM families without bloating the core tool API.
- Skills should contain:
  - target-family heuristics
  - evidence-to-tool selection doctrine
  - protocol or platform-specific workflows
  - escalation and validation playbooks
  - safety and approval guidance for risky operations
- Examples of skill families:
  - automotive/CAN/UDS
  - Windows/SMB/AD
  - Linux service exploitation
  - CMS-specific workflows
  - appliance/vendor patterns
- `striker` and `resident` should be the main consumers of these higher-context skills; `scout` and `fuzzer` can also load narrower doctrine where useful.

### 6. Unified client and shared worker harness
- Replace [src/mcp/mcp_tool_bridge.py](/home/micccon/Documents/VT-SaiBER/src/mcp/mcp_tool_bridge.py) with a single attackbox client using Streamable HTTP.
- Remove `kali_` / `msf_` prefix synthesis, SSE-specific logic, and endpoint auto-correction.
- Introduce a shared execution harness for `scout`, `fuzzer`, `striker`, and `resident` that handles:
  - tool discovery and caching
  - allowlist filtering
  - approvals
  - retry/timeout policy
  - artifact registration
  - structured result normalization
- Keep `supervisor` and `librarian` non-executing.

### 7. State and persistence
- Keep the shared state generic and portable across target types:
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
- Avoid schemas tailored to any single benchmark environment.
- Persist large outputs by reference only, with metadata about producing tool, target, and summary.

### 8. MCP response contract
Every tool returns the same envelope:
- `status`
- `summary`
- `evidence`
- `artifacts`
- `raw`
- `metadata`

This is required for:
- consistent agent parsing
- reduced regex dependence
- better persistence
- easier support for many VM types

## Public Interfaces
- Runtime env:
  - add `ATTACKBOX_MCP_URL`
  - remove `KALI_MCP_URL`
  - remove `MSF_MCP_URL`
- MCP transport:
  - Streamable HTTP only
- MCP API:
  - one unified endpoint
  - curated workflow-oriented tool names
  - normalized result envelope
- Skill system:
  - target specialization lives in skills, not in benchmark-specific MCP APIs

## Test Plan
- Rewrite [tests/mcp_tests/mcp_toolbridge_tests.py](/home/micccon/Documents/VT-SaiBER/tests/mcp_tests/mcp_toolbridge_tests.py) for the single attackbox client and curated tool surface.
- Add contract tests for:
  - expected tool discovery
  - normalized success/error/partial envelopes
  - per-agent allowlists
  - approval gating for `system_execute_command`
- Add integration tests for:
  - `scout -> fuzzer -> librarian -> striker -> resident`
  - exploit-to-session flow
  - post-exploitation enrichment
  - artifact persistence
- Validate against more than the automotive benchmark where possible; the automotive VM remains one benchmark for proving the platform can reach a high level of attack sophistication.

## Assumptions
- This is a non-compatibility-preserving hard cut.
- Kali and Metasploit are the permanent execution foundations.
- The product is designed for many VM and target types.
- Skills are the preferred mechanism for specific cases and deeper tactics.
- The benchmark defines the expected level of offensive capability, not the shape of the architecture.


there are leftover scripts and dockerfiles as well. so for agent tests, firstly I want to organize them each into their own folder. Each agent test should copy the script onto the running agent container, and then do the test live with openrouter. Additionally we have a lot of 