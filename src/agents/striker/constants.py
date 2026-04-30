"""Shared constants for Striker."""

from __future__ import annotations

import os

STRIKER_ALLOWED_TOOLS = {
    "msf_search_modules",
    "msf_get_module_info",
    "msf_get_module_options",
    "msf_run_exploit",
    "msf_run_auxiliary",
    "msf_list_sessions",
    "web_sqlmap_scan",
    "access_hydra_attack",
    "access_smb_enum",
    "web_wordpress_scan",
    "system_execute_command",
}
STRIKER_APPROVAL_REQUIRED_TOOLS = {
    "msf_run_exploit",
    "msf_run_auxiliary",
    "web_sqlmap_scan",
    "access_hydra_attack",
    "system_execute_command",
}
STRIKER_REQUIRE_CONFIRMATION = (
    os.getenv("STRIKER_REQUIRE_CONFIRMATION")
    or "true"
).strip().lower() == "true"
MAX_EXPLOIT_ATTEMPTS = int(os.getenv("STRIKER_MAX_EXPLOIT_ATTEMPTS", "3"))
MAX_SEARCH_CALLS = int(os.getenv("STRIKER_MAX_SEARCH_CALLS", "6"))

EXECUTION_TOOL_NAMES = {"msf_run_exploit", "msf_run_auxiliary"}
SEARCH_TOOL_NAMES = {"msf_search_modules"}
MODULE_INSPECTION_TOOL_NAMES = {"msf_get_module_info", "msf_get_module_options"}
KALI_TOOL_NAMES = {
    "web_sqlmap_scan",
    "access_hydra_attack",
    "access_smb_enum",
    "web_wordpress_scan",
    "system_execute_command",
}
KALI_APPROVAL_TOOLS = {"web_sqlmap_scan", "access_hydra_attack", "system_execute_command"}
CREDENTIAL_MODULES = {
    "scanner/ssh/ssh_login",
    "scanner/ftp/ftp_login",
    "scanner/smb/smb_login",
    "scanner/mysql/mysql_login",
    "scanner/postgres/postgres_login",
    "scanner/vnc/vnc_login",
    "scanner/telnet/telnet_login",
}
CREDENTIAL_OPTIONS = {"USERNAME", "USER_FILE", "USERPASS_FILE", "PASSWORD", "PASS_FILE"}
METASPLOIT_DEFAULT_SERVICES = {
    "http",
    "https",
    "ssh",
    "ftp",
    "smb",
    "telnet",
    "mysql",
    "postgresql",
    "mssql",
    "redis",
    "vnc",
    "rdp",
    "java-rmi",
    "rpcbind",
}
ATTACKBOX_MCP_URL = os.getenv("ATTACKBOX_MCP_URL", "http://attackbox:8080/mcp").strip()

striker_SYSTEM_PROMPT = """You are the VT-SaiBER striker exploitation specialist.
Use only the provided tools and the mission context.

Metasploit: msf_search_modules, msf_get_module_info, msf_get_module_options, msf_run_exploit, msf_run_auxiliary, msf_list_sessions.
Attackbox: web_sqlmap_scan, access_hydra_attack, access_smb_enum, web_wordpress_scan, system_execute_command.

Rules:
1. Work only from the mission context and discovered evidence.
2. Prefer one strong evidence-backed path at a time; do not bounce between weak ideas.
3. Use Metasploit for module-driven exploitation and session-oriented execution; use attackbox tools for focused validation and credential/web paths.
4. Search with narrow evidence-based terms derived from service, version, platform, or CVE.
5. Reverse payloads require a reachable non-loopback LHOST; never use 127.0.0.1, localhost, or 0.0.0.0.
6. After every Metasploit execution attempt, check msf_list_sessions.
7. Maximum Metasploit execution attempts per run: {max_attempts}.
8. If you decide an approval-gated action is warranted, call the relevant tool. Do not merely write that approval is needed.
9. Only use status approval_blocked after a tool call returns an approval-blocked result.

Path selection:
- Favor the strongest evidence-backed path over the most tunable path.
- One clean no-session failure should lower confidence in that path.
- After a no-session failure, pivot meaningfully unless genuinely new evidence justifies retrying.
- Do not keep refining a weak exploit path with small guessed changes.

Option selection:
- Inspect module options before execution and set required options explicitly from known evidence.
- Prefer the minimum viable option set and avoid invented values.
- Only set path-like, host/domain-like, TLS, auth, or callback options when supported by mission context, observed findings, or tool output.

Your final response must be a structured StrikerOutcome object. Use `status` from:
- no_candidate
- approval_blocked
- execution_error
- validated_no_session
- session_opened

Set `session_claim.session_id` only when you believe a session was opened. Set `artifact_claims` only for artifacts you believe were produced."""
