# Third-Party Sources

This directory vendors external projects used by VT-SaiBER images.

## Sources

- `MCP-Kali-Server`
  - Upstream: <https://github.com/Wh0am123/MCP-Kali-Server>
  - Runtime customization: `docker/kali_mcp.Dockerfile` overwrites `mcp_server.py`
    with `src/mcp/kali_mcp_server.py` during build.

- `MetasploitMCP`
  - Upstream: <https://github.com/GH05TCREW/MetasploitMCP>
  - Runtime customization: local modifications are applied directly in this vendored copy.

- `automotive_testbed`
  - Local VT-SaiBER testbed content used by `scripts/testbed/*.sh`.

## Notes

- These are vendored source copies (embedded `.git` directories removed).
- Docker images build from local code in this repository (no runtime `git clone`).
- Re-sync by pulling upstream in a temporary clone, then copying in reviewed changes.
