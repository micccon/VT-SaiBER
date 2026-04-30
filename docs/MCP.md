# MCP Integration

VT-SaiBER agents connect directly to the Docker-hosted attackbox MCP server through the promoted Agents SDK execution lane.

## Key Files
- `src/execution/runner.py`
- `src/contracts/execution.py`
- `src/mcp/attackbox_server.py`
- `src/agents/*/constants.py`

## Runtime Endpoint
- Attackbox MCP URL: `ATTACKBOX_MCP_URL` or `MCP_ATTACKBOX_URL`
- Default in Docker: `http://attackbox:8080/mcp`
- Metasploit RPC remains hosted inside the attackbox container.

## Tool Access
Specialist agents declare exact MCP allowlists in their constants files. The execution runner registers only allowed tools and marks high-impact tools as approval-required when configured by the agent.

Non-tool agents, including supervisor and librarian, use the chat/synthesis lane and do not receive MCP tools.

## Guardrails
- Graph/router safety checks enforce terminal status, iteration limits, valid agent names, and target scope.
- Agent policies enforce approval and pre-call checks for high-impact operations.
- The attackbox MCP server validates dangerous file path arguments and command shapes server-side.