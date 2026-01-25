# VT-SaiBER (Agentic AI + Cybersecurity)

**AI-Powered Cybersecurity Agent Orchestration System**

VT-SaiBER is an advanced cybersecurity platform that combines AI agent orchestration with network reconnaissance tools. Inspired by the Avengers, it features specialized "Avenger" agents that work together to perform comprehensive security assessments using natural language commands.

![VT-SaiBER Architecture](docs/Untitled-2.png)

## What VT-SaiBER Does

- **AI Agent Orchestration**: Multiple specialized agents coordinate complex security tasks
- **Network Reconnaissance**: Advanced port scanning, service detection, and host discovery
- **Natural Language Interface**: Ask questions in plain English, get intelligent security analysis
- **Ethical Scanning**: Built-in input validation and security controls
- **Structured Reporting**: Comprehensive results with actionable insights
- **Extensible Architecture**: Easy to add new agents and capabilities

## Architecture Overview

### Core Components
```
VT-SaiBER/
├── orchestrator/                # Agent coordination system
│   ├── agent_system.py          # Main orchestrator (Google ADK)
│   ├── tony_stark.py            # Prompt engineering
│   ├── Validators.py            # Input/output validation
│   ├── interfaces.py            # Component contracts
│   └── mocks.py                 # Testing utilities
├── avengers/                    # Specialized agents
│   ├── nick_fury_agent.py       # Agent controller (ADK-based)
│   ├── vision_agent.py          # Network reconnaissance
│   └── vuln_report_agent.py     # Vulnerability reporting
├── interaction/                 # User interfaces
│   └── api/
│       └── thanos.py            # Input validation & security
├── tools/                       # External tool integrations
│   └── vision/
│       ├── vision_mcp_server.py # MCP server for Nmap
│       ├── vision_scanner.py    # Nmap wrapper
│       └── vision_parser.py     # XML to JSON parser
├── blueprints/                  # Data models & schemas
│   └── schemas.py               # Pydantic models
├── utils/
│   └── DrStrange.py             # Logging & telemetry
└── database/                    # Configuration & data
    ├── avenger_registry.json    # Agent definitions
    ├── avenger_prompts/         # LLM prompts
    └── logger/                  # Application logs
```

### Agent Roles (Inspired by Avengers)

- **Nick Fury**: Agent Controller - coordinates task execution across agents (ADK-based)
- **Tony Stark**: Prompt Engineer - crafts optimal prompts for LLM interactions
- **Vision**: Network Scanner - performs Nmap-based reconnaissance
- **Thanos**: Input Validator - ensures safe, valid user inputs
- **Dr. Strange**: Logger - tracks all system events and agent interactions

## Quick Start

### Prerequisites

- **Python 3.12+**
- **Nmap** installed on system
- **Google AI API Key** (for ADK frontend)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd VT-SaiBER
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up Google AI API**
   ```bash
   export GOOGLE_API_KEY="your-google-ai-api-key-here"
   ```

## Usage

### Option 1: Full Agent System (Streamlit UI)

```bash
# Start MCP server (in one terminal)
python tools/vision/vision_mcp_server.py

# Start Streamlit UI (in another terminal)
streamlit run main.py
```

### Option 2: MCP Server Only

Run the network scanning tools directly:

```bash
python tools/vision/vision_mcp_server.py
```

The server exposes these tools via HTTP:
- `ping_scan` - Host discovery
- `quick_scan` - Fast port scanning
- `port_scan` - Specific port scanning
- `service_scan` - Service version detection
- `comprehensive_scan` - Full security assessment

### Option 3: Agent Testing

Test individual components:

```bash
python tests/vision_agent_test.py
```

## Configuration

### Environment Variables

```bash
GOOGLE_API_KEY=your-api-key-here
GOOGLE_GENAI_USE_VERTEXAI=False
```

### Security Configuration

Edit `config.yaml` for security settings:

```yaml
security:
  allowed_target_scopes:
    - "192.168.1.0/24"
    - "10.0.0.0/8"
```

### Agent Registry

Modify `database/avenger_registry.json` to configure agents.

## Testing

```bash
# Test orchestrator
python test_orchestrator.py

# Test vision agent
python tests/vision_agent_test.py

# Test MCP server
python tools/vision/vision_mcp_server.py --test
```

## Development

### Adding New Agents

1. **Create agent class** in `avengers/` using Google ADK:
   ```python
   from google.adk.agents import Agent
   
   class NewAgent:
       def __init__(self):
           self.agent = Agent(
               name="new_agent",
               model="gemini-2.0-flash",
               instruction="Your agent instructions here"
           )
   ```

2. **Register in database** (`database/avenger_registry.json`)

3. **Add to AgentSystem** in `orchestrator/agent_system.py`

### Adding New Tools

Create MCP tools in `tools/vision/vision_mcp_server.py`:
```python
@mcp.tool(description="My new security tool")
def my_new_tool(target: str) -> dict:
    # Tool implementation
    pass
```

## Security & Ethics

**Important**: VT-SaiBER is designed for **authorized security testing only**. Always ensure you have explicit permission before scanning any network or system.

### Built-in Security Features
- **Input Validation**: Thanos validates all inputs against allowed target ranges
- **Rate Limiting**: Built-in delays and rate controls
- **Ethical Scanning**: Warns about intrusive scan types
- **Audit Logging**: All actions are logged for accountability

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
- **Nmap**: The gold standard for network scanning
- **Google ADK**: For the AI agent development framework
- **FastMCP**: For the model context protocol implementation
