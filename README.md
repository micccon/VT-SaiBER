# 🛡️ VT-SaiBER: Autonomous Multi-Agent Cyber-Physical Security Squad

**VT-SaiBER** (Cyber-Physical Autonomous Intelligence for Bus & Endpoint Reconnaissance) is a modular, multi-agent orchestration framework designed to conduct autonomous penetration testing across IT networks and Automotive/IoT testbeds. 

By leveraging **LangGraph** for orchestration and the **Model Context Protocol (MCP)** for tool connectivity, VT-SaiBER coordinates a squad of specialized AI agents to map networks, identify vulnerabilities, and interact with vehicle systems in a simulated environment.

---

## 🏗️ System Architecture

VT-SaiBER uses a **Supervisor-Worker** pattern. A central "Brain" manages the global mission state, delegating granular tasks to specialists who execute actions via Dockerized tools.

### The Squad
* **Supervisor:** The Brain. Manages state transitions, validates goals, and handles mission routing.
* **Network Scout:** Recon specialist. Maps active hosts, open ports, and service versions.
* **Web Fuzzer:** Discovery specialist. Identifies unlinked directories and API endpoints.
* **Striker:** Precision Exploitation specialist. Executes surgical strikes via Metasploit.
* **Automotive Specialist:** OT specialist. Interacts with `vcan0`, UDS, and CAN-bus IDs.
* **Embedded/IoT Agent:** Protocol specialist. Targets MQTT brokers and Modbus/CoAP interfaces.
* **Librarian:** Intelligence specialist. Conducts RAG-driven research and OSINT.
* **Resident:** Post-Exploitation specialist. Handles lateral movement, pivoting, and persistence.

---

## 🚀 Tech Stack

* **Orchestration:** [LangGraph](https://github.com/langchain-ai/langgraph)
* **Intelligence:** Claude 3.5 Sonnet / GPT-4o
* **Persistence & RAG:** PostgreSQL 16+ with `pgvector`
* **Tool Interface:** Model Context Protocol (MCP)
* **Infrastructure:** Docker Compose (Multi-container orchestration)
* **Security Tools:** Kali Linux (Nmap, ffuf), Metasploit Framework (MSF-RPC)

---

## 📂 Project Structure

```text
VT-SaiBER/
├── docker-compose.yml         # Orchestrates Agents, DB, and MCP servers
├── .env.example               # Template for API keys and secrets
├── requirements.txt           # Python dependencies
│
├── src/
│   ├── main.py                # Entry point: Initializes LangGraph loop
│   ├── state.py               # Shared State (TypedDict) definitions
│   │
│   ├── agents/                # Agent logic & System Prompts
│   │   ├── base.py            # Abstract Base Agent Class
│   │   ├── supervisor.py
│   │   └── ... (worker agents)
│   │
│   ├── mcp/                   # Tool Interfaces
│   │   ├── client.py          # Unified MCP Client
│   │   └── servers/           # Custom MCP server definitions
│   │
│   ├── database/              # Memory & Persistence Layer
│   │   ├── manager.py         # Postgres/pgvector logic
│   │   └── schema.sql         # Database table definitions
│   │
│   └── graph/                 # Workflow Orchestration
│       ├── builder.py         # Node/Edge assembly
│       └── router.py          # Conditional handoff logic
│
├── data/                      # Persistent storage (Logs & PDF Knowledge Base)
├── docker/                    # Custom Dockerfiles for Kali/Auto-MCP
└── tests/                     # Unit tests for individual agent tools
```

---

## 🛠️ Setup & Deployment

### Clone the Repository:

```bash
git clone https://github.com/micccon/VT-SaiBER.git
cd VT-SaiBER
```

### Configure Environment:

```bash
cp .env.example .env
# Edit .env to add your ANTHROPIC_API_KEY and DATABASE_URL
```

### Launch the Environment:

```bash
docker-compose up --build
```

---

## 🔒 Safety & Guardrails

* **Scope Lock:** All agents are restricted to CIDR-validated target whitelists.
* **Throttling:** Mandatory 200ms delay between network requests to ensure system stability.
* **Human-in-the-Loop (HITL):** High-risk actions (exploit execution/CAN injection) require manual approval.

---

## 👥 Team Roles

* **Chief Architect:** [Your Name] — LangGraph & Supervisor Logic
* **Infra Lead:** [Sudip's Name] — Docker, MCP, & Post-Ex Tunneling
* **Specialist Lead:** [Member 3] — Recon & Exploitation Logic
* **Data & Lib Lead:** [Member 4] — PostgreSQL/pgvector & RAG Pipeline
* **Research Lead:** [Member 5] — Prompt Engineering & OSINT Tools

---

## 📄 License

[Add your license here]

## 🤝 Contributing

[Add contribution guidelines here]
