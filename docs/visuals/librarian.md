# Librarian Agent: Design and Architecture

The **Librarian** is a "formal agent" specialized in operating **knowledge tools** (RAG + OSINT). Unlike other agents that interface with system tools (e.g., nmap or Metasploit) via MCP servers, the Librarian's tools are primarily internal functions and external research APIs.

From a senior engineering perspective, a robust Librarian agent consists of the following architectural components:

---

## 1. Responsibilities and Interface

The Librarian’s scope is strictly defined: it provides the technical "know-how" and exploit intelligence required for the mission.

### Core Interface
The agent should expose a standardized asynchronous method:

```python
class LibrarianAgent:
    async def answer(self, question: str, context: dict | None = None) -> dict:
        """
        Processes a knowledge-based query and returns a structured response.
        """
        ...
```

### Response Structure
The output must be structured for seamless consumption by the **Supervisor** or **Striker** agents:

```python
{
    "answer": "text explanation",   # Synthesized technical guidance
    "sources": [...],                # List of RAG / OSINT references
    "confidence": 0.85,             # Float (0.0 - 1.0) for decision logic
    "raw_evidence": {...},          # (Optional) Raw chunks or URLs for verification
}
```

---

## 2. Tool Layer: Knowledge & Research

While other agents utilize MCP servers for system-level execution, the Librarian utilizes a "Knowledge Toolset":

* **Internal Tools (Programmatic):**
    * **RAG Retrieval:** `RAGOrchestrator.retrieve(query, source="kb|findings|both")`.
    * **Local KB Organization:** Aggregating vector chunks into "Source Documents" and "Summaries."
* **External Tools (Direct API or MCP):**
    * **Tavily Search API:** Used for real-time CVE research, exploit implementations, and official documentation.
    * **Extended OSINT:** Expandable to other security-specific databases.

> **Design Note:** While system tools (nmap, Metasploit) are best wrapped in MCP, the Librarian often calls RAG and HTTP OSINT clients directly in Python, acting as a specialized "tool wrapper layer" itself.

---

## 3. Internal Pipeline: The "Mini Pipeline"

A production-grade Librarian processes requests through a five-stage internal pipeline:



### I. Query Understanding
* Standardize the input (normalization).
* **Classification:** Identify if the query is an **Exploit Lookup** (e.g., "vsftpd 2.3.4"), **Tool Usage** (e.g., "nmap flags for backdoor detection"), or **Conceptual** (e.g., "What is CVE-2011-2523?").
* **Keyword Reinforcement:** Append context-heavy terms like "Metasploit module" or "PoC."

### II. Retrieval (RAG + OSINT)
* **Knowledge Base:** Query the internal vector store for historical findings.
* **OSINT:** Trigger web searches (e.g., via Tavily) for the latest security advisories.

### III. Evidence Fusion & Filtering
* Merge results from all sources.
* Filter for relevance based on similarity scores.
* **De-duplication:** Ensure the same Exploit-DB page or documentation doesn't appear multiple times.

### IV. Answer Generation (LLM Synthesis)
* Utilize a specialized system prompt to format the output:
    1.  Identify the specific Exploit/Metasploit module.
    2.  Outline the execution path (Scan → Module selection → Payload).
    3.  Highlight risks and mitigation strategies.

### V. Confidence Assessment
* Calculate a confidence score ($0.0 \leq C \leq 1.0$) based on:
    * Similarity metrics from the Vector DB.
    * Presence of exact matches for exploit paths (e.g., `exploit/unix/ftp/vsftpd_234_backdoor`).

---

## 4. Agent Integration & Orchestration

The Librarian is a collaborative node within the larger agentic framework:

* **Supervisor Interaction:**
    * When the **Scout** identifies a service (e.g., vsftpd 2.3.4), the Supervisor queries the Librarian: *"What exploit is applicable to vsftpd 2.3.4 on 192.168.1.50?"*
    * The Supervisor uses the Librarian's `confidence` score to decide whether to authorize the **Striker**.
* **Striker Interaction:**
    * The Striker extracts the exact `module_path` from the Librarian's response to populate Metasploit MCP parameters.
    * If confidence is low, the Striker may request a "Deep Search" or flag the task for human intervention.

---

## 5. Minimum Viable Component List

To implement the Librarian agent, you need:

1.  **Standardized Interface:** A class/method that returns structured JSON.
2.  **RAG Integration:** Connection to a `RAGOrchestrator`.
3.  **OSINT Client:** Integration with an API like Tavily for live CVE/Exploit data.
4.  **Synthesis Engine:** LLM client with a tailored "Security Expert" system prompt.
5.  **Caching Layer:** A simple cache to prevent redundant external API calls for identical queries.
6.  **Scoring Logic:** A deterministic or LLM-based method to output confidence levels.

---