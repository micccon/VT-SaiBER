1. What is RAG? What does it do?
RAG (Retrieval‑Augmented Generation) means that, before the LLM answers, it first retrieves relevant information from an external knowledge base, then feeds that content into the LLM as context. This makes answers:

More accurate and grounded (there are documents to check against)

Able to use project‑specific docs, mission findings, and historical logs, instead of only relying on the model’s pre‑training

The overall flow can be split into two phases:

Retrieval: Convert the user question into an embedding vector, then search a vector database for the most similar text chunks (top‑k chunks)

Generation: Send the original question plus the retrieved chunks to the LLM, and let the LLM generate an answer based on that context

2. RAG Architecture Overview
text
┌─────────────────────────────────────────────────────────────┐
│                        Knowledge Sources                     │
│   data/*.pdf   │   docs/*.md   │   findings / mission logs  │
└───────────────────────────┬─────────────────────────────────┘
                            │
                    scripts/ingest_docs.py
                    (chunk → embed → insert)
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              src/database/  (Memory & Persistence)           │
│                                                             │
│   schema.sql ──► knowledge_base  (content, embedding)       │
│                  findings_embeddings  (VECTOR 1536)         │
│   manager.py ──► ingest_document() / retrieve_context()     │
└───────────────────────────┬─────────────────────────────────┘
                            │  vector search (top‑k)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              src/agents/librarian.py  (RAG Front‑End)       │
│                                                             │
│   1. Receive research query (from CyberState)               │
│   2. Embed query → pgvector similarity search               │
│   3. Fetch top‑k chunks                                     │
│   4. Build prompt → LLM (Claude 3.5 Sonnet)                 │
│   5. Write research_results back to CyberState              │
└──────────────┬──────────────────────────┬───────────────────┘
               │                          │
        (assign task)                     │(read results)
               ▼                          ▼
┌──────────────────────┐     ┌────────────────────────┐
│  src/agents/         │     │  src/agents/            │
│  supervisor.py       │     │  striker.py             │
│                      │     │  (uses RAG knowledge    │
│  router.py routing   │     │   to choose exploits)   │
└──────────────────────┘     └────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│                    src/state.py  (CyberState)               │
│                                                             │
│   research_query        ← written by Supervisor             │
│   research_results      ← written by Librarian              │
│   rag_context_snippets  ← raw chunks (recommended field)    │
└─────────────────────────────────────────────────────────────┘
RAG Flow (short version)

text
  [Knowledge Source]
       │ ingest_docs.py
       ▼
  [pgvector DB]  ◄──────────────────────────────┐
       │ retrieve_context()                      │
       ▼                                         │
  [Librarian] ──► LLM ──► CyberState.results    │
       ▲                                         │
       │ research_query                          │
  [Supervisor] ──► [Striker / Other Agents] ─────┘
                        (use results to act)
3. RAG Components (in VT‑SaiBER)
Component type	Description	VT‑SaiBER mapping
Data sources / docs	Knowledge to search	docs/, mission reports, data/ PDFs, findings logs
Embedding model	Turn text into vectors	text-embedding-3-small (OpenAI) or compatible, 1536‑d 
​
Vector store / DB	Stores embeddings, supports similarity search	PostgreSQL 16+ with pgvector (VECTOR(1536)), defined in src/database/schema.sql 
​
Retriever	Wraps query embedding → vector search → top‑k	Extend src/database/manager.py or add rag_engine.py
LLM	Generates answers from context	Claude 3.5 Sonnet / GPT‑4o, called from src/agents/
RAG front‑end agent	Orchestrates RAG and returns results	src/agents/librarian.py (Intelligence specialist)
4. RAG Pipeline Steps
4.1 Indexing phase (offline / batch)
Goal: Turn documents into data that can be searched via vectors.

Step	Description	VT‑SaiBER implementation
Collect documents	Load docs/*.md, data/*.pdf, mission logs	scripts/ingest_docs.py (to be created) 
​
Chunking	Split long docs into 300–800 token chunks	same script, calling rag_engine.ingest_document()
Embedding	Call embedding API for each chunk (1536‑d)	text-embedding-3-small via OpenAI SDK
Store in DB	Write to Postgres + pgvector	src/database/manager.py or rag_engine.py
Suggested pgvector schema:

sql
CREATE TABLE knowledge_base (
    id          SERIAL PRIMARY KEY,
    source      TEXT,           -- source file name or URL
    mission_id  INTEGER,        -- optional, bind to mission
    content     TEXT,           -- raw chunk text
    metadata    JSONB,          -- e.g. agent, target_ip, tags
    embedding   VECTOR(1536)
);

CREATE INDEX ON knowledge_base USING ivfflat (embedding vector_cosine_ops);
4.2 Query / generation phase (online)
Every time the Librarian agent receives a query:

Supervisor or user writes a research question into CyberState

Librarian (src/agents/librarian.py) reads the query

Embed query using text-embedding-3-small

Run pgvector similarity search, for example:
ORDER BY embedding <-> %s::vector LIMIT 5

Fetch top‑k chunks + metadata

Build a prompt and call the LLM (Claude / GPT‑4o)

Return answer + sources into CyberState.research_results

5. Integration points in VT‑SaiBER
5.1 Data layer (src/database/)
schema.sql

Already has findings and findings_embeddings (pgvector)

Recommended: add a knowledge_base table dedicated to doc chunks

manager.py

Currently handles Postgres/pgvector connections and CRUD

Recommended to add (or separate into rag_engine.py):

ingest_document(source, content, metadata) — chunk → embed → insert into pgvector

retrieve_context(query: str, filters: dict, top_k: int) — embed query → vector search → return chunks

5.2 Agent layer (src/agents/)
librarian.py (Intelligence specialist) is the main RAG front‑end:

Receives research instructions from Supervisor (e.g. “research vsftpd 2.3.4 CVE”)

Calls retrieve_context() to query pgvector

Combines OSINT (MCP tools) + RAG results

Writes summary + sources back into CyberState.research_results

supervisor.py and striker.py are downstream consumers of RAG:

Read CyberState.research_results / rag_context_snippets to make decisions

Striker uses exploit knowledge from RAG to choose attack techniques

5.3 State layer (src/state.py)
python
class CyberState(TypedDict):
    # ... existing fields ...
    research_results: Annotated[list, operator.add]   # existing
    rag_context_snippets: list[dict]                  # new: raw chunks from Librarian
    # suggested dict structure: {"content": str, "source": str, "score": float}
5.4 Graph layer (src/graph/)
builder.py: add the Librarian node to the LangGraph; the node reads CyberState and updates research_results

router.py: conditional routing to decide when the Supervisor should call the Librarian (i.e. when to trigger RAG)

5.5 Scripts & tests
scripts/ingest_docs.py (to be created): one‑off / periodic ingestion of docs/*.md and data/*.pdf into pgvector

tests/ (recommended):

Ingest sample docs → Librarian query → assert that the LLM prompt includes the expected chunks

6. RAG Use Cases
Scenario	Example Librarian query	Likely knowledge sources
Exploit / CVE lookup	vsftpd 2.3.4 exploit conditions	Metasploit docs, CVE DB, data/ PDFs
Mission knowledge	previous attacks on port 21 FTP	findings_embeddings (past mission findings)
Attack strategy	lateral movement techniques after shell	docs/AGENT_SPECS.md, OSINT notes
System docs	how to add a new agent	docs/ARCHITECTURE.md, other docs/*.md
OT / CAN knowledge	UDS diagnostic session attack	automotive docs, OT specialist notes
7. Safety & Guardrails (RAG‑related)
Scope lock: retrieve_context() can use metadata filters (e.g., target_ip whitelist) to avoid retrieving knowledge outside the allowed scope.

Human‑in‑the‑loop (HITL): High‑risk exploit knowledge (e.g., CAN injection) from Librarian should be reviewed by Supervisor before being handed to Striker.

Throttling: Embedding API calls and pgvector queries should have retries and rate limiting to protect the system.

8. Summary
RAG building blocks: document store + embedding model + pgvector + retriever + LLM

Layer	Key files	RAG role
DB	src/database/schema.sql, manager.py	Store embeddings and run vector search
Agent	src/agents/librarian.py	RAG front‑end, orchestrates queries
State	src/state.py	research_results / rag_context_snippets
Graph	src/graph/builder.py, router.py	Node wiring and routing logic
Script	scripts/ingest_docs.py	Batch document indexing
Data	data/ PDFs, docs/*.md	Knowledge sources
