from __future__ import annotations

import uuid

import pytest

from src.agents.librarian import LibrarianAgent
from src.config import get_runtime_config
from src.database.librarian.cve_client import CVEClient
from src.database.librarian.osint_client import OSINTClient
from src.database.rag.embedding import EmbeddingClient
from src.database.rag.models import Chunk
from src.database.rag.rag_engine import RAGOrchestrator
from src.database.rag.rag_manager import insert_kb_chunk
from src.database.rag.retriever import RAGRetriever
from src.main import build_initial_state


class EmptyRag:
    async def retrieve(self, query: str, source: str = "both", top_k: int = 5, filters=None):
        return {"kb_results": [], "findings_results": [], "combined": []}


class EmptyOSINTClient:
    def is_configured(self) -> bool:
        return False

    async def search(self, query: str, *, max_results=None):
        return []


class EmptyCVEClient:
    async def search(self, *, query: str, service_clues=None, known_cves=None, max_results: int = 5):
        return []


def step(message: str) -> None:
    print(f"\n[live-step] {message}")


def print_librarian_output(label: str, out: dict) -> None:
    cache_entry = next(iter(out["research_cache"].values()))
    finding = out["intelligence_findings"][0]
    log_findings = _first_agent_log_findings(out)
    print(f"[{label}] summary={cache_entry.get('summary')}")
    print(f"[{label}] confidence={cache_entry.get('confidence')}")
    print(f"[{label}] source_types={cache_entry.get('source_types')}")
    print(f"[{label}] citations={cache_entry.get('citations')}")
    print(f"[{label}] source_status={cache_entry.get('source_status')}")
    print(f"[{label}] degraded_reasons={cache_entry.get('degraded_reasons')}")
    print(f"[{label}] retrieval_trace={log_findings.get('retrieval_trace')}")
    print(f"[{label}] finding={finding}")


def _first_agent_log_findings(out: dict) -> dict:
    logs = out.get("agent_log", []) or []
    if not logs:
        return {}
    first = logs[0]
    if isinstance(first, dict):
        return first.get("findings", {}) or {}
    return getattr(first, "findings", None) or {}


def require_live_embeddings() -> EmbeddingClient:
    client = EmbeddingClient()
    if not client.is_available():
        cfg = get_runtime_config()
        reason = (
            "Live embedding test requires configured EMBEDDING_PROVIDER and OPENROUTER_API_KEY. "
            f"provider={client.provider!r} model={client.model_name!r} "
            f"has_api_key={bool(cfg.openrouter_api_key)} "
            f"base_url={cfg.openrouter_base_url!r}"
        )
        print(f"[live-skip] {reason}")
        pytest.skip(reason)
    return client


def require_tavily() -> OSINTClient:
    client = OSINTClient()
    if not client.is_configured():
        cfg = get_runtime_config()
        reason = (
            "Live OSINT test requires TAVILY_API_KEY and tavily package. "
            f"has_tavily_key={bool(cfg.tavily_api_key)}"
        )
        print(f"[live-skip] {reason}")
        pytest.skip(reason)
    return client


def require_live_llm_config() -> None:
    cfg = get_runtime_config()
    if not cfg.openrouter_api_key or not cfg.openrouter_model:
        pytest.skip("Live librarian LLM test requires OPENROUTER_API_KEY and OPENROUTER_MODEL.")


def state(goal: str, mission_id: str | None = None):
    return build_initial_state(
        mission_goal=goal,
        target_scope=["10.0.0.1"],
        mission_id=mission_id or f"pytest-live-{uuid.uuid4().hex[:10]}",
    )


async def insert_live_kb_chunk(kb_source_prefix: str, doc_name: str, chunk_text: str) -> tuple[EmbeddingClient, str]:
    embedding_client = require_live_embeddings()
    chunk_embedding = await embedding_client.embed_text(chunk_text)
    insert_kb_chunk(
        Chunk(
            doc_name=doc_name,
            chunk_text=chunk_text,
            embedding=chunk_embedding,
            metadata={
                "source_path": f"{kb_source_prefix}{doc_name}",
                **embedding_client.metadata(),
            },
        )
    )
    return embedding_client, chunk_text


async def run_live_kb_retrieval(query: str, embedding_client: EmbeddingClient, top_k: int = 3):
    retriever = RAGRetriever(embedding_client=embedding_client)
    return await retriever.retrieve(query=query, source="kb", top_k=top_k)


def make_librarian_with_empty_sources() -> LibrarianAgent:
    return LibrarianAgent(
        rag_orchestrator=EmptyRag(),
        osint_client=EmptyOSINTClient(),
        cve_client=EmptyCVEClient(),
        llm_client=None,
    )


def make_librarian_with_empty_sources_live_llm() -> LibrarianAgent:
    return LibrarianAgent(
        rag_orchestrator=EmptyRag(),
        osint_client=EmptyOSINTClient(),
        cve_client=EmptyCVEClient(),
    )


def make_librarian_with_empty_kb_and_osint() -> LibrarianAgent:
    return LibrarianAgent(
        rag_orchestrator=EmptyRag(),
        osint_client=EmptyOSINTClient(),
        llm_client=None,
    )


def make_librarian_with_empty_kb_live_cve_osint() -> LibrarianAgent:
    return LibrarianAgent(rag_orchestrator=EmptyRag())


def make_librarian_with_empty_kb_live_osint() -> LibrarianAgent:
    return LibrarianAgent(
        rag_orchestrator=EmptyRag(),
        cve_client=EmptyCVEClient(),
        llm_client=None,
    )


def make_librarian_with_real_kb_live_external() -> LibrarianAgent:
    return LibrarianAgent(rag_orchestrator=RAGOrchestrator())


def make_librarian_with_real_kb_empty_external() -> LibrarianAgent:
    return LibrarianAgent(
        rag_orchestrator=RAGOrchestrator(),
        osint_client=EmptyOSINTClient(),
        cve_client=EmptyCVEClient(),
        llm_client=None,
    )


__all__ = [
    "CVEClient",
    "EmptyCVEClient",
    "EmptyOSINTClient",
    "EmptyRag",
    "RAGOrchestrator",
    "_first_agent_log_findings",
    "insert_live_kb_chunk",
    "make_librarian_with_empty_sources_live_llm",
    "make_librarian_with_empty_kb_and_osint",
    "make_librarian_with_empty_kb_live_cve_osint",
    "make_librarian_with_empty_kb_live_osint",
    "make_librarian_with_empty_sources",
    "make_librarian_with_real_kb_live_external",
    "make_librarian_with_real_kb_empty_external",
    "print_librarian_output",
    "require_live_embeddings",
    "require_live_llm_config",
    "require_tavily",
    "run_live_kb_retrieval",
    "state",
    "step",
]
