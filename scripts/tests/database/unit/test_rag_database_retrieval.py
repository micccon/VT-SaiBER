from __future__ import annotations

from dataclasses import replace

from src.config import get_runtime_config
from src.database.findings_repository import create_finding
from src.database.rag.embedding import EmbeddingClient
from src.database.rag.models import Chunk
from src.database.rag.rag_manager import insert_kb_chunk
from src.database.rag.retriever import RAGRetriever


def _disabled_embedding_client() -> EmbeddingClient:
    cfg = replace(
        get_runtime_config(),
        embedding_provider="disabled",
        embedding_model="disabled-test-model",
        embedding_dimensions=1024,
    )
    return EmbeddingClient(config=cfg)


def test_kb_lexical_fallback_returns_inserted_chunks(kb_source_prefix: str) -> None:
    embedding_client = _disabled_embedding_client()
    provenance = embedding_client.provenance_tag()
    insert_kb_chunk(
        Chunk(
            doc_name="pytest-kb.md",
            chunk_text="vsftpd 2.3.4 backdoor exploit guidance mentions port 6200 shell behavior",
            embedding=[0.0] * 1024,
            metadata={
                "source_path": f"{kb_source_prefix}pytest-kb.md",
                "tool": "pytest",
                "embedding_provider": "disabled",
                "embedding_model": "disabled-test-model",
                "embedding_dimensions": 1024,
                "embedding_provenance": provenance,
            },
        )
    )

    retriever = RAGRetriever(embedding_client=embedding_client)
    results = __import__("asyncio").run(
        retriever.retrieve(
            query="vsftpd 2.3.4 backdoor exploit",
            source="kb",
            top_k=3,
        )
    )

    kb_results = results["kb_results"]
    print(
        "[rag] kb lexical results="
        + ", ".join(
            f"{item['doc_name']} score={float(item['score']):.3f}" for item in kb_results
        )
    )
    assert kb_results
    assert kb_results[0]["doc_name"] == "pytest-kb.md"
    assert "vsftpd 2.3.4" in kb_results[0]["chunk_text"]
    assert float(kb_results[0]["score"]) > 0


def test_findings_lexical_fallback_returns_matching_records(mission_id: str) -> None:
    create_finding(
        mission_id=mission_id,
        agent_name="librarian",
        finding_type="intelligence_brief",
        severity="medium",
        target_ip="10.9.8.7",
        target_port=21,
        title="vsftpd exploit path",
        description="Backdoored vsftpd 2.3.4 likely gives a shell when triggered.",
        data={
            "cve": "CVE-2011-2523",
            "source_types": ["kb", "cve"],
            "technical_params": {"exploit_module": "exploit/unix/ftp/vsftpd_234_backdoor"},
        },
        auto_embed=False,
    )

    retriever = RAGRetriever(embedding_client=_disabled_embedding_client())
    results = __import__("asyncio").run(
        retriever.retrieve(
            query="vsftpd backdoor cve 2011 2523",
            source="findings",
            top_k=3,
            filters={"mission_id": mission_id},
        )
    )

    finding_results = results["findings_results"]
    print(
        "[rag] findings lexical results="
        + ", ".join(
            f"{item['title']} score={float(item['score']):.3f}" for item in finding_results
        )
    )
    assert finding_results
    assert finding_results[0]["mission_id"] == mission_id
    assert finding_results[0]["title"] == "vsftpd exploit path"
    assert finding_results[0]["data"]["cve"] == "CVE-2011-2523"
