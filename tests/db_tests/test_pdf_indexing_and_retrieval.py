import pytest
from dotenv import load_dotenv

from src.database.rag.rag_engine import RAGOrchestrator
from src.database.manager import get_connection

load_dotenv()

PDF_PATH = "src/database/testbed_docs/metasploit_vsftpd_guide.pdf"


@pytest.mark.asyncio
async def test_pdf_indexing_and_retrieval():
    rag = RAGOrchestrator()
    await rag.index_knowledge_base_full(["src/database/testbed_docs"])

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT doc_name, chunk_text, metadata, embedding
                FROM knowledge_base
                WHERE metadata->>'source_path' LIKE %s
                ORDER BY id DESC;
                """,
                ("%metasploit_vsftpd_guide.pdf%",),
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    assert rows, "No rows for metasploit_vsftpd_guide.pdf found in knowledge_base"

    found_row = None
    for row in rows:
        doc_name, chunk_text, metadata, embedding = row
        if "vsftpd" in chunk_text.lower():
            found_row = row
            break

    assert found_row is not None, (
        "Found rows for metasploit_vsftpd_guide.pdf but none of the chunk_text "
        "mentions 'vsftpd'"
    )

    doc_name, chunk_text, metadata, embedding = found_row

    assert doc_name.endswith(".pdf")
    assert "vsftpd" in chunk_text.lower()
    assert isinstance(metadata, dict)
    assert "source_path" in metadata
    assert metadata["source_path"].endswith("metasploit_vsftpd_guide.pdf")
    assert embedding is not None

    results = await rag.retrieve(query="vsftpd 2.3.4", source="kb", top_k=5)
    kb_results = results["kb_results"]
    assert kb_results, "No kb_results returned from RAG retrieve"

    matched = [
        r
        for r in kb_results
        if r["doc_name"].endswith("metasploit_vsftpd_guide.pdf")
        and "vsftpd" in r["chunk_text"].lower()
    ]
    assert matched, (
        "RAG retrieval did not return any chunk from metasploit_vsftpd_guide.pdf "
        "that mentions 'vsftpd'"
    )
