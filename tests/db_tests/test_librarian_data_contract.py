import pytest

from src.agents.librarian import LibrarianAgent
from src.database.librarian.prompts import LibrarianPrompts


@pytest.mark.asyncio
async def test_librarian_normalizes_object_citations(monkeypatch):
    agent = LibrarianAgent()

    class _FakeLLM:
        async def ainvoke(self, *_args, **_kwargs):
            return {
                "content": """
                {
                  "summary": "Use the documented exploit path.",
                  "technical_params": {"exploit_module": "exploit/test/module"},
                  "confidence": 0.91,
                  "is_osint_derived": false,
                  "citations": [
                    {"source": "kb", "reference": "sqlmap/Usage.md"},
                    {"source": "osint", "reference": "https://example.com/advisory"}
                  ],
                  "conflicting_sources": null
                }
                """
            }

    agent._llm = _FakeLLM()
    agent._client = agent._llm

    brief = await agent._research_brief(
        "test query",
        rag_results=[{"doc_name": "sqlmap/Usage.md", "chunk_text": "example"}],
        osint_results=[],
    )

    assert brief.citations == [
        "kb:sqlmap/Usage.md",
        "osint:https://example.com/advisory",
    ]


def test_librarian_prompt_uses_normalized_osint_snippet():
    content = LibrarianPrompts.build_user_content(
        "test query",
        kb_results=[],
        osint_results=[
            {
                "title": "Advisory",
                "url": "https://example.com/advisory",
                "snippet": "This OSINT snippet should be present.",
            }
        ],
    )

    assert "This OSINT snippet should be present." in content
