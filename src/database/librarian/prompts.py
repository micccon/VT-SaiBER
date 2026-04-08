from typing import Any, Dict, List


class LibrarianPrompts:
    SYSTEM_PROMPT = """You are a cybersecurity research specialist.
You receive:
- A compact description of the current mission and target telemetry.
- Retrieved knowledge base snippets and OSINT results.

Your task: Return ONE JSON object with:
- summary (string): Plain-language explanation of exploit/tool insights.
- technical_params (dict): Key-value pairs (e.g., 'exploit_module': '...', 'cve': '...').
- is_osint_derived (boolean): True if the answer is from external OSINT.
- confidence (float 0..1): Confidence in the summary and params.
- citations (array): URLs or internal source identifiers.
- conflicting_sources (array or null): Any notable conflicts in sources.

Do NOT execute tools. Only provide cited intelligence based on the given context."""

    @staticmethod
    def build_user_content(
        query: str,
        kb_results: List[Dict[str, Any]],
        osint_results: List[Dict[str, Any]],
    ) -> str:
        lines: List[str] = [f"Telemetry summary: {query}", ""]

        # RAG 
        if kb_results:
            lines.append("Internal knowledge base evidence (RAG):")
            for i, r in enumerate(kb_results[:5], 1):
                doc = r.get("doc_name", "unknown")
                sim = r.get("similarity", 0.0)
                snippet = (r.get("chunk_text", "") or "")[:300].replace("\n", " ")
                lines.append(f"{i}. [KB:{doc}] (sim={sim:.2f}) {snippet}...")
        else:
            lines.append("No internal KB evidence retrieved.")

        # OSINT 
        if osint_results:
            lines.append("")
            lines.append("External OSINT evidence:")
            for i, o in enumerate(osint_results[:5], 1):
                title = o.get("title", "unknown")
                url = o.get("url", "unknown")
                snippet = (o.get("content", "") or "")[:200].replace("\n", " ")
                lines.append(f"{i}. [OSINT:{title}] {url} {snippet}...")

        lines.append("")
        lines.append("Based on the above, produce a single JSON object as specified.")
        return "\n".join(lines)