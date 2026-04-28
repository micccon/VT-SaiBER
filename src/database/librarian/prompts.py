from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Dict, List


class LibrarianPrompts:
    SYSTEM_PROMPT = """
        You are a cybersecurity research specialist.

        You receive:
        - A compact description of the current mission and target telemetry.
        - "kb_results": internal knowledge base snippets (RAG).
        - "findings_results": historical internal findings from prior workflow steps.
        - "cve_results": official CVE and KEV evidence.
        - "osint_results": external open-source intelligence results (web search, OSINT).

        Your task: Return ONE JSON object with the following fields:

        - summary (string):
        Plain-language explanation of exploit or tooling insights that are directly relevant to the mission and targets.

        - technical_params (object):
        Key-value pairs that downstream agents can act on.
        Examples: 
            - "exploit_module": "exploit/multi/http/..." 
            - "cve": "CVE-2023-XXXX"
            - "service": "http"
            - "product": "apache httpd"
            - any other structured parameters that are useful for exploitation or deeper scanning.

        - confidence (float, 0.0–1.0):
        Your overall confidence in the summary and technical_params, based on the quality and agreement of sources.

        - is_osint_derived (boolean):
        - true if your final answer relies significantly on information from osint_results.
        - false if your answer is based only on kb_results and telemetry.
        Rules:
        - If osint_results is empty, you MUST set is_osint_derived to false.
        - If you use any facts that come only from osint_results, you SHOULD set is_osint_derived to true.

        - citations (array of strings):
        Each element MUST be a compact textual reference.
        Good examples:
            - "kb:sqlmap/Usage.md"
            - "kb:vsftpd 2.3.4 Backdoor Command Execution"
            - "finding:prior-librarian-brief"
            - "cve:https://nvd.nist.gov/vuln/detail/CVE-2011-2523"
            - "osint:https://nvd.nist.gov/vuln/detail/CVE-2011-2523"
        Rules:
        - For KB-derived facts, prefix with "kb:".
        - For historical internal findings, prefix with "finding:".
        - For official CVE or KEV facts, prefix with "cve:".
        - For OSINT-derived facts, prefix with "osint:".
        - Include at least one citation for each major claim in summary or technical_params.

        - conflicting_sources (array of strings or null):
        - Describe any major disagreements between sources (for example, different versions, different CVEs, conflicting exploitability).
        - Use null if there are no notable conflicts.

        Behavior rules:
        - Prefer precise, evidence-based statements tied to the provided kb_results, findings_results, cve_results, and osint_results.
        - Prefer internal KB and finding evidence first, then official CVE evidence, then external docs.
        - If the available context is weak or partially relevant, lower the confidence score and clearly state uncertainties in the summary.
        - Do NOT execute tools. Only synthesize and cite intelligence based on the given context.
        """

    @staticmethod
    def _normalize_item(item: Any) -> Dict[str, Any]:
        if isinstance(item, dict):
            return dict(item)
        if is_dataclass(item):
            return asdict(item)
        if hasattr(item, "model_dump"):
            return item.model_dump()
        return {}

    @staticmethod
    def build_user_content(
        query: str,
        kb_results: List[Dict[str, Any]],
        osint_results: List[Dict[str, Any]],
        findings_results: List[Dict[str, Any]] | None = None,
        cve_results: List[Dict[str, Any]] | None = None,
        source_status: Dict[str, Any] | None = None,
    ) -> str:
        lines: List[str] = [f"Telemetry summary: {query}", ""]
        findings_results = findings_results or []
        cve_results = cve_results or []

        if source_status:
            lines.append("Source readiness:")
            for name, status in source_status.items():
                lines.append(f"- {name}: {status}")
            lines.append("")

        if kb_results:
            lines.append("Internal knowledge base evidence (RAG):")
            for i, r in enumerate(kb_results[:5], 1):
                normalized = LibrarianPrompts._normalize_item(r)
                doc = normalized.get("doc_name", "unknown")
                sim = float(normalized.get("score") or normalized.get("similarity") or 0.0)
                snippet = (normalized.get("chunk_text", "") or "")[:300].replace("\n", " ")
                lines.append(f"{i}. [KB:{doc}] (sim={sim:.2f}) {snippet}...")
        else:
            lines.append("No internal KB evidence retrieved.")

        if findings_results:
            lines.append("")
            lines.append("Historical internal findings:")
            for i, finding in enumerate(findings_results[:5], 1):
                normalized = LibrarianPrompts._normalize_item(finding)
                title = normalized.get("title", "unknown")
                score = float(normalized.get("score") or normalized.get("similarity") or 0.0)
                snippet = (normalized.get("description", "") or "")[:220].replace("\n", " ")
                lines.append(f"{i}. [FINDING:{title}] (score={score:.2f}) {snippet}...")

        if cve_results:
            lines.append("")
            lines.append("Official CVE / KEV evidence:")
            for i, cve in enumerate(cve_results[:5], 1):
                normalized = LibrarianPrompts._normalize_item(cve)
                title = normalized.get("title") or normalized.get("identifier") or "unknown"
                reference = normalized.get("reference", "unknown")
                snippet = (normalized.get("snippet", "") or normalized.get("summary", "") or "")[:260].replace("\n", " ")
                lines.append(f"{i}. [CVE:{title}] {reference} {snippet}...")

        if osint_results:
            lines.append("")
            lines.append("External OSINT evidence:")
            for i, o in enumerate(osint_results[:5], 1):
                normalized = LibrarianPrompts._normalize_item(o)
                title = normalized.get("title", "unknown")
                url = normalized.get("url", normalized.get("reference", "unknown"))
                snippet = (normalized.get("snippet", "") or "")[:200].replace("\n", " ")
                lines.append(f"{i}. [OSINT:{title}] {url} {snippet}...")

        lines.append("")
        lines.append("Based on the above, produce a single JSON object as specified.")
        return "\n".join(lines)
