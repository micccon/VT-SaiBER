"""
Online retrieval and reranking for the VT-SaiBER RAG layer.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from src.config import get_runtime_config
from src.database.findings_repository import search_findings_text, search_similar_findings

from .embedding import EmbeddingClient
from .rag_manager import search_by_embedding, search_by_text


class RAGRetriever:
    def __init__(self, embedding_client: EmbeddingClient):
        """Create a retriever around the configured embedding client."""

        self.embedding_client = embedding_client
        self.config = get_runtime_config()

    async def retrieve(
        self,
        query: str,
        source: str = "both",
        top_k: int = 5,
        filters: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Retrieve KB and/or finding rows, preferring vectors with lexical fallback."""

        results: Dict[str, Any] = {}
        query_embedding = await self._get_query_embedding(query)
        kb_filters = dict(filters or {})
        findings_filters = dict(filters or {})
        provenance = self.embedding_client.provenance_tag()
        if provenance:
            # KB chunks are filtered to the active embedding provenance to avoid mixed vector spaces.
            kb_filters.setdefault("embedding_provenance", provenance)

        if source in ["kb", "both"]:
            results["kb_results"] = await self.retrieve_from_kb(
                query=query,
                top_k=top_k,
                filters=kb_filters,
                query_embedding=query_embedding,
            )
        else:
            results["kb_results"] = []

        if source in ["findings", "both"]:
            results["findings_results"] = await self.retrieve_from_findings(
                query=query,
                top_k=top_k,
                filters=findings_filters,
                query_embedding=query_embedding,
            )
        else:
            results["findings_results"] = []

        results["combined"] = sorted(
            results["kb_results"] + results["findings_results"],
            key=lambda item: float(item.get("score") or item.get("similarity") or 0.0),
            reverse=True,
        )
        return results

    async def retrieve_from_kb(
        self,
        query: str,
        top_k: int = 5,
        filters: Dict[str, Any] | None = None,
        query_embedding: List[float] | None = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve KB evidence by vector similarity, falling back to lexical search."""

        if query_embedding is None:
            # Missing embeddings should degrade retrieval, not block the librarian.
            rows = search_by_text(query, top_k=top_k, filters=filters)
            return self._rerank_kb_results(query, rows, top_k=top_k)
        fetch_k = max(int(top_k) * 3, self.config.rag_kb_fetch_k)
        rows = search_by_embedding(
            query_embedding,
            top_k=fetch_k,
            filters=filters,
            min_similarity=self.config.rag_kb_similarity_threshold,
        )
        if not rows:
            # Empty vector results may indicate stale provenance or a narrow threshold.
            rows = search_by_text(query, top_k=top_k, filters=filters)
        return self._rerank_kb_results(query, rows, top_k=top_k)

    async def retrieve_from_findings(
        self,
        query: str,
        top_k: int = 5,
        filters: Dict[str, Any] | None = None,
        query_embedding: List[float] | None = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve historical finding evidence by vector similarity or lexical search."""

        if query_embedding is None:
            rows = search_findings_text(query, limit=top_k, filters=filters)
            return self._rerank_findings_results(rows, top_k=top_k)
        fetch_k = max(int(top_k) * 3, self.config.rag_findings_fetch_k)
        rows = search_similar_findings(
            embedding_vector=query_embedding,
            limit=fetch_k,
            threshold=self.config.rag_findings_similarity_threshold,
            filters=filters,
            embedding_model=self.embedding_client.provenance_tag(),
        )
        if not rows:
            rows = search_findings_text(query, limit=top_k, filters=filters)
        return self._rerank_findings_results(rows, top_k=top_k)

    async def _get_query_embedding(self, query: str) -> List[float] | None:
        """Best-effort query embedding; callers handle None as lexical fallback."""

        if not self.embedding_client.is_available():
            return None
        try:
            return await self.embedding_client.embed_text(query)
        except Exception:
            return None

    def _rerank_kb_results(
        self,
        query: str,
        rows: List[Dict[str, Any]],
        *,
        top_k: int,
    ) -> List[Dict[str, Any]]:
        """Apply lightweight KB-specific boosts and per-document diversity limits."""

        query_terms = self._extract_query_terms(query)
        rescored: List[Dict[str, Any]] = []
        chunks_per_doc: Dict[str, int] = {}

        for row in rows:
            metadata = dict(row.get("metadata") or {})
            doc_name = str(row.get("doc_name") or "")
            rel_path = str(metadata.get("rel_path") or "")
            tool = str(metadata.get("tool") or "")
            haystack = " ".join([doc_name.lower(), rel_path.lower(), tool.lower()])

            score = float(row.get("similarity") or 0.0)
            matched_terms = sum(1 for term in query_terms if term in haystack)
            if matched_terms:
                # Slightly reward filename/tool matches because they are usually more precise.
                score += min(0.12, 0.03 * matched_terms)
            if tool and any(term == tool.lower() for term in query_terms):
                score += 0.05

            doc_bucket = doc_name or rel_path or "unknown"
            row_with_score = dict(row)
            row_with_score["score"] = round(score, 6)
            row_with_score["matched_terms"] = matched_terms

            if chunks_per_doc.get(doc_bucket, 0) >= self.config.rag_max_chunks_per_doc:
                continue
            chunks_per_doc[doc_bucket] = chunks_per_doc.get(doc_bucket, 0) + 1
            rescored.append(row_with_score)

        rescored.sort(key=lambda item: float(item.get("score") or 0.0), reverse=True)
        return rescored[:top_k]

    def _rerank_findings_results(
        self,
        rows: List[Dict[str, Any]],
        *,
        top_k: int,
    ) -> List[Dict[str, Any]]:
        """Apply severity and freshness boosts to historical findings."""

        rescored: List[Dict[str, Any]] = []
        for row in rows:
            score = float(row.get("similarity") or 0.0)
            severity = str(row.get("severity") or "").lower()
            if severity == "critical":
                score += 0.08
            elif severity == "high":
                score += 0.05
            elif severity == "medium":
                score += 0.02

            created_at = row.get("created_at")
            if created_at is not None:
                # Recent findings are more likely to reflect the current mission state.
                age_days = self._age_in_days(created_at)
                if age_days <= 7:
                    score += 0.04
                elif age_days <= 30:
                    score += 0.02

            row_with_score = dict(row)
            row_with_score["score"] = round(score, 6)
            rescored.append(row_with_score)

        rescored.sort(key=lambda item: float(item.get("score") or 0.0), reverse=True)
        return rescored[:top_k]

    def _extract_query_terms(self, query: str) -> List[str]:
        """Extract simple unique terms for transparent reranking boosts."""

        terms = []
        for token in str(query or "").lower().replace("/", " ").replace("_", " ").split():
            token = token.strip(" ,.:;()[]{}")
            if len(token) >= 3 and token not in terms:
                terms.append(token)
        return terms

    def _age_in_days(self, value: Any) -> int:
        """Normalize string/datetime timestamps into whole-day ages."""

        if isinstance(value, str):
            parsed = datetime.fromisoformat(value)
        else:
            parsed = value
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0, int((datetime.now(timezone.utc) - parsed).total_seconds() // 86400))
