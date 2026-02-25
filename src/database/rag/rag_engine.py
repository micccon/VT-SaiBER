# src/database/rag/rag_engine.py

"""
RAG Orchestrator Module
Main entry point coordinating all RAG sub-modules (embedding, indexing, retrieval).
Provides high-level API for agents and CLI tools.
"""

from typing import Optional, Dict, Any, List
from .embedding import EmbeddingClient
from .chunking import ChunkingStrategy, simple_chunking
from .indexing import IndexingPipeline
from .retriever import RAGRetriever

class RAGOrchestrator:
    
    def __init__(self):
        """Initialize all RAG components"""
        self.embedding_client = EmbeddingClient()
        self.chunking_strategy = simple_chunking
        self.indexing_pipeline = IndexingPipeline(
            embedding_client=self.embedding_client,
            chunking_strategy=self.chunking_strategy
        )
        self.retriever = RAGRetriever(
            embedding_client=self.embedding_client
        )
    
    # ===== Offline Pipeline =====
    
    async def index_knowledge_base_full(self, source_dirs: List[str]):
        """
        Full indexing: clear old data and re-index all files
        Suitable for: initial setup
        """
        print("[RAG] Starting full knowledge base indexing...")
        await self.indexing_pipeline.index_documents(
            source_paths=source_dirs,
            mode="full"
        )
        print("[RAG] Knowledge base indexing completed")
    
    async def index_knowledge_base_incremental(self, source_dirs: List[str]):
        """
        Incremental indexing: only index new/modified files
        Suitable for: periodic updates
        """
        print("[RAG] Starting incremental knowledge base indexing...")
        await self.indexing_pipeline.index_documents(
            source_paths=source_dirs,
            mode="incremental"
        )
        print("[RAG] Incremental indexing completed")
    
    # ===== Online Pipeline =====
    
    async def retrieve(self, 
                      query: str, 
                      source: str = "both",
                      top_k: int = 5,
                      filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Unified query interface
        
        Args:
            query: Query text
            source: "kb" (knowledge base) / "findings" (historical) / "both" (both)
            top_k: Number of results to return
            filters: Metadata filters
        
        Returns:
            {
                "kb_results": [...],          # Knowledge base results (if source includes kb)
                "findings_results": [...],    # Historical findings results (if source includes findings)
                "combined": [...]             # Combined results
            }
        """
        results = {}
        
        # Query knowledge base
        if source in ["kb", "both"]:
            kb_results = await self.retriever.retrieve_from_kb(
                query=query,
                top_k=top_k,
                filters=filters
            )
            results["kb_results"] = kb_results
        else:
            results["kb_results"] = []
        
        # Query historical findings
        if source in ["findings", "both"]:
            finding_results = await self.retriever.retrieve_from_findings(
                query=query,
                top_k=top_k,
                filters=filters
            )
            results["findings_results"] = finding_results
        else:
            results["findings_results"] = []
        
        # Combine all results
        results["combined"] = results["kb_results"] + results["findings_results"]
        
        return results
    
    # ===== Convenience Methods =====
    
    async def research(self, 
                      query: str,
                      include_history: bool = True) -> str:
        """
        High-level research interface (for Librarian)
        Returns formatted research results
        """
        source = "both" if include_history else "kb"
        
        results = await self.retrieve(query=query, source=source)
        
        formatted = self._format_research_results(
            query=query,
            results=results
        )
        
        return formatted
    
    def _format_research_results(self, query: str, results: Dict) -> str:
        """Format RAG results into a readable research report"""
        
        report = f"""
        === RAG Research Results for: "{query}" ===

        Knowledge Base Results:
        """
        for i, kb_result in enumerate(results["kb_results"], 1):
            report += f"""{i}. Source: {kb_result['source']}
                            Similarity: {kb_result['similarity']:.2f}
                            Text: {kb_result['chunk_text'][:200]}...
                        """
        
        if results["findings_results"]:
            report += "\n\nHistorical Findings:\n"
            for i, finding in enumerate(results["findings_results"], 1):
                report += f"""
                            {i}. {finding['title']} ({finding['severity']})
                            Target: {finding['target_ip']}
                            Similarity: {finding['similarity']:.2f}
                            """
        
        return report
    
    # ===== Lifecycle Management =====
    
    async def health_check(self) -> Dict[str, Any]:
        try:
            # Test Embedding API
            test_embedding = await self.embedding_client.embed_text("test")
            embedding_ok = len(test_embedding) == 1536
            
            # Test database connectionFF
            from src.database import manager
            db_ok = manager.test_connection() is not None
            
            return {
                "status": "healthy" if (embedding_ok and db_ok) else "unhealthy",
                "embedding_client": "ok" if embedding_ok else "failed",
                "database": "ok" if db_ok else "failed"
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }