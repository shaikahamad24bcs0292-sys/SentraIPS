"""
Automated unit tests for StandardsRAGEngine and Knowledge Base Retrieval.
Validates chunking, TF-IDF retrieval, ranking, and structured evidence attachment.
"""

import pytest
from pathlib import Path
from knowledge_base.rag import StandardsRAGEngine, StandardsChunk, StructuredEvidenceItem
from security_engine.findings import SecurityFinding, EvidenceItem


@pytest.fixture(scope="module")
def rag_engine():
    """Initializes and caches the RAG engine across module tests."""
    return StandardsRAGEngine()


def test_rag_knowledge_base_loading(rag_engine):
    """Verifies that standards chunks are properly loaded and indexed from NIST and RFC documents."""
    assert len(rag_engine.chunks) > 0, "RAG engine should load and index chunks from knowledge base."
    
    # Verify both NIST and RFC documents are present in index
    doc_types = {chunk.document for chunk in rag_engine.chunks}
    assert any("800-77" in doc for doc in doc_types), "NIST SP 800-77 Rev. 1 chunks must be indexed."
    assert any("RFC 7296" in doc for doc in doc_types), "RFC 7296 chunks must be indexed."
    assert any("RFC 4301" in doc for doc in doc_types), "RFC 4301 chunks must be indexed."
    assert any("RFC 8221" in doc for doc in doc_types), "RFC 8221 chunks must be indexed."


def test_rag_chunk_metadata_integrity(rag_engine):
    """Verifies that all indexed chunks have non-empty text, document, and section IDs."""
    for chunk in rag_engine.chunks:
        assert chunk.chunk_id, "Chunk ID must be non-empty"
        assert chunk.document, "Document name must be non-empty"
        assert chunk.section, "Section reference must be non-empty"
        assert chunk.title, "Chunk title must be non-empty"
        assert len(chunk.text.strip()) > 30, f"Chunk {chunk.chunk_id} content must be substantial"


def test_rag_crypto_query_retrieval(rag_engine):
    """Tests retrieval precision for legacy symmetric cipher queries."""
    results = rag_engine.retrieve("AES CBC mode 3DES legacy encryption security", top_k=3)
    assert len(results) >= 1
    
    # Top result should have positive relevance score
    top_chunk, score = results[0]
    assert score > 0.1, f"Relevance score {score} should indicate meaningful match"
    
    # Excerpt should mention crypto or cipher concepts
    combined_text = " ".join(c.text.lower() for c, _ in results)
    assert any(term in combined_text for term in ["aead", "gcm", "cbc", "cipher", "encryption"])


def test_rag_diffie_hellman_query_retrieval(rag_engine):
    """Tests retrieval precision for Diffie-Hellman key exchange weakness queries."""
    results = rag_engine.retrieve("Diffie Hellman Group 5 1024-bit discrete logarithm weak", top_k=3)
    assert len(results) >= 1
    
    top_chunk, score = results[0]
    assert score > 0.05
    combined_text = " ".join(c.text.lower() for c, _ in results)
    assert any(term in combined_text for term in ["diffie-hellman", "dh", "group 14", "group 19", "group 5", "group 2"])


def test_rag_pfs_query_retrieval(rag_engine):
    """Tests retrieval precision for Perfect Forward Secrecy queries."""
    results = rag_engine.retrieve("Perfect Forward Secrecy PFS child SA renegotiation", top_k=3)
    assert len(results) >= 1
    
    combined_text = " ".join(c.text.lower() for c, _ in results)
    assert any(term in combined_text for term in ["forward secrecy", "pfs", "child sa", "diffie-hellman"])


def test_rag_enrich_finding(rag_engine):
    """Verifies that enrich_finding creates a complete StructuredEvidenceItem with references."""
    sample_finding = SecurityFinding(
        finding_id="FIND-DH-001",
        rule_id="RULE-DH-GRP5",
        title="Weak Diffie-Hellman Group 5 (1024-bit MODP)",
        category="Key Exchange",
        severity="HIGH",
        risk_contribution=25,
        evidence=EvidenceItem(
            observed_field="dh_group",
            observed_value=5,
            packet_source="IKE_SA_INIT Transform Attribute (Type 4)",
            rule_criterion="Group < 14 (MODP < 2048-bit)",
        ),
        description="Diffie-Hellman Group 5 offers only ~80 bits of symmetric equivalent security.",
        recommendation="Migrate to DH Group 14 (2048-bit MODP) or Group 19 (256-bit ECP).",
    )
    
    structured_ev = rag_engine.enrich_finding(sample_finding, top_k=2)
    assert isinstance(structured_ev, StructuredEvidenceItem)
    assert structured_ev.finding_id == "FIND-DH-001"
    assert structured_ev.rule_id == "RULE-DH-GRP5"
    assert structured_ev.risk_contribution == 25
    assert len(structured_ev.references) >= 1
    
    first_ref = structured_ev.references[0]
    assert "document" in first_ref
    assert "section" in first_ref
    assert "relevance_score" in first_ref
    assert "excerpt" in first_ref
