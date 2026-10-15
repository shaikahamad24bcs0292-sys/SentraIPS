"""
RAG (Retrieval-Augmented Generation) & Evidence Grounding Engine for SentraIPS.
Indexes authoritative standards (NIST SP 800-77 Rev. 1, RFC 7296, RFC 4301, RFC 8221)
and retrieves verified citation evidence for security findings.
"""

from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from pydantic import BaseModel, Field
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class StandardReference(BaseModel):
    """Authoritative citation snippet retrieved from the standards knowledge base."""
    document: str
    section: str
    title: str
    excerpt: str
    relevance_score: float


class StructuredEvidenceItem(BaseModel):
    """Structured evidence object matching SentraIPS Phase 5 specification."""
    finding_id: str
    finding: str
    observed_evidence: str
    rule_id: str
    risk_contribution: int
    references: List[Dict[str, Any]] = Field(default_factory=list)
    remediation_guideline: Optional[str] = None


class KnowledgeBaseChunk:
    """Document section chunk for vector retrieval."""
    def __init__(self, doc_name: str, section: str, title: str, text: str):
        self.doc_name = doc_name
        self.document = doc_name
        self.section = section
        self.title = title
        self.text = text
        self.chunk_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', doc_name[:20])}_{re.sub(r'[^a-zA-Z0-9]', '_', section)}"
        self.full_content = f"{doc_name} {section} {title}\n{text}"


StandardsChunk = KnowledgeBaseChunk


class StandardsRAGEngine:
    """
    RAG indexing and retrieval engine operating over NIST and RFC standards.
    """

    def __init__(self, kb_dir: Optional[Path] = None):
        self.kb_dir = kb_dir or (Path(__file__).resolve().parent)
        self.chunks: List[KnowledgeBaseChunk] = []
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.tfidf_matrix: Optional[np.ndarray] = None
        self._load_and_index()

    def _load_and_index(self) -> None:
        """Parses standards files and builds TF-IDF similarity index."""
        self.chunks.clear()
        search_dirs = [self.kb_dir / "nist", self.kb_dir / "rfc"]

        for s_dir in search_dirs:
            if not s_dir.exists():
                continue
            for txt_file in s_dir.glob("*.txt"):
                try:
                    with open(txt_file, "r", encoding="utf-8", errors="replace") as f:
                        raw_text = f.read()
                    self._parse_file_chunks(txt_file.name, raw_text)
                except Exception as e:
                    print(f"[RAG] Warning: Failed to parse {txt_file}: {e}")

        if not self.chunks:
            print(f"[RAG] Warning: No standards chunks loaded from {self.kb_dir}")
            return

        corpus = [c.full_content for c in self.chunks]
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
        self.tfidf_matrix = self.vectorizer.fit_transform(corpus)

    def _parse_file_chunks(self, filename: str, content: str) -> None:
        """Splits document content into section-level knowledge chunks."""
        # Detect doc title from header banner
        header_match = re.search(r"^=+\s*\n(.*?)\n=+", content, re.DOTALL)
        if header_match:
            hdr_lines = [l.strip() for l in header_match.group(1).splitlines() if l.strip()]
            doc_name = " -- ".join(hdr_lines[:2]) if hdr_lines else filename
        else:
            doc_match = re.search(r"^([^\n]+(?:\n[^\n]+)?)\n={5,}", content)
            doc_name = doc_match.group(1).replace("\n", " -- ").strip() if doc_match else filename

        # Split on [Section X: Title] markers
        section_pattern = re.compile(r"\[(Section\s+[\d\.]+(?::[^\n\]]+)?)\]", re.IGNORECASE)
        parts = section_pattern.split(content)

        if len(parts) < 2:
            # Single chunk fallback
            self.chunks.append(KnowledgeBaseChunk(doc_name, "General", doc_name, content.strip()))
            return

        # parts[0] is header
        for i in range(1, len(parts), 2):
            sec_header = parts[i].strip()
            sec_body = parts[i + 1].strip() if (i + 1) < len(parts) else ""

            sec_num = sec_header.split(":")[0].strip()
            sec_title = sec_header.split(":", 1)[1].strip() if ":" in sec_header else sec_num

            self.chunks.append(KnowledgeBaseChunk(
                doc_name=doc_name,
                section=sec_num,
                title=sec_title,
                text=sec_body,
            ))

    def retrieve(self, query: str, top_k: int = 2) -> List[Tuple[KnowledgeBaseChunk, float]]:
        """
        Retrieves top-k KnowledgeBaseChunks paired with cosine similarity scores.
        """
        if not self.chunks or self.vectorizer is None or self.tfidf_matrix is None:
            return []

        query_vec = self.vectorizer.transform([query])
        sims = cosine_similarity(query_vec, self.tfidf_matrix).flatten()
        top_indices = np.argsort(sims)[::-1]

        results: List[Tuple[KnowledgeBaseChunk, float]] = []
        for idx in top_indices[:top_k]:
            results.append((self.chunks[idx], float(sims[idx])))
        return results

    def retrieve_evidence(self, query: str, top_k: int = 2, min_score: float = 0.10) -> List[StandardReference]:
        """
        Retrieves top-k authoritative standards references relevant to the query.
        """
        if not self.chunks or self.vectorizer is None or self.tfidf_matrix is None:
            return []

        query_vec = self.vectorizer.transform([query])
        sims = cosine_similarity(query_vec, self.tfidf_matrix).flatten()

        # Sort by similarity descending
        top_indices = np.argsort(sims)[::-1]

        results: List[StandardReference] = []
        for idx in top_indices:
            score = float(sims[idx])
            if score < min_score and len(results) > 0:
                break
            chunk = self.chunks[idx]
            # Form clean excerpt (first 250 chars)
            excerpt = chunk.text[:300].replace("\n", " ").strip()
            if len(chunk.text) > 300:
                excerpt += "..."

            results.append(StandardReference(
                document=chunk.doc_name,
                section=chunk.section,
                title=chunk.title,
                excerpt=excerpt,
                relevance_score=round(score, 4),
            ))
            if len(results) >= top_k:
                break

        return results

    def enrich_finding(self, finding: Any, top_k: int = 2) -> StructuredEvidenceItem:
        """
        Grounds a SecurityFinding in authoritative standards and generates a StructuredEvidenceItem.
        """
        rule_id = getattr(finding, "rule_id", "UNKNOWN_RULE")
        title = getattr(finding, "title", "Security Finding")
        fid = getattr(finding, "finding_id", getattr(finding, "id", "F001"))
        pts = getattr(finding, "risk_contribution", getattr(finding, "points", 0))

        ev_item = getattr(finding, "evidence", None)
        if ev_item:
            obs = f"{getattr(ev_item, 'observed_field', '')} = {getattr(ev_item, 'observed_value', '')}"
            src = getattr(ev_item, "packet_source", "PCAP traffic")
        else:
            obs = str(getattr(finding, "observed_field", ""))
            src = getattr(finding, "packet_source", "PCAP traffic")

        rec = getattr(finding, "recommendation", None)

        # Formulate search query targeting cryptographic context
        query = f"{title} {rule_id.replace('_', ' ')} {obs}"
        refs = self.retrieve_evidence(query, top_k=top_k)

        # Standard format mandated by Phase 5 specification
        ref_dicts = [
            {
                "document": r.document,
                "section": r.section,
                "title": r.title,
                "excerpt": r.excerpt,
                "relevance_score": r.relevance_score,
            }
            for r in refs
        ]

        return StructuredEvidenceItem(
            finding_id=fid,
            finding=title,
            observed_evidence=f"{obs} (Observed from {src})",
            rule_id=rule_id,
            risk_contribution=pts,
            references=ref_dicts,
            remediation_guideline=rec,
        )
