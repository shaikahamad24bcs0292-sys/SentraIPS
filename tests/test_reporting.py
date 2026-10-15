"""
Automated unit and integration tests for SentraIPS Reporting System (Phase 5).
Validates Executive report, 13-section Technical report, LLM explainer guardrails, and PDF generation.
"""

from pathlib import Path
import pytest
from security_engine import SecurityEngine, SecurityAssessmentReport
from knowledge_base.rag import StandardsRAGEngine
from reporting.llm_explainer import LLMExplainer, FindingExplanation, AuditNarrative
from reporting.executive_report import ExecutiveReportGenerator
from reporting.technical_report import TechnicalReportGenerator
from reporting.pdf_generator import PDFReportGenerator


@pytest.fixture(scope="module")
def weak_pcap_path(project_root: Path) -> Path:
    pcap = project_root / "demo_data" / "weak_capture.pcap"
    assert pcap.exists(), "weak_capture.pcap must exist for testing"
    return pcap


@pytest.fixture(scope="module")
def assessment_report(project_root: Path, weak_pcap_path: Path) -> SecurityAssessmentReport:
    config_file = project_root / "security_engine" / "config.yaml"
    engine = SecurityEngine(config_path=config_file)
    return engine.assess_pcap_file(weak_pcap_path)


@pytest.fixture(scope="module")
def rag_engine() -> StandardsRAGEngine:
    return StandardsRAGEngine()


@pytest.fixture(scope="module")
def explainer(rag_engine: StandardsRAGEngine) -> LLMExplainer:
    return LLMExplainer(rag_engine=rag_engine)


def test_llm_explainer_single_finding(explainer: LLMExplainer, rag_engine: StandardsRAGEngine, assessment_report: SecurityAssessmentReport):
    """Verifies that LLMExplainer produces structured, authoritative explanations for findings."""
    assert len(assessment_report.threat_matrix.findings) > 0
    finding = assessment_report.threat_matrix.findings[0]
    
    evidence = rag_engine.enrich_finding(finding)
    explanation = explainer.explain_finding(finding, evidence)
    
    assert isinstance(explanation, FindingExplanation)
    assert len(explanation.technical_explanation.strip()) > 20
    assert len(explanation.business_impact.strip()) > 20
    assert len(explanation.authoritative_basis.strip()) > 20
    assert len(explanation.recommended_action.strip()) > 20


def test_llm_explainer_audit_narrative(explainer: LLMExplainer, assessment_report: SecurityAssessmentReport):
    """Verifies that audit narrative preserves the deterministic risk score without altering it."""
    original_score = assessment_report.risk_score
    original_severity = assessment_report.severity
    
    narrative = explainer.generate_audit_narrative(assessment_report)
    
    assert isinstance(narrative, AuditNarrative)
    assert len(narrative.executive_summary.strip()) > 30
    assert str(original_score) in narrative.executive_summary or str(original_score) in narrative.risk_profile_description
    assert len(narrative.strategic_recommendations) > 0
    
    # Bounded LLM guardrail: Report risk score must be strictly unchanged
    assert assessment_report.risk_score == original_score
    assert assessment_report.severity == original_severity


def test_executive_report_markdown_generation(assessment_report: SecurityAssessmentReport, rag_engine: StandardsRAGEngine, explainer: LLMExplainer):
    """Verifies Executive report markdown structure, headings, and metric tables."""
    gen = ExecutiveReportGenerator(rag_engine=rag_engine, explainer=explainer)
    md = gen.generate_markdown(assessment_report)
    
    assert isinstance(md, str)
    assert len(md) > 500
    assert "# SentraIPS" in md
    assert "Executive Summary" in md
    assert "Overall Risk Evaluation" in md
    assert "Major Findings" in md
    assert "Business & Operational Impact" in md
    assert "Priority Strategic Recommendations" in md
    assert f"{assessment_report.risk_score} / 100" in md


def test_technical_report_thirteen_sections(assessment_report: SecurityAssessmentReport, rag_engine: StandardsRAGEngine, explainer: LLMExplainer):
    """Verifies Technical report contains all 13 required audit sections."""
    gen = TechnicalReportGenerator(rag_engine=rag_engine, explainer=explainer)
    md = gen.generate_markdown(assessment_report)
    
    required_sections = [
        "## 1. Capture Information",
        "## 2. VPN Configuration",
        "## 3. IKE Analysis",
        "## 4. ESP Analysis",
        "## 5. AI Traffic Inference",
        "## 6. Security Findings",
        "## 7. Risk Score",
        "## 8. Threat Matrix",
        "## 9. Evidence",
        "## 10. NIST/RFC References",
        "## 11. Recommendations",
        "## 12. AI Confidence",
        "## 13. Limitations",
    ]
    
    for section in required_sections:
        assert section in md, f"Missing required section: {section}"


def test_pdf_report_generation(tmp_path: Path, assessment_report: SecurityAssessmentReport, rag_engine: StandardsRAGEngine, explainer: LLMExplainer):
    """Verifies that PDF generator produces a valid binary PDF file."""
    output_pdf = tmp_path / "test_audit_report.pdf"
    
    pdf_gen = PDFReportGenerator(rag_engine=rag_engine, explainer=explainer)
    result_path = pdf_gen.generate_pdf(assessment_report, output_pdf=output_pdf)
    
    assert result_path.exists(), "Generated PDF file must exist"
    file_size = result_path.stat().st_size
    assert file_size > 2000, f"Generated PDF should be substantial (>2000 bytes), got {file_size}"
    
    with open(result_path, "rb") as f:
        header = f.read(5)
    assert header == b"%PDF-", f"File must start with standard PDF magic bytes '%PDF-', got {header}"
