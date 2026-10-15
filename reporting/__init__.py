"""
SentraIPS Reporting & Explainability Package (Phase 5).
Provides automated JSON and HTML security reports, compliance evaluation,
RAG evidence grounding, LLM explainability narratives, and PDF generation.
"""

from reporting.report_schema import (
    ReportExecutiveSummary,
    ReportVPNConfiguration,
    ReportTrafficAnalysis,
    ReportFinding,
    ReportComplianceItem,
    ReportRecommendation,
    SecurityAssessmentReportUnified,
)
from reporting.json_report import JSONReportGenerator
from reporting.html_report import HTMLReportGenerator
from reporting.report_generator import ReportGenerator

# Existing Phase 5/6 legacy reporting engines
from reporting.llm_explainer import LLMExplainer, FindingExplanation, AuditNarrative
from reporting.executive_report import ExecutiveReportGenerator
from reporting.technical_report import TechnicalReportGenerator
from reporting.pdf_generator import PDFReportGenerator

__all__ = [
    "ReportGenerator",
    "JSONReportGenerator",
    "HTMLReportGenerator",
    "SecurityAssessmentReportUnified",
    "ReportExecutiveSummary",
    "ReportVPNConfiguration",
    "ReportTrafficAnalysis",
    "ReportFinding",
    "ReportComplianceItem",
    "ReportRecommendation",
    "LLMExplainer",
    "FindingExplanation",
    "AuditNarrative",
    "ExecutiveReportGenerator",
    "TechnicalReportGenerator",
    "PDFReportGenerator",
]
