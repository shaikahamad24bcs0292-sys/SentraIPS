"""
Executive Security Audit Report Generator for SentraIPS.
Generates strategic, C-level compliance and risk posture summaries.
Strictly follows the Phase 5 specification:
- Executive Summary
- Overall Risk
- Major Findings
- Business/Operational Impact
- Priority Recommendations
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from security_engine.findings import SecurityAssessmentReport
from knowledge_base.rag import StandardsRAGEngine
from reporting.llm_explainer import LLMExplainer, AuditNarrative


class ExecutiveReportGenerator:
    """Compiles C-level executive summary reports in structured text and Markdown."""

    def __init__(self, rag_engine: Optional[StandardsRAGEngine] = None, explainer: Optional[LLMExplainer] = None):
        self.rag = rag_engine or StandardsRAGEngine()
        self.explainer = explainer or LLMExplainer(self.rag)

    def generate_markdown(self, report: SecurityAssessmentReport) -> str:
        """Generates executive audit report in GitHub-flavored Markdown."""
        narrative: AuditNarrative = self.explainer.generate_audit_narrative(report)
        score = report.risk_score
        severity = report.severity
        tm = report.threat_matrix
        sub = report.sub_scores

        lines = [
            "# SentraIPS — Executive VPN Security Assessment Report",
            f"**Target Capture / Gateway:** `{report.capture_id}`  ",
            f"**Overall Risk Posture:** **{score} / 100 ({severity})**  ",
            f"**Audit Standard Baselines:** NIST SP 800-77 Rev. 1, RFC 7296, RFC 4301, RFC 8221  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            narrative.executive_summary,
            "",
            narrative.risk_profile_description,
            "",
            "---",
            "",
            "## 2. Overall Risk Evaluation",
            "",
            f"| Metric | Assessment Result | Baseline Standard Target |",
            f"|---|---|---|",
            f"| **Overall Risk Score** | **{score} / 100** | < 20 (LOW) |",
            f"| **Qualitative Severity** | **{severity}** | LOW |",
            f"| **Cryptography Risk Subscore** | {sub.crypto_risk} pts | 0 pts |",
            f"| **Key Exchange Risk Subscore** | {sub.key_exchange_risk} pts | 0 pts |",
            f"| **Protocol & SA Risk Subscore** | {getattr(sub, 'configuration_risk', getattr(sub, 'protocol_risk', 0))} pts | 0 pts |",
            f"| **Metadata Exposure Subscore** | {getattr(sub, 'metadata_exposure_risk', getattr(sub, 'metadata_risk', 0))} pts | <= 15 pts |",
            "",
            "---",
            "",
            "## 3. Major Findings",
            "",
            f"A total of **{tm.total_findings}** security findings were identified "
            f"(Critical: {tm.critical_count}, High: {tm.high_count}, Medium: {tm.medium_count}, Low: {tm.low_count}):",
            "",
            "| ID | Severity | Points | Rule ID | Title | Authoritative Reference |",
            "|---|---|---|---|---|---|",
        ]

        for f in tm.findings:
            fid = getattr(f, "finding_id", getattr(f, "id", "F001"))
            pts = getattr(f, "risk_contribution", getattr(f, "points", 0))
            ref_str = getattr(f, "description", getattr(f, "standard_ref", f.rule_id))
            lines.append(f"| `{fid}` | **{f.severity}** | +{pts} | `{f.rule_id}` | {f.title} | {ref_str} |")

        lines.extend([
            "",
            "---",
            "",
            "## 4. Business & Operational Impact",
            "",
            narrative.business_operational_impact,
            "",
            "### Primary Risk Drivers:",
        ])

        for driver in narrative.primary_vulnerability_drivers:
            lines.append(f"- **{driver}**")

        lines.extend([
            "",
            "---",
            "",
            "## 5. Priority Strategic Recommendations",
            "",
            "The following remediation actions are prioritized to rapidly lower enterprise risk:",
            "",
        ])

        for rec in narrative.strategic_remediation_roadmap:
            lines.append(f"- {rec}")

        lines.extend([
            "",
            "---",
            f"*{narrative.compliance_statement}*",
            "",
        ])

        return "\n".join(lines)
