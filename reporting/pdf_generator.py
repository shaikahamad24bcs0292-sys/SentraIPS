"""
Professional PDF Audit Report Generator for SentraIPS.
Uses ReportLab to generate publication-grade executive and technical PDF reports.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)

from security_engine.findings import SecurityAssessmentReport
from knowledge_base.rag import StandardsRAGEngine
from reporting.llm_explainer import LLMExplainer


class PDFReportGenerator:
    """Generates visual, high-quality cybersecurity audit reports in PDF format."""

    def __init__(self, rag_engine: Optional[StandardsRAGEngine] = None, explainer: Optional[LLMExplainer] = None):
        self.rag = rag_engine or StandardsRAGEngine()
        self.explainer = explainer or LLMExplainer(self.rag)

    def generate_pdf(
        self,
        report: SecurityAssessmentReport,
        output_path: Optional[Union[str, Path]] = None,
        output_pdf: Optional[Union[str, Path]] = None,
        parsed_pcap: Optional[Any] = None,
        traffic_inference: Optional[Any] = None,
    ) -> Path:
        """
        Builds and saves professional multi-page PDF audit report.
        """
        target = output_path or output_pdf
        if target is None:
            raise ValueError("output_path or output_pdf must be provided")
        out_file = Path(target)
        out_file.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(out_file),
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40,
        )

        styles = getSampleStyleSheet()

        # Custom Palette
        primary_color = colors.HexColor("#1A365D")    # Dark Navy
        secondary_color = colors.HexColor("#2B6CB0")  # Slate Blue
        text_dark = colors.HexColor("#2D3748")
        bg_light = colors.HexColor("#F7FAFC")
        border_color = colors.HexColor("#E2E8F0")

        # Severity Colors
        sev_colors = {
            "CRITICAL": colors.HexColor("#9B2C2C"),
            "HIGH": colors.HexColor("#C53030"),
            "MEDIUM": colors.HexColor("#DD6B20"),
            "LOW": colors.HexColor("#2F855A"),
        }

        # Custom Typography Styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=primary_color,
            spaceAfter=6,
        )

        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#718096"),
            spaceAfter=15,
        )

        h1_style = ParagraphStyle(
            "Heading1_Custom",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=primary_color,
            spaceBefore=14,
            spaceAfter=8,
        )

        h2_style = ParagraphStyle(
            "Heading2_Custom",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=secondary_color,
            spaceBefore=10,
            spaceAfter=4,
        )

        body_style = ParagraphStyle(
            "Body_Custom",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=text_dark,
            spaceAfter=6,
        )

        callout_style = ParagraphStyle(
            "Callout",
            parent=styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#4A5568"),
        )

        table_header_style = ParagraphStyle(
            "TableHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=colors.white,
        )

        table_cell_style = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=text_dark,
        )

        story = []

        # 1. Header Banner & Title
        story.append(Paragraph("SentraIPS — VPN Security Audit Report", title_style))
        story.append(Paragraph(
            "AI-Driven IPsec VPN Cryptographic Security & Protocol Assessment Platform<br/>"
            "Smart India Hackathon 2026 Internal Evaluation Prototype",
            subtitle_style,
        ))
        story.append(HRFlowable(width="100%", thickness=2, color=primary_color, spaceAfter=15))

        # 2. Executive Scorecard Box
        narrative = self.explainer.generate_audit_narrative(report)
        score = report.risk_score
        severity = report.severity
        badge_color = sev_colors.get(severity, primary_color)

        score_data = [
            [
                Paragraph(f"<b>Overall Risk Score:</b> <font color='{badge_color.hexval()}'><b>{score} / 100</b></font>", body_style),
                Paragraph(f"<b>Qualitative Severity:</b> <font color='{badge_color.hexval()}'><b>{severity}</b></font>", body_style),
                Paragraph(f"<b>Audit Target:</b> {report.capture_id}", body_style),
            ],
            [
                Paragraph(f"<b>Total Findings:</b> {report.threat_matrix.total_findings}", body_style),
                Paragraph(f"<b>Critical/High:</b> {report.threat_matrix.critical_count + report.threat_matrix.high_count}", body_style),
                Paragraph(f"<b>Compliance Baseline:</b> NIST SP 800-77 / RFC 8221", body_style),
            ],
        ]

        score_table = Table(score_data, colWidths=[180, 180, 170])
        score_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg_light),
            ("BOX", (0, 0), (-1, -1), 1, border_color),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, border_color),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 12))

        # 3. Executive Summary
        story.append(Paragraph("1. Executive Summary", h1_style))
        story.append(Paragraph(narrative.executive_summary, body_style))
        story.append(Paragraph(narrative.risk_profile_description, body_style))

        # 4. Threat Matrix & Findings Table
        story.append(Spacer(1, 8))
        story.append(Paragraph("2. Evaluated Threat Matrix", h1_style))

        tm_headers = [
            Paragraph("ID", table_header_style),
            Paragraph("Severity", table_header_style),
            Paragraph("Risk", table_header_style),
            Paragraph("Rule ID", table_header_style),
            Paragraph("Title & Observed Parameter", table_header_style),
        ]
        tm_rows = [tm_headers]

        for f in report.threat_matrix.findings:
            row_sev_color = sev_colors.get(f.severity, text_dark)
            fid = getattr(f, "finding_id", getattr(f, "id", "F001"))
            pts = getattr(f, "risk_contribution", getattr(f, "points", 0))
            ev_item = getattr(f, "evidence", None)
            if ev_item:
                obs = f"{getattr(ev_item, 'observed_field', '')} = {getattr(ev_item, 'observed_value', '')}"
            else:
                obs = getattr(f, "observed_field", "")

            tm_rows.append([
                Paragraph(fid, table_cell_style),
                Paragraph(f"<font color='{row_sev_color.hexval()}'><b>{f.severity}</b></font>", table_cell_style),
                Paragraph(f"+{pts}", table_cell_style),
                Paragraph(f.rule_id, table_cell_style),
                Paragraph(f"<b>{f.title}</b><br/>Observed: <i>{obs}</i>", table_cell_style),
            ])

        tm_table = Table(tm_rows, colWidths=[35, 60, 40, 160, 235])
        tm_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), primary_color),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, bg_light]),
            ("BOX", (0, 0), (-1, -1), 0.5, border_color),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, border_color),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(tm_table)

        # 5. AI Traffic Inference Section (Phase 4 Integration)
        story.append(Spacer(1, 10))
        story.append(Paragraph("3. AI Traffic Inference & Uncertainty Diagnostics", h1_style))

        inf_pred = "N/A"
        inf_status = "N/A"
        inf_conf = "N/A"
        cnn_pred = "N/A"
        rf_pred = "N/A"

        if traffic_inference:
            inf_pred = getattr(traffic_inference, "final_prediction", traffic_inference.get("final_prediction", "N/A") if isinstance(traffic_inference, dict) else "N/A")
            inf_status = getattr(traffic_inference, "status", traffic_inference.get("status", "N/A") if isinstance(traffic_inference, dict) else "N/A")
            conf_val = getattr(traffic_inference, "final_confidence", traffic_inference.get("final_confidence", None) if isinstance(traffic_inference, dict) else None)
            inf_conf = f"{conf_val:.1%}" if conf_val is not None else "N/A (Disagreement Signal)"
            cnn_pred = getattr(traffic_inference, "cnn_prediction", traffic_inference.get("cnn_prediction", "N/A") if isinstance(traffic_inference, dict) else "N/A")
            rf_pred = getattr(traffic_inference, "statistical_prediction", traffic_inference.get("statistical_prediction", "N/A") if isinstance(traffic_inference, dict) else "N/A")

        ai_data = [
            [
                Paragraph("<b>Ensemble Classification:</b>", body_style),
                Paragraph(f"<b>{inf_pred}</b> (Status: <u>{inf_status.upper()}</u>)", body_style),
            ],
            [
                Paragraph("<b>1D-CNN Temporal Model:</b>", body_style),
                Paragraph(f"{cnn_pred}", body_style),
            ],
            [
                Paragraph("<b>Random Forest Stat Model:</b>", body_style),
                Paragraph(f"{rf_pred}", body_style),
            ],
            [
                Paragraph("<b>Ensemble Confidence:</b>", body_style),
                Paragraph(f"{inf_conf}", body_style),
            ],
        ]
        ai_table = Table(ai_data, colWidths=[180, 350])
        ai_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg_light),
            ("BOX", (0, 0), (-1, -1), 0.5, border_color),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, border_color),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(ai_table)

        # 6. Auditable Evidence & Standards Grounding
        story.append(Spacer(1, 10))
        story.append(Paragraph("4. Grounded Standards Evidence (NIST / RFC RAG)", h1_style))

        for f in report.threat_matrix.findings:
            ev = self.rag.enrich_finding(f)
            exp = self.explainer.explain_finding(f, ev)

            ref_summary = ""
            for r in ev.references[:1]:
                ref_summary = f"<i>{r.get('document')} ({r.get('section')})</i>: \"{r.get('excerpt')}\""

            fid = getattr(f, "finding_id", getattr(f, "id", "F001"))
            pts = getattr(f, "risk_contribution", getattr(f, "points", 0))
            ev_item = getattr(f, "evidence", None)
            if ev_item:
                obs = f"{getattr(ev_item, 'observed_field', '')} = {getattr(ev_item, 'observed_value', '')}"
                src = getattr(ev_item, "packet_source", "PCAP traffic")
            else:
                obs = getattr(f, "observed_field", "")
                src = getattr(f, "packet_source", "PCAP traffic")

            f_block = [
                Paragraph(f"<b>Finding [{fid}]: {f.title}</b> (+{pts} pts - {f.severity})", h2_style),
                Paragraph(f"<b>Observed Parameter:</b> {obs} (Source: {src})", body_style),
                Paragraph(f"<b>Technical Analysis:</b> {exp.technical_explanation}", body_style),
                Paragraph(f"<b>Standards Grounding:</b> {ref_summary}", callout_style),
                Paragraph(f"<b>Remediation Directive:</b> <code>{exp.recommended_action}</code>", body_style),
                Spacer(1, 4),
            ]
            story.append(KeepTogether(f_block))

        # 7. Priority Action Plan
        story.append(Spacer(1, 8))
        story.append(Paragraph("5. Prioritized Remediation Roadmap", h1_style))
        for rec in narrative.strategic_remediation_roadmap:
            story.append(Paragraph(f"• {rec}", body_style))

        # Build Document
        doc.build(story)
        return out_file
