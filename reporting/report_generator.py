"""
Central Report Generator for SentraIPS (Phase 5).
Coordinates end-to-end audit pipelines:
  PCAP
  -> IPsec Parser
  -> ESP Feature Extraction
  -> Security Engine Findings
  -> Knowledge Base Compliance Evaluation
  -> Prioritized Recommendations
  -> JSON Report
  -> Standalone HTML Report
"""

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent

from packet_analysis.parser import IPsecPCAPParser, PCAPParseResult
from packet_analysis.features import ESPFeatureExtractor, ESPTrafficFeatures
from security_engine import SecurityEngine, SecurityAssessmentReport
from models import predict_traffic
from knowledge_base import ComplianceEngine, ComplianceEvaluationResult
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


class ReportGenerator:
    """
    Orchestrates Phase 5 unified reporting across security, ML, compliance, and formatting layers.
    """

    def __init__(
        self,
        security_engine: Optional[SecurityEngine] = None,
        compliance_engine: Optional[ComplianceEngine] = None,
        reports_dir: Optional[Union[str, Path]] = None,
        output_dir: Optional[Union[str, Path]] = None,
    ):
        self.security_engine = security_engine or SecurityEngine()
        self.compliance_engine = compliance_engine or ComplianceEngine()
        target_dir = output_dir or reports_dir or (PROJECT_ROOT / "reports")
        self.reports_dir = Path(target_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        pcap_path: Union[str, Path],
        report_id: Optional[str] = None,
    ) -> Tuple[SecurityAssessmentReportUnified, Path, Path]:
        """
        Executes end-to-end assessment from a PCAP file, saves JSON and HTML,
        and returns (unified_report, json_path, html_path).
        """
        report = self.generate_report_from_pcap(pcap_path, report_id=report_id)
        json_path, html_path = self.save_reports(report)
        return report, json_path, html_path

    def generate_report_from_pcap(
        self,
        pcap_path: Union[str, Path],
        report_id: Optional[str] = None,
    ) -> SecurityAssessmentReportUnified:
        """
        Executes end-to-end assessment from a PCAP file and produces a unified report.
        """
        p = Path(pcap_path)
        if not p.exists():
            raise FileNotFoundError(f"PCAP file not found: {p}")

        cid = p.stem
        # 1. Parse PCAP outer headers
        parsed = IPsecPCAPParser.parse_pcap(p, capture_id=cid)

        # 2. Extract ESP features if present
        esp_features = None
        if parsed.esp_packets > 0:
            esp_features = ESPFeatureExtractor.extract_from_pcap(p)

        # 3. Deterministic Security Assessment
        sec_report = self.security_engine.assess_parsed_pcap(parsed, esp_features)

        # 4. Phase 4 AI Traffic Classification
        traffic_pred = None
        if esp_features and parsed.esp_packets > 0:
            traffic_pred = predict_traffic(esp_features)
        else:
            traffic_pred = {
                "traffic_class": "Unknown",
                "confidence": 0.0,
                "model": "RandomForest",
                "probabilities": {},
            }

        return self.build_unified_report(
            parsed=parsed,
            esp_features=esp_features,
            sec_report=sec_report,
            traffic_pred=traffic_pred,
            report_id=report_id,
        )

    def build_unified_report(
        self,
        parsed: PCAPParseResult,
        esp_features: Optional[ESPTrafficFeatures],
        sec_report: SecurityAssessmentReport,
        traffic_pred: Dict[str, Any],
        report_id: Optional[str] = None,
    ) -> SecurityAssessmentReportUnified:
        """
        Synthesizes modular analysis components into a validated SecurityAssessmentReportUnified instance.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        r_id = report_id or f"audit_{parsed.capture_id}_{int(datetime.now().timestamp())}"

        # 1. VPN Configuration model
        prov = sec_report.observed_configuration.get("observation_provenance", {})
        vpn_cfg = ReportVPNConfiguration(
            vpn_mode=str(sec_report.observed_configuration.get("vpn_mode", "Unknown")),
            ike_version=parsed.ike.version,
            encryption=parsed.ike.encryption,
            encryption_key_length=parsed.ike.encryption_key_length,
            authentication=parsed.ike.authentication,
            dh_group=parsed.ike.dh_group,
            dh_group_name=parsed.ike.dh_group_name,
            pfs=parsed.ike.pfs,
            esp_detected=parsed.esp_detected,
            initiator_spi=parsed.ike.initiator_spi,
            responder_spi=parsed.ike.responder_spi,
            total_packets=parsed.total_packets,
            ike_packets=parsed.ike_packets,
            esp_packets=parsed.esp_packets,
            observation_provenance=prov,
        )

        # 2. Traffic Analysis model
        traffic_type = traffic_pred.get("traffic_class", "Unknown")
        confidence = float(traffic_pred.get("confidence", 0.0))
        model_name = str(traffic_pred.get("model", "RandomForest"))
        probs = traffic_pred.get("probabilities", {})

        traffic_analysis = ReportTrafficAnalysis(
            traffic_type=traffic_type,
            confidence=confidence,
            model=model_name,
            packet_count=esp_features.total_packets if esp_features else 0,
            flow_duration_sec=esp_features.flow_duration_sec if esp_features else 0.0,
            mean_packet_size=esp_features.size_mean if esp_features else 0.0,
            packet_size_min=esp_features.size_min if esp_features else 0.0,
            packet_size_max=esp_features.size_max if esp_features else 0.0,
            packet_size_std=esp_features.size_std if esp_features else 0.0,
            mean_iat_ms=esp_features.iat_mean_ms if esp_features else 0.0,
            burst_count=esp_features.burst_count if esp_features else 0,
            mean_burst_bytes=esp_features.mean_burst_bytes if esp_features else 0.0,
            probabilities=probs,
        )

        # 3. Compliance evaluation via Knowledge Base
        config_dict = {
            "encryption": parsed.ike.encryption,
            "dh_group": parsed.ike.dh_group,
            "dh_group_name": parsed.ike.dh_group_name,
            "pfs": parsed.ike.pfs,
            "ike_version": parsed.ike.version,
            "authentication": parsed.ike.authentication,
            "vpn_mode": sec_report.observed_configuration.get("vpn_mode", "tunnel"),
            "esp_packets": parsed.esp_packets,
        }
        comp_res: ComplianceEvaluationResult = self.compliance_engine.evaluate_configuration(
            config=config_dict,
            findings=sec_report.findings,
        )

        compliance_items = [
            ReportComplianceItem(
                control_id=c.control_id,
                category=c.category,
                title=c.title,
                status=c.status,
                observed_value=str(c.observed_value),
                expected_standard=c.expected_standard,
                framework=c.framework,
                rationale=c.rationale,
                references=c.references,
            )
            for c in comp_res.checks
        ]

        compliance_summary = {
            "total_checks": comp_res.total_checks,
            "passed": comp_res.passed,
            "warnings": comp_res.warnings,
            "failed": comp_res.failed,
            "unknown": comp_res.unknown,
        }

        # 4. Security Findings with standards citations
        report_findings: List[ReportFinding] = []
        for f in sec_report.findings:
            refs = []
            # Match finding to knowledge base rule
            if f.rule_id:
                # Find by condition or rule_id
                cond = f.rule_id.lower()
                r = self.compliance_engine.get_rule_by_condition(cond)
                if r:
                    refs = [ref.model_dump() for ref in r.references]

            ev_dict = f.evidence.model_dump() if hasattr(f.evidence, "model_dump") else f.evidence if isinstance(f.evidence, dict) else {"details": str(f.evidence)}

            rf = ReportFinding(
                id=f.id,
                title=f.title,
                severity=f.severity,
                category=f.category,
                description=f.description,
                evidence=ev_dict,
                impact=f.impact,
                recommendation=f.recommendation,
                confidence=f.confidence,
                source=f.source,
                references=refs,
            )
            report_findings.append(rf)

        # 5. Prioritized Recommendations
        recs: List[ReportRecommendation] = []
        for i, rec in enumerate(sec_report.recommendations, 1):
            recs.append(ReportRecommendation(
                id=f"REC-{i:03d}",
                priority=getattr(rec, "priority", "MEDIUM"),
                title=getattr(rec, "title", "Recommendation"),
                action=getattr(rec, "action", getattr(rec, "recommendation", "")),
                target_parameter=getattr(rec, "target_parameter", getattr(rec, "category", "General")),
                rationale=getattr(rec, "rationale", getattr(rec, "description", getattr(rec, "impact", ""))),
            ))

        # 6. Executive Summary
        dh_display = f"{parsed.ike.dh_group_name} ({parsed.ike.dh_group})" if parsed.ike.dh_group else parsed.ike.dh_group_name
        summary_narrative = (
            f"SentraIPS completed assessment for capture '{parsed.capture_id}'. "
            f"Evaluated risk score is {sec_report.risk_score}/100 ({sec_report.severity}). "
            f"Observed cryptographic parameters: {parsed.ike.version}, {parsed.ike.encryption}, DH {dh_display}, PFS {parsed.ike.pfs}. "
            f"Encrypted traffic classified as '{traffic_type}' with {confidence:.1%} confidence."
        )

        summary = ReportExecutiveSummary(
            analysis_id=parsed.capture_id,
            timestamp=now_iso,
            overall_risk_score=sec_report.risk_score,
            severity=sec_report.severity,
            ipsec_detected=parsed.ipsec_detected,
            ike_version=parsed.ike.version,
            encryption=parsed.ike.encryption,
            dh_group=dh_display,
            pfs=str(parsed.ike.pfs),
            traffic_classification=traffic_type,
            traffic_confidence=confidence,
            compliance_rating=comp_res.overall_status,
            summary_narrative=summary_narrative,
        )

        # 7. Limitations
        limitations = list(sec_report.limitations)
        limitations.append("Encrypted ESP payload contents were never decrypted; all analysis is derived strictly from outer packet headers and inter-arrival timing.")
        limitations.append("ML traffic classification represents a probabilistic inference based on observed outer packet size and burst distributions, not deterministic payload inspection.")

        return SecurityAssessmentReportUnified(
            report_id=r_id,
            timestamp=now_iso,
            summary=summary,
            vpn_configuration=vpn_cfg,
            traffic_analysis=traffic_analysis,
            security_assessment={
                "risk_score": sec_report.risk_score,
                "severity": sec_report.severity,
                "score_breakdown": [item.model_dump() for item in sec_report.score_breakdown],
            },
            findings=report_findings,
            compliance=compliance_items,
            compliance_summary=compliance_summary,
            recommendations=recs,
            limitations=limitations,
            html_url=f"/reports/{r_id}/html",
            json_url=f"/reports/{r_id}",
        )

    def save_reports(
        self,
        report: SecurityAssessmentReportUnified,
        output_dir: Optional[Union[str, Path]] = None,
    ) -> Tuple[Path, Path]:
        """
        Saves both JSON and HTML report files to target directory.
        Returns:
            Tuple of (json_path, html_path)
        """
        target_dir = Path(output_dir) if output_dir else self.reports_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        json_path = target_dir / f"{report.report_id}.json"
        html_path = target_dir / f"{report.report_id}.html"

        JSONReportGenerator.save(report, json_path)
        HTMLReportGenerator.save(report, html_path)

        return json_path, html_path
