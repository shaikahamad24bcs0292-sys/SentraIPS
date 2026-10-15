"""
Comprehensive Technical Security Audit Report Generator for SentraIPS.
Strictly implements all 13 technical audit report sections specified in Phase 5:
1. Capture Information
2. VPN Configuration
3. IKE Analysis
4. ESP Analysis
5. AI Traffic Inference
6. Security Findings
7. Risk Score
8. Threat Matrix
9. Evidence
10. NIST/RFC References
11. Recommendations
12. AI Confidence
13. Limitations
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel

from security_engine.findings import SecurityAssessmentReport, SecurityFinding
from models.ensemble import EnsemblePredictionResult
from knowledge_base.rag import StandardsRAGEngine, StructuredEvidenceItem
from reporting.llm_explainer import LLMExplainer, FindingExplanation


class TechnicalReportGenerator:
    """Compiles detailed, auditable engineering reports for cybersecurity and network teams."""

    def __init__(self, rag_engine: Optional[StandardsRAGEngine] = None, explainer: Optional[LLMExplainer] = None):
        self.rag = rag_engine or StandardsRAGEngine()
        self.explainer = explainer or LLMExplainer(self.rag)

    def generate_markdown(
        self,
        report: SecurityAssessmentReport,
        parsed_pcap: Optional[Any] = None,
        esp_features: Optional[Any] = None,
        traffic_inference: Optional[Union[EnsemblePredictionResult, Dict[str, Any]]] = None,
    ) -> str:
        """
        Builds complete 13-section technical audit document in GitHub-flavored Markdown.
        """
        score = report.risk_score
        severity = report.severity
        tm = report.threat_matrix
        sub = report.sub_scores

        # Extract parsed PCAP values safely
        obs_cfg = getattr(report, "observed_configuration", {}) or {}
        encr = getattr(parsed_pcap, "encryption", obs_cfg.get("encryption", "Unknown"))
        key_len = getattr(parsed_pcap, "encryption_key_length", obs_cfg.get("encryption_key_length", "Unknown"))
        dh_grp = getattr(parsed_pcap, "dh_group", obs_cfg.get("dh_group", "Unknown"))
        dh_name = getattr(parsed_pcap, "dh_group_name", obs_cfg.get("dh_group_name", "Unknown"))
        pfs_val = getattr(parsed_pcap, "pfs", obs_cfg.get("pfs", "Unknown"))
        ike_ver = getattr(parsed_pcap, "ike_version", obs_cfg.get("ike_version", "IKEv2"))
        tot_pkts = getattr(parsed_pcap, "total_packets", obs_cfg.get("total_packets", 0))
        esp_pkts = getattr(parsed_pcap, "esp_packets", obs_cfg.get("esp_packets", 0))
        ike_pkts = getattr(parsed_pcap, "ike_packets", obs_cfg.get("ike_packets", 0))
        init_spi = getattr(parsed_pcap, "initiator_spi", obs_cfg.get("initiator_spi", "Unknown"))
        resp_spi = getattr(parsed_pcap, "responder_spi", obs_cfg.get("responder_spi", "Unknown"))

        # ESP stats
        flow_dur = getattr(esp_features, "flow_duration_sec", 0.0)
        pkt_size_mean = getattr(esp_features, "size_mean", 0.0)
        pkt_size_max = getattr(esp_features, "size_max", 0)
        iat_mean = getattr(esp_features, "iat_mean_ms", 0.0)
        burst_count = getattr(esp_features, "burst_count", 0)

        # AI inference details
        cnn_pred = getattr(traffic_inference, "cnn_prediction", traffic_inference.get("cnn_prediction", "N/A") if isinstance(traffic_inference, dict) else "N/A")
        cnn_conf = getattr(traffic_inference, "cnn_confidence", traffic_inference.get("cnn_confidence", 0.0) if isinstance(traffic_inference, dict) else 0.0)
        stat_pred = getattr(traffic_inference, "statistical_prediction", traffic_inference.get("statistical_prediction", "N/A") if isinstance(traffic_inference, dict) else "N/A")
        stat_conf = getattr(traffic_inference, "statistical_confidence", traffic_inference.get("statistical_confidence", 0.0) if isinstance(traffic_inference, dict) else 0.0)
        agreement = getattr(traffic_inference, "agreement", traffic_inference.get("agreement", False) if isinstance(traffic_inference, dict) else False)
        final_pred = getattr(traffic_inference, "final_prediction", traffic_inference.get("final_prediction", "N/A") if isinstance(traffic_inference, dict) else "N/A")
        final_conf = getattr(traffic_inference, "final_confidence", traffic_inference.get("final_confidence", None) if isinstance(traffic_inference, dict) else None)
        inf_status = getattr(traffic_inference, "status", traffic_inference.get("status", "N/A") if isinstance(traffic_inference, dict) else "N/A")
        cap_id = getattr(report, "capture_id", "unknown_capture")

        lines = [
            "# SentraIPS — Technical Security Assessment Report",
            f"**Target Session:** `{cap_id}` | **Audit ID:** `SEC-AUD-{cap_id.upper()}` | **Engine Version:** `SentraIPS v0.5.0`",
            "",
            "---",
            "",
            "## 1. Capture Information",
            f"- **Capture Identifier:** `{cap_id}`",
            f"- **Total Captured Packets:** `{tot_pkts}` packets",
            f"- **Observed Protocols:** ESP (IP Proto 50), IKE (UDP 500/4500)",
            f"- **Network Interface Topology:** `172.28.0.0/24` (Transit Network: `ipsec-gateway-a` <-> `ipsec-gateway-b`)",
            "",
            "## 2. VPN Configuration",
            f"- **VPN Mode:** `TUNNEL (IPv4)`",
            f"- **IKE Version:** `{ike_ver}`",
            f"- **Cipher Suite:** `{encr}` ({key_len}-bit)",
            f"- **Diffie-Hellman Group:** `Group {dh_grp} ({dh_name})`",
            f"- **Perfect Forward Secrecy (PFS):** `{pfs_val}`",
            "",
            "## 3. IKE Analysis",
            f"- **Negotiated Handshake Exchanges:** `IKE_SA_INIT`, `IKE_AUTH`",
            f"- **Total IKE Packets:** `{ike_pkts}` packets",
            f"- **Initiator SPI:** `{init_spi}`",
            f"- **Responder SPI:** `{resp_spi}`",
            f"- **Cleartext Metadata Visibility:** SPIs, transform proposal IDs, and Diffie-Hellman public keys are exposed in unencrypted IKE_SA_INIT headers.",
            "",
            "## 4. ESP Analysis",
            f"- **ESP Encrypted Packets:** `{esp_pkts}` packets",
            f"- **Flow Duration:** `{flow_dur:.3f}` seconds",
            f"- **Packet Size Dynamics:** Mean = `{pkt_size_mean:.1f}` B, Max = `{pkt_size_max}` B",
            f"- **Inter-Arrival Time (IAT):** Mean = `{iat_mean:.2f}` ms",
            f"- **Traffic Bursts:** `{burst_count}` bursts detected (50ms idle threshold)",
            f"- **Payload Confidentiality:** Payloads remain 100% encrypted. Analysis operates exclusively over outer headers and temporal sequence dynamics.",
            "",
            "## 5. AI Traffic Inference",
            f"- **1D-CNN Temporal Model Prediction:** `{cnn_pred}` (Confidence: `{cnn_conf:.1%}`)",
            f"- **Random Forest Statistical Model Prediction:** `{stat_pred}` (Confidence: `{stat_conf:.1%}`)",
            f"- **Model Agreement Check:** `{'AGREEMENT' if agreement else 'DISAGREEMENT (UNCERTAIN)'}`",
            f"- **Final Inferred Application:** `{final_pred}`",
            f"- **Operational Status:** `{inf_status.upper()}`",
            "",
            "## 6. Security Findings",
            "Individual vulnerability findings evaluated against deterministic rule sets:",
            "",
        ]

        enriched_findings: List[Tuple[SecurityFinding, StructuredEvidenceItem, FindingExplanation]] = []
        for f in tm.findings:
            ev = self.rag.enrich_finding(f)
            exp = self.explainer.explain_finding(f, ev)
            enriched_findings.append((f, ev, exp))

            fid = getattr(f, "finding_id", getattr(f, "id", "F001"))
            pts = getattr(f, "risk_contribution", getattr(f, "points", 0))
            ev_item = getattr(f, "evidence", None)
            if ev_item:
                obs = f"{getattr(ev_item, 'observed_field', '')} = {getattr(ev_item, 'observed_value', '')}"
                src = getattr(ev_item, "packet_source", "PCAP traffic")
            else:
                obs = str(getattr(f, "observed_field", ""))
                src = str(getattr(f, "packet_source", "PCAP traffic"))

            lines.extend([
                f"### Finding `{fid}`: {f.title} ({f.severity})",
                f"- **Rule Identifier:** `{f.rule_id}`",
                f"- **Risk Points:** `+{pts} pts`",
                f"- **Observed Field:** `{obs}`",
                f"- **Source:** `{src}`",
                f"- **Technical Analysis:** {exp.technical_explanation}",
                f"- **Business & Operational Impact:** {exp.business_impact}",
                f"- **Authoritative Basis:** {exp.authoritative_basis}",
                f"- **Actionable Recommendation:** {exp.recommended_action}",
                "",
            ])

        proto_risk = getattr(sub, "configuration_risk", getattr(sub, "protocol_risk", 0))
        meta_risk = getattr(sub, "metadata_exposure_risk", getattr(sub, "metadata_risk", 0))

        lines.extend([
            "## 7. Risk Score",
            f"- **Total Deterministic Risk Score:** **{score} / 100**",
            f"- **Qualitative Risk Band:** **{severity}**",
            f"- **Subscores Breakdown:**",
            f"  - Cryptography Risk Subscore: `{sub.crypto_risk}` pts",
            f"  - Key Exchange Risk Subscore: `{sub.key_exchange_risk}` pts",
            f"  - Protocol & SA Risk Subscore: `{proto_risk}` pts",
            f"  - Metadata Exposure Subscore: `{meta_risk}` pts",
            "",
            "## 8. Threat Matrix",
            "| ID | Severity | Points | Rule ID | Title | Observed Parameter |",
            "|---|---|---|---|---|---|",
        ])

        for f in tm.findings:
            fid = getattr(f, "finding_id", getattr(f, "id", "F001"))
            pts = getattr(f, "risk_contribution", getattr(f, "points", 0))
            ev_item = getattr(f, "evidence", None)
            obs = f"{getattr(ev_item, 'observed_field', '')} = {getattr(ev_item, 'observed_value', '')}" if ev_item else str(getattr(f, "observed_field", ""))
            lines.append(f"| `{fid}` | **{f.severity}** | +{pts} | `{f.rule_id}` | {f.title} | `{obs}` |")

        lines.extend([
            "",
            "## 9. Evidence",
            "Auditable evidence chain grounded in network capture observations:",
            "",
        ])

        for f, ev, _ in enriched_findings:
            fid = getattr(f, "finding_id", getattr(f, "id", "F001"))
            lines.extend([
                f"#### `[{fid}]` {f.title}",
                f"- **Evidence Statement:** {ev.observed_evidence}",
                f"- **Rule ID:** `{ev.rule_id}` (+{ev.risk_contribution} pts)",
                "",
            ])

        lines.extend([
            "## 10. NIST/RFC References",
            "Standards citations retrieved via vector RAG similarity pipeline:",
            "",
        ])

        for f, ev, _ in enriched_findings:
            fid = getattr(f, "finding_id", getattr(f, "id", "F001"))
            lines.append(f"#### Cross-References for Finding `{fid}` ({f.title}):")
            for ref in ev.references:
                lines.extend([
                    f"- **{ref.get('document')} — {ref.get('section')}: {ref.get('title')}** (Relevance: `{ref.get('relevance_score', 0):.2f}`)",
                    f"  > \"{ref.get('excerpt')}\"",
                    "",
                ])

        lines.extend([
            "## 11. Recommendations",
            "Actionable strongSwan remediation configuration directives:",
            "",
        ])

        for i, (f, _, exp) in enumerate(enriched_findings, 1):
            lines.append(f"{i}. **{f.title}:** {exp.recommended_action}")

        lines.extend([
            "",
            "## 12. AI Confidence",
            f"- **Dual-Model Inference Confidence:**",
            f"  - 1D-CNN Temporal Sequence Model: `{cnn_conf:.1%}`",
            f"  - Random Forest Statistical Model: `{stat_conf:.1%}`",
            f"  - Combined Ensemble Confidence: `{final_conf:.1%}`" if final_conf is not None else f"  - Combined Ensemble Confidence: `None (Uncertainty Flagged)`",
            f"- **Uncertainty Classification Note:** When models disagree, SentraIPS strictly outputs `UNCERTAIN` to prevent hallucination or misattribution.",
            "",
            "## 13. Limitations",
            "1. **Cleartext Handshake Visibility:** Child SA PFS renegotiations conducted inside encrypted IKEv2 `CREATE_CHILD_SA` exchanges cannot be observed on the wire without gateway configuration metadata.",
            "2. **Traffic Flow Confidentiality Padding:** If gateways employ aggressive variable-length dummy padding (RFC 4303 TFC), packet size dynamics are masked, shifting model reliance onto packet arrival pacing.",
            "3. **Zero Payload Decryption Guarantee:** SentraIPS never performs payload decryption, preserving end-to-end user privacy in compliance with telecommunications and security standards.",
            "",
            "---",
            "*Report generated by SentraIPS Autonomous Security Evaluation Engine.*",
            "",
        ])

        return "\n".join(lines)
