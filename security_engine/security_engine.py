"""
Phase 3 Core Security Engine Orchestrator for SentraIPS.
Coordinates the end-to-end security assessment pipeline:
PCAP / Configuration -> IPsec Parser -> Extracted Configuration -> Security Rules -> Findings -> Risk Score -> Recommendations.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml

from packet_analysis.parser import IPsecPCAPParser, PCAPParseResult
from packet_analysis.features import ESPFeatureExtractor, ESPTrafficFeatures
from .schemas import (
    ExtractedConfiguration,
    ObservationStatus,
    ParameterObservation,
    ESPObservation,
    EvidenceItem,
    Recommendation,
    ScoreBreakdownItem,
    SecurityAssessmentReport,
    SecurityFinding,
    SubScores,
    ThreatMatrix,
)
from .rules import SecurityRuleEvaluator
from .risk_scoring import RiskScoringEngine
from .recommendations import RecommendationEngine


class SecurityEngine:
    """End-to-end deterministic security evaluation and compliance engine."""

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or Path(__file__).resolve().parent / "config.yaml"
        with open(self.config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)

        scoring_cfg = self.config.get("scoring", {})
        min_score = scoring_cfg.get("min_score", 0)
        max_score = scoring_cfg.get("max_score", 100)

        self.rule_evaluator = SecurityRuleEvaluator(self.config_path)
        self.risk_scoring_engine = RiskScoringEngine(min_score=min_score, max_score=max_score)
        self.recommendation_engine = RecommendationEngine()

    def map_severity(self, score: int) -> str:
        """Maps numeric risk score in [0, 100] to qualitative risk severity band."""
        return self.risk_scoring_engine.map_severity(score)

    def assess_parsed_pcap(
        self,
        parsed_pcap: PCAPParseResult,
        features: Optional[ESPTrafficFeatures] = None,
    ) -> SecurityAssessmentReport:
        """Executes full deterministic evaluation over parsed PCAP data."""
        # 1. Extract configuration with strict provenance
        config = self.rule_evaluator.extract_configuration(parsed_pcap, features)

        # 2. Evaluate security rules
        findings = self.rule_evaluator.evaluate_configuration(config)

        # 3. Calculate transparent risk score and breakdown
        scoring_result = self.risk_scoring_engine.calculate(findings)
        risk_score = scoring_result["risk_score"]
        severity = scoring_result["severity"]
        score_breakdown = scoring_result["score_breakdown"]
        sub_scores = scoring_result["sub_scores"]

        # 4. Build threat matrix
        threat_matrix = ThreatMatrix()
        for f in findings:
            threat_matrix.add_finding(f)

        # 5. Generate prioritized recommendations
        recommendations = self.recommendation_engine.generate(findings, config)

        # 6. Compile audit limitations
        limitations = [
            "ESP payload contents are fully encrypted; analysis is strictly limited to observable outer packet headers, SPI metadata, and sequence progression.",
            "Rekeyed Child SA transform attributes negotiated inside encrypted IKE_AUTH or CREATE_CHILD_SA payloads cannot be observed without decryption keys.",
        ]
        if config.encryption.status == ObservationStatus.UNKNOWN:
            limitations.append("Cipher suite was not observable in capture (handshake may have preceded packet capture).")
        if config.dh_group.status == ObservationStatus.UNKNOWN:
            limitations.append("Diffie-Hellman group was not observable in capture.")
        if config.pfs.status == ObservationStatus.UNKNOWN:
            limitations.append("PFS status was not observable from capture alone.")

        # 7. Backward-compatible observed_configuration dictionary
        observed_config = {
            "vpn_mode": config.vpn_mode.value,
            "ip_version": (parsed_pcap.ground_truth or {}).get("ip_version", "ipv4"),
            "ike_version": config.ike_version.value,
            "encryption": config.encryption.value,
            "encryption_key_length": config.raw_parameters.get("encryption_key_length"),
            "authentication": config.raw_parameters.get("authentication"),
            "dh_group": config.dh_group.value,
            "dh_group_name": config.dh_group.notes or "Unknown / Not Detected",
            "pfs": config.pfs.value,
            "total_packets": parsed_pcap.total_packets,
            "ike_packets": parsed_pcap.ike_packets,
            "esp_packets": parsed_pcap.esp_packets,
            "initiator_spi": parsed_pcap.ike.initiator_spi,
            "responder_spi": parsed_pcap.ike.responder_spi,
            "observation_provenance": {
                "encryption": config.encryption.status.value,
                "dh_group": config.dh_group.status.value,
                "pfs": config.pfs.status.value,
                "ike_version": config.ike_version.status.value,
                "vpn_mode": config.vpn_mode.status.value,
            },
        }

        return SecurityAssessmentReport(
            capture_id=parsed_pcap.capture_id,
            risk_score=risk_score,
            severity=severity,
            score_breakdown=score_breakdown,
            findings=findings,
            recommendations=recommendations,
            sub_scores=sub_scores,
            threat_matrix=threat_matrix,
            configuration=config,
            observed_configuration=observed_config,
            limitations=limitations,
            is_deterministic=True,
        )

    def assess_configuration(
        self,
        config_dict: Dict[str, Any],
        capture_id: str = "config_assessment",
    ) -> SecurityAssessmentReport:
        """Executes security evaluation directly over a configuration dictionary."""
        enc_val = config_dict.get("encryption") or "Unknown / Not Detected"
        enc_status = (
            ObservationStatus.UNKNOWN
            if not enc_val or enc_val == "Unknown / Not Detected"
            else ObservationStatus.OBSERVED
        )

        dh_val = config_dict.get("dh_group")
        dh_status = (
            ObservationStatus.UNKNOWN
            if dh_val is None or str(dh_val) == "Unknown / Not Detected"
            else ObservationStatus.OBSERVED
        )

        pfs_raw = config_dict.get("pfs")
        if isinstance(pfs_raw, bool):
            pfs_status = ObservationStatus.OBSERVED
            pfs_val = pfs_raw
        elif str(pfs_raw).lower() in ("true", "false"):
            pfs_status = ObservationStatus.OBSERVED
            pfs_val = str(pfs_raw).lower() == "true"
        else:
            pfs_status = ObservationStatus.UNKNOWN
            pfs_val = "Unknown / Not Detected"

        ike_val = config_dict.get("ike_version") or "Unknown / Not Detected"
        ike_status = (
            ObservationStatus.UNKNOWN
            if not ike_val or ike_val == "Unknown / Not Detected"
            else ObservationStatus.OBSERVED
        )

        mode_val = config_dict.get("vpn_mode") or "Unknown / Not Detected"
        mode_status = (
            ObservationStatus.UNKNOWN
            if not mode_val or mode_val == "Unknown / Not Detected"
            else ObservationStatus.OBSERVED
        )

        config = ExtractedConfiguration(
            encryption=ParameterObservation(
                name="encryption",
                value=enc_val,
                status=enc_status,
                source="Provided Configuration",
            ),
            dh_group=ParameterObservation(
                name="dh_group",
                value=dh_val if dh_val is not None else "Unknown / Not Detected",
                status=dh_status,
                source="Provided Configuration",
                notes=config_dict.get("dh_group_name"),
            ),
            pfs=ParameterObservation(
                name="pfs",
                value=pfs_val,
                status=pfs_status,
                source="Provided Configuration",
            ),
            ike_version=ParameterObservation(
                name="ike_version",
                value=ike_val,
                status=ike_status,
                source="Provided Configuration",
            ),
            vpn_mode=ParameterObservation(
                name="vpn_mode",
                value=mode_val,
                status=mode_status,
                source="Provided Configuration",
            ),
            esp=ESPObservation(
                presence=bool(config_dict.get("esp_packets", 0) > 0),
                packet_count=config_dict.get("esp_packets", 0),
            ),
            total_packets=config_dict.get("total_packets", 0),
            ike_packets=config_dict.get("ike_packets", 0),
            esp_packets=config_dict.get("esp_packets", 0),
            raw_parameters=config_dict,
        )

        findings = self.rule_evaluator.evaluate_configuration(config)
        scoring_result = self.risk_scoring_engine.calculate(findings)
        recommendations = self.recommendation_engine.generate(findings, config)

        threat_matrix = ThreatMatrix()
        for f in findings:
            threat_matrix.add_finding(f)

        limitations = [
            "Assessment conducted against submitted configuration metadata without raw packet verification.",
        ]
        if enc_status == ObservationStatus.UNKNOWN:
            limitations.append("Cipher suite was not provided or not detected.")
        if dh_status == ObservationStatus.UNKNOWN:
            limitations.append("Diffie-Hellman group was not provided or not detected.")
        if pfs_status == ObservationStatus.UNKNOWN:
            limitations.append("PFS configuration was not provided or not detected.")

        return SecurityAssessmentReport(
            capture_id=capture_id,
            risk_score=scoring_result["risk_score"],
            severity=scoring_result["severity"],
            score_breakdown=scoring_result["score_breakdown"],
            findings=findings,
            recommendations=recommendations,
            sub_scores=scoring_result["sub_scores"],
            threat_matrix=threat_matrix,
            configuration=config,
            observed_configuration=config_dict,
            limitations=limitations,
            is_deterministic=True,
        )

    def assess_pcap_file(
        self,
        pcap_path: Union[str, Path],
        ground_truth: Optional[Dict[str, Any]] = None,
    ) -> SecurityAssessmentReport:
        """Convenience method: parses PCAP file, extracts features, and assesses security."""
        parsed = IPsecPCAPParser.parse_pcap(pcap_path, ground_truth=ground_truth)
        features = None
        if parsed.esp_packets > 0:
            features = ESPFeatureExtractor.extract_from_pcap(pcap_path)
        return self.assess_parsed_pcap(parsed, features)
