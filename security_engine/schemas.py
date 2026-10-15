"""
Phase 3 Schemas and Data Models for SentraIPS Security Engine.
Defines schemas for:
- Observation status (OBSERVED, INFERRED, UNKNOWN)
- Extracted configuration
- Security findings
- Score breakdowns
- Prioritized recommendations
- Assessment report
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ObservationStatus(str, Enum):
    """Observation reliability status for extracted parameters."""
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class ParameterObservation(BaseModel):
    """Auditable observation of a configuration or cryptographic parameter."""
    name: str
    value: Any
    status: ObservationStatus = ObservationStatus.UNKNOWN
    source: str = "Unknown / Not Detected"
    notes: Optional[str] = None


class ESPObservation(BaseModel):
    """Auditable observation of ESP encrypted traffic headers."""
    presence: bool = False
    packet_count: int = 0
    spis_observed: List[str] = Field(default_factory=list)
    seq_min: Optional[int] = None
    seq_max: Optional[int] = None
    seq_progression: str = "No ESP packets detected"
    anomalies_detected: List[str] = Field(default_factory=list)
    disclaimer: str = (
        "ESP payloads are encrypted and cannot be decrypted without secret keys. "
        "Security evaluation operates exclusively over observable outer headers, SPIs, and sequence metadata."
    )


class ExtractedConfiguration(BaseModel):
    """Structured view of extracted IPsec configuration with explicit observation status."""
    encryption: ParameterObservation
    dh_group: ParameterObservation
    pfs: ParameterObservation
    ike_version: ParameterObservation
    vpn_mode: ParameterObservation
    esp: ESPObservation
    total_packets: int = 0
    ike_packets: int = 0
    esp_packets: int = 0
    raw_parameters: Dict[str, Any] = Field(default_factory=dict)


class EvidenceItem(BaseModel):
    """Concrete packet or configuration evidence underpinning a finding."""
    model_config = ConfigDict(extra="allow")

    observed_field: str = ""
    observed_value: Any = None
    packet_source: str = "Observed from configuration"
    rule_criterion: str = ""

    def __getitem__(self, item: str) -> Any:
        if hasattr(self, item):
            return getattr(self, item)
        if item in self.__pydantic_extra__:
            return self.__pydantic_extra__[item]
        raise KeyError(item)

    def get(self, item: str, default: Any = None) -> Any:
        try:
            return self[item]
        except (KeyError, AttributeError):
            return default

    def to_clean_dict(self) -> Dict[str, Any]:
        """Returns clean dictionary with key evidence fields, prioritizing domain keys."""
        dump = self.model_dump()
        extra = {
            k: v for k, v in dump.items()
            if k not in ("observed_field", "observed_value", "packet_source", "rule_criterion")
            and v is not None
        }
        if extra:
            return extra
        if self.observed_field:
            return {self.observed_field: self.observed_value}
        return dump


class SecurityFinding(BaseModel):
    """
    Standardized Phase 3 security finding with deterministic audit evidence.
    Every finding strictly contains:
    - id
    - title
    - severity
    - category
    - description
    - evidence
    - impact
    - recommendation
    - confidence
    - source
    """
    id: str = Field(..., description="Unique finding identifier (e.g. VPN-001)")
    title: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    category: str
    description: str
    evidence: Union[EvidenceItem, Dict[str, Any]]
    impact: str = ""
    recommendation: str = ""
    confidence: float = 1.0
    source: str = "Observed from configuration"

    # Backward compatibility attributes
    finding_id: Optional[str] = None
    rule_id: Optional[str] = None
    risk_contribution: int = 0

    @model_validator(mode="before")
    @classmethod
    def normalize_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        # Normalize ID
        fid = data.get("id") or data.get("finding_id") or "VPN-001"
        data["id"] = fid
        if not data.get("finding_id"):
            # Ensure finding_id starts with 'F' for backward compatibility
            data["finding_id"] = fid if fid.startswith("F") else f"F-{fid}"

        if not data.get("rule_id"):
            data["rule_id"] = fid

        # Normalize evidence
        ev = data.get("evidence")
        if isinstance(ev, dict) and not isinstance(ev, EvidenceItem):
            obs_field = ev.get("observed_field", "")
            obs_val = ev.get("observed_value")
            if not obs_field:
                # Pick first domain key that is not standard metadata
                for k, v in ev.items():
                    if k not in ("packet_source", "rule_criterion", "observed_field", "observed_value"):
                        obs_field = k
                        obs_val = v
                        break
            if not obs_field:
                obs_field = "configuration"
                obs_val = str(ev)

            data["evidence"] = EvidenceItem(
                observed_field=str(obs_field),
                observed_value=obs_val,
                packet_source=ev.get("packet_source", data.get("source", "Observed from configuration")),
                rule_criterion=ev.get("rule_criterion", data.get("description", "")),
                **{k: v for k, v in ev.items() if k not in ("observed_field", "observed_value", "packet_source", "rule_criterion")}
            )

        return data

    def to_dict(self) -> Dict[str, Any]:
        """Serializes finding according to the strict Phase 3 specification."""
        clean_evidence = (
            self.evidence.to_clean_dict()
            if isinstance(self.evidence, EvidenceItem)
            else (self.evidence if isinstance(self.evidence, dict) else {})
        )
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "evidence": clean_evidence,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "source": self.source,
        }


class ThreatMatrix(BaseModel):
    """Categorized summary of all security findings."""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    findings: List[SecurityFinding] = Field(default_factory=list)

    def add_finding(self, finding: SecurityFinding):
        self.findings.append(finding)
        self.total_findings += 1
        sev = finding.severity.upper()
        if sev == "CRITICAL":
            self.critical_count += 1
        elif sev == "HIGH":
            self.high_count += 1
        elif sev == "MEDIUM":
            self.medium_count += 1
        elif sev == "LOW":
            self.low_count += 1
        elif sev == "INFO":
            self.info_count += 1


class SubScores(BaseModel):
    """Domain-specific risk contributions."""
    crypto_risk: int = 0
    key_exchange_risk: int = 0
    configuration_risk: int = 0
    metadata_exposure_risk: int = 0


class ScoreBreakdownItem(BaseModel):
    """Explainable risk score item contribution."""
    finding_id: str
    rule_id: str
    title: str
    severity: str
    points: int
    category: str
    reason: str


class RecommendationPriority(str, Enum):
    """Priority order for remedial recommendations."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Recommendation(BaseModel):
    """Actionable remediation recommendation with priority and rationale."""
    priority: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    title: str
    description: str
    action: str
    related_finding_id: Optional[str] = None
    category: str = "Configuration"


class SecurityAssessmentReport(BaseModel):
    """Complete explainable Phase 3 cybersecurity assessment report."""
    capture_id: str
    risk_score: int  # 0 to 100
    severity: str    # "LOW", "LOW-MEDIUM", "MEDIUM", "HIGH", "CRITICAL"
    score_breakdown: List[ScoreBreakdownItem] = Field(default_factory=list)
    findings: List[SecurityFinding] = Field(default_factory=list)
    recommendations: List[Recommendation] = Field(default_factory=list)
    sub_scores: SubScores = Field(default_factory=SubScores)
    threat_matrix: ThreatMatrix = Field(default_factory=ThreatMatrix)
    configuration: Optional[ExtractedConfiguration] = None
    observed_configuration: Dict[str, Any] = Field(default_factory=dict)
    limitations: List[str] = Field(default_factory=list)
    scoring_methodology: str = (
        "Deterministic additive scoring bounded in range [0, 100]. "
        "Weights and rule thresholds defined in security_engine/config.yaml. "
        "Calculated strictly from observed packet and configuration evidence without LLM/AI interference."
    )
    is_deterministic: bool = True

    def to_summary_dict(self) -> Dict[str, Any]:
        """Returns clean representation matching Phase 3 specifications."""
        return {
            "risk_score": self.risk_score,
            "severity": self.severity,
            "score_breakdown": [b.model_dump() for b in self.score_breakdown],
            "findings": [f.to_dict() for f in self.findings],
            "recommendations": [r.model_dump() for r in self.recommendations],
            "limitations": self.limitations,
        }


# Type alias for clarity
SecurityAssessmentResult = SecurityAssessmentReport
