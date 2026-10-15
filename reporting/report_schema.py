"""
Unified Report Schemas for SentraIPS (Phase 5).
Defines structured, strongly typed Pydantic models for Executive Summaries,
Configuration Audits, ML Traffic Profiling, Compliance Checks, and Security Reports.
"""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class ReportExecutiveSummary(BaseModel):
    analysis_id: str
    timestamp: str
    overall_risk_score: int = Field(..., ge=0, le=100)
    severity: str  # LOW, LOW-MEDIUM, MEDIUM, HIGH, CRITICAL
    ipsec_detected: bool
    ike_version: str
    encryption: str
    dh_group: str
    pfs: str
    traffic_classification: str
    traffic_confidence: float = 0.0
    compliance_rating: str  # COMPLIANT, COMPLIANT_WITH_WARNINGS, NON_COMPLIANT, INSUFFICIENT_DATA
    summary_narrative: str = ""


class ReportVPNConfiguration(BaseModel):
    vpn_mode: str
    ike_version: str
    encryption: str
    encryption_key_length: Optional[int] = None
    authentication: str
    dh_group: Optional[Union[int, str]] = None
    dh_group_name: str = "Unknown"
    pfs: Union[bool, str] = "Unknown"
    esp_detected: bool = False
    initiator_spi: str = "Unknown"
    responder_spi: str = "Unknown"
    total_packets: int = 0
    ike_packets: int = 0
    esp_packets: int = 0
    observation_provenance: Dict[str, str] = Field(default_factory=dict)


class ReportTrafficAnalysis(BaseModel):
    traffic_type: str
    confidence: float = 0.0
    ml_confidence: Optional[float] = None
    model: str = "RandomForest"
    model_used: Optional[str] = None
    packet_count: int = 0
    flow_duration_sec: float = 0.0
    mean_packet_size: float = 0.0
    packet_size_min: float = 0.0
    packet_size_max: float = 0.0
    packet_size_std: float = 0.0
    std_packet_size: Optional[float] = None
    min_packet_size: Optional[float] = None
    max_packet_size: Optional[float] = None
    mean_iat_ms: float = 0.0
    burst_count: int = 0
    mean_burst_bytes: float = 0.0
    probabilities: Dict[str, float] = Field(default_factory=dict)
    is_inferred: bool = True

    def model_post_init(self, __context: Any) -> None:
        if self.ml_confidence is not None and self.confidence == 0.0:
            self.confidence = self.ml_confidence
        if self.model_used is not None and self.model == "RandomForest":
            self.model = self.model_used



class ReportFinding(BaseModel):
    id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    description: str
    evidence: Union[Dict[str, Any], Any] = Field(default_factory=dict)
    impact: str
    recommendation: str
    confidence: float = 1.0
    source: str = "Observed from packet capture"
    references: List[Union[Dict[str, Any], str]] = Field(default_factory=list)


class ReportComplianceItem(BaseModel):
    control_id: str = "COMP-01"
    id: Optional[str] = None
    category: str
    title: str = ""
    parameter: Optional[str] = None
    status: str  # PASS, WARNING, FAIL, UNKNOWN
    observed_value: str
    expected_standard: str = ""
    standard: Optional[str] = None
    framework: str = "NIST SP 800-77 Rev. 1 & RFC 8221/8247"
    rationale: str = ""
    details: Optional[str] = None
    recommendation: Optional[str] = None
    references: List[Union[Dict[str, Any], str]] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        if self.id and (not self.control_id or self.control_id == "COMP-01"):
            self.control_id = self.id
        if self.standard and not self.expected_standard:
            self.expected_standard = self.standard
        if self.details and not self.rationale:
            self.rationale = self.details



class ReportRecommendation(BaseModel):
    id: str
    priority: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    action: str
    target_parameter: str = "General"
    rationale: str = ""


class SecurityAssessmentReportUnified(BaseModel):
    report_id: str
    timestamp: str
    summary: ReportExecutiveSummary
    vpn_configuration: ReportVPNConfiguration
    traffic_analysis: ReportTrafficAnalysis
    security_assessment: Dict[str, Any] = Field(default_factory=dict)
    findings: List[ReportFinding] = Field(default_factory=list)
    compliance: List[ReportComplianceItem] = Field(default_factory=list)
    compliance_summary: Dict[str, int] = Field(default_factory=dict)
    recommendations: List[ReportRecommendation] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    html_url: Optional[str] = None
    json_url: Optional[str] = None

