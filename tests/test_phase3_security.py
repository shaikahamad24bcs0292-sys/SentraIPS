"""
Comprehensive Phase 3 Test Suite for SentraIPS Security Engine.
Tests all 14 mandatory security engine criteria:
1. AES-256-GCM secure configuration
2. AES-128-CBC warning
3. Strong DH group (Group 19 / ecp256, Group 20 / ecp384)
4. Weak DH group (Group 5 / modp1536, Group 1/2)
5. PFS enabled
6. PFS disabled
7. IKEv2 recommended
8. IKEv1 warning / deprecated
9. Unknown parameters (no false-positive vulnerability assumptions)
10. Multiple simultaneous findings aggregation
11. Risk score calculation and explainable breakdown
12. Prioritized recommendation generation
13. Invalid input handling
14. Missing fields graceful handling
+ API endpoint tests for POST /security-assessment
"""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from security_engine import (
    ObservationStatus,
    RiskScoringEngine,
    SecurityAssessmentReport,
    SecurityEngine,
    SecurityFinding,
    SecurityRuleEvaluator,
)
from security_engine.schemas import ExtractedConfiguration, ParameterObservation, ESPObservation, EvidenceItem


@pytest.fixture
def engine(project_root: Path) -> SecurityEngine:
    config_file = project_root / "security_engine" / "config.yaml"
    return SecurityEngine(config_path=config_file)


# -----------------------------------------------------------------------------
# 1. AES-256-GCM Secure Configuration
# -----------------------------------------------------------------------------
def test_aes_256_gcm_secure_configuration(engine: SecurityEngine):
    """Verify AES-256-GCM is treated as Strong/Recommended with 0 risk penalty."""
    report = engine.assess_configuration({
        "encryption": "AES-256-GCM",
        "dh_group": 19,
        "pfs": True,
        "ike_version": "IKEv2",
    })

    # No cryptography findings should be triggered
    crypto_findings = [f for f in report.findings if f.category == "Cryptography"]
    assert len(crypto_findings) == 0
    assert report.sub_scores.crypto_risk == 0
    assert report.risk_score == 0
    assert report.severity == "LOW"


# -----------------------------------------------------------------------------
# 2. AES-128-CBC Warning
# -----------------------------------------------------------------------------
def test_aes_128_cbc_warning(engine: SecurityEngine):
    """Verify AES-128-CBC triggers a non-AEAD warning finding with 20 risk points."""
    report = engine.assess_configuration({
        "encryption": "AES-128-CBC",
        "dh_group": 19,
        "pfs": True,
        "ike_version": "IKEv2",
    })

    crypto_findings = [f for f in report.findings if f.category == "Cryptography"]
    assert len(crypto_findings) == 1
    cbc_finding = crypto_findings[0]
    assert cbc_finding.rule_id == "CRYPTO_LEGACY_NON_AEAD"
    assert cbc_finding.severity == "MEDIUM"
    assert cbc_finding.risk_contribution == 20
    assert "CBC" in str(cbc_finding.evidence.observed_value)
    assert report.sub_scores.crypto_risk == 20


# -----------------------------------------------------------------------------
# 3. Strong DH Group
# -----------------------------------------------------------------------------
def test_strong_dh_group(engine: SecurityEngine):
    """Verify Group 19 (ecp256) and Group 20 (ecp384) trigger 0 key exchange risk."""
    for grp in [19, 20, "ecp256", "ecp384"]:
        report = engine.assess_configuration({
            "encryption": "AES-256-GCM",
            "dh_group": grp,
            "pfs": True,
            "ike_version": "IKEv2",
        })
        dh_findings = [f for f in report.findings if f.category == "Key Exchange"]
        assert len(dh_findings) == 0
        assert report.sub_scores.key_exchange_risk == 0


# -----------------------------------------------------------------------------
# 4. Weak DH Group
# -----------------------------------------------------------------------------
def test_weak_dh_group(engine: SecurityEngine):
    """Verify Group 5 triggers legacy DH warning, and Group 2 triggers insecure DH."""
    # Test Group 5 (Legacy 1536-bit)
    report_g5 = engine.assess_configuration({
        "encryption": "AES-256-GCM",
        "dh_group": 5,
        "dh_group_name": "modp1536",
        "pfs": True,
        "ike_version": "IKEv2",
    })
    g5_findings = [f for f in report_g5.findings if f.rule_id == "DH_GROUP_LEGACY"]
    assert len(g5_findings) == 1
    assert g5_findings[0].severity == "MEDIUM"
    assert g5_findings[0].risk_contribution == 20

    # Test Group 2 (Insecure 1024-bit)
    report_g2 = engine.assess_configuration({
        "encryption": "AES-256-GCM",
        "dh_group": 2,
        "dh_group_name": "modp1024",
        "pfs": True,
        "ike_version": "IKEv2",
    })
    g2_findings = [f for f in report_g2.findings if f.rule_id == "DH_GROUP_INSECURE"]
    assert len(g2_findings) == 1
    assert g2_findings[0].severity == "CRITICAL"
    assert g2_findings[0].risk_contribution == 25


# -----------------------------------------------------------------------------
# 5. PFS Enabled
# -----------------------------------------------------------------------------
def test_pfs_enabled(engine: SecurityEngine):
    """Verify PFS Enabled triggers no finding and 0 risk points."""
    report = engine.assess_configuration({
        "encryption": "AES-256-GCM",
        "dh_group": 19,
        "pfs": True,
        "ike_version": "IKEv2",
    })
    pfs_findings = [f for f in report.findings if f.rule_id == "PFS_DISABLED"]
    assert len(pfs_findings) == 0


# -----------------------------------------------------------------------------
# 6. PFS Disabled
# -----------------------------------------------------------------------------
def test_pfs_disabled(engine: SecurityEngine):
    """Verify PFS Disabled triggers PFS_DISABLED warning finding."""
    report = engine.assess_configuration({
        "encryption": "AES-256-GCM",
        "dh_group": 19,
        "pfs": False,
        "ike_version": "IKEv2",
    })
    pfs_findings = [f for f in report.findings if f.rule_id == "PFS_DISABLED"]
    assert len(pfs_findings) == 1
    assert pfs_findings[0].severity == "MEDIUM"
    assert pfs_findings[0].risk_contribution == 20
    assert pfs_findings[0].evidence.observed_value is False


# -----------------------------------------------------------------------------
# 7. IKEv2 Recommended
# -----------------------------------------------------------------------------
def test_ikev2_recommended(engine: SecurityEngine):
    """Verify IKEv2 triggers no deprecation finding."""
    report = engine.assess_configuration({
        "encryption": "AES-256-GCM",
        "dh_group": 19,
        "pfs": True,
        "ike_version": "IKEv2",
    })
    ike_findings = [f for f in report.findings if f.rule_id == "IKE_VERSION_DEPRECATED"]
    assert len(ike_findings) == 0


# -----------------------------------------------------------------------------
# 8. IKEv1 Warning
# -----------------------------------------------------------------------------
def test_ikev1_warning(engine: SecurityEngine):
    """Verify IKEv1 triggers IKE_VERSION_DEPRECATED finding with 20 risk points."""
    report = engine.assess_configuration({
        "encryption": "AES-256-GCM",
        "dh_group": 19,
        "pfs": True,
        "ike_version": "IKEv1",
    })
    ike_findings = [f for f in report.findings if f.rule_id == "IKE_VERSION_DEPRECATED"]
    assert len(ike_findings) == 1
    assert ike_findings[0].severity == "HIGH"
    assert ike_findings[0].risk_contribution == 20
    assert "IKEV1" in str(ike_findings[0].evidence.observed_value).upper()


# -----------------------------------------------------------------------------
# 9. Unknown Parameters (Not Assumed Vulnerable)
# -----------------------------------------------------------------------------
def test_unknown_parameters_not_assumed_vulnerable(engine: SecurityEngine):
    """Verify unknown parameters are not assumed vulnerable and add 0 risk points."""
    report = engine.assess_configuration({
        "encryption": "Unknown / Not Detected",
        "dh_group": "Unknown / Not Detected",
        "pfs": "Unknown / Not Detected",
        "ike_version": "Unknown / Not Detected",
    })

    # Must not assume weak ciphers or disabled PFS
    assert report.risk_score == 0
    assert report.severity == "LOW"
    assert report.sub_scores.crypto_risk == 0
    assert report.sub_scores.key_exchange_risk == 0
    assert report.sub_scores.configuration_risk == 0

    # Provenance must be marked UNKNOWN
    assert report.configuration.encryption.status == ObservationStatus.UNKNOWN
    assert report.configuration.dh_group.status == ObservationStatus.UNKNOWN
    assert report.configuration.pfs.status == ObservationStatus.UNKNOWN
    assert report.configuration.ike_version.status == ObservationStatus.UNKNOWN

    # Must produce operational guidance recommendation explaining unobserved status
    recs = [r for r in report.recommendations if "Unobserved" in r.title]
    assert len(recs) >= 1
    assert recs[0].priority == "LOW"


# -----------------------------------------------------------------------------
# 10. Multiple Simultaneous Findings
# -----------------------------------------------------------------------------
def test_multiple_simultaneous_findings(engine: SecurityEngine):
    """Verify simultaneous presence of multiple weak parameters correctly aggregates."""
    report = engine.assess_configuration({
        "encryption": "3DES-CBC",
        "dh_group": 2,
        "pfs": False,
        "ike_version": "IKEv1",
    })

    rule_ids = {f.rule_id for f in report.findings}
    assert "CRYPTO_WEAK_CIPHER" in rule_ids
    assert "DH_GROUP_INSECURE" in rule_ids
    assert "PFS_DISABLED" in rule_ids
    assert "IKE_VERSION_DEPRECATED" in rule_ids

    # 3DES (30) + DH 2 (25) + PFS Disabled (20) + IKEv1 (20) = 95
    assert report.risk_score == 95
    assert report.severity == "CRITICAL"
    assert len(report.score_breakdown) == 4


# -----------------------------------------------------------------------------
# 11. Risk Score Calculation and Bands
# -----------------------------------------------------------------------------
def test_risk_score_calculation_and_bands():
    """Verify exact 0-100 scoring bands and bounds clamping."""
    scorer = RiskScoringEngine()

    assert scorer.map_severity(0) == "LOW"
    assert scorer.map_severity(24) == "LOW"
    assert scorer.map_severity(25) == "LOW-MEDIUM"
    assert scorer.map_severity(49) == "LOW-MEDIUM"
    assert scorer.map_severity(50) == "MEDIUM"
    assert scorer.map_severity(74) == "MEDIUM"
    assert scorer.map_severity(75) == "HIGH"
    assert scorer.map_severity(89) == "HIGH"
    assert scorer.map_severity(90) == "CRITICAL"
    assert scorer.map_severity(100) == "CRITICAL"

    # Clamp test: sum > 100 clamped to 100
    mock_findings = [
        SecurityFinding(
            id="VPN-001",
            title="Crit 1",
            severity="CRITICAL",
            category="Cryptography",
            description="desc",
            evidence=EvidenceItem(),
            risk_contribution=60,
        ),
        SecurityFinding(
            id="VPN-002",
            title="Crit 2",
            severity="CRITICAL",
            category="Key Exchange",
            description="desc",
            evidence=EvidenceItem(),
            risk_contribution=60,
        ),
    ]
    res = scorer.calculate(mock_findings)
    assert res["risk_score"] == 100
    assert res["severity"] == "CRITICAL"


# -----------------------------------------------------------------------------
# 12. Recommendation Generation
# -----------------------------------------------------------------------------
def test_recommendation_generation(engine: SecurityEngine):
    """Verify prioritized recommendation generation with actions."""
    report = engine.assess_configuration({
        "encryption": "3DES-CBC",
        "dh_group": 5,
        "pfs": False,
    })

    assert len(report.recommendations) >= 3

    priorities = [r.priority for r in report.recommendations]
    # CRITICAL should appear before MEDIUM
    assert priorities[0] == "CRITICAL"

    # Verify action text is concrete and actionable
    crit_rec = report.recommendations[0]
    assert "aes256gcm16" in crit_rec.action or "ChaCha20" in crit_rec.action or "esp" in crit_rec.action


# -----------------------------------------------------------------------------
# 13. Invalid Input Handling
# -----------------------------------------------------------------------------
def test_invalid_input_handling(engine: SecurityEngine):
    """Verify engine handles empty or unexpected input gracefully."""
    # Completely empty dict
    report = engine.assess_configuration({})
    assert isinstance(report, SecurityAssessmentReport)
    assert report.risk_score == 0
    assert report.severity == "LOW"

    # Garbage data types
    report2 = engine.assess_configuration({
        "encryption": 12345,
        "dh_group": "non_numeric_invalid_group",
        "pfs": "invalid_pfs_string",
    })
    assert isinstance(report2, SecurityAssessmentReport)
    assert 0 <= report2.risk_score <= 100


# -----------------------------------------------------------------------------
# 14. Missing Fields
# -----------------------------------------------------------------------------
def test_missing_fields_graceful_handling(engine: SecurityEngine):
    """Verify omitted fields default to UNKNOWN without raising errors."""
    report = engine.assess_configuration({
        "encryption": "AES-256-GCM",
        # dh_group omitted
        # pfs omitted
        # ike_version omitted
    })
    assert report.configuration.encryption.status == ObservationStatus.OBSERVED
    assert report.configuration.dh_group.status == ObservationStatus.UNKNOWN
    assert report.configuration.pfs.status == ObservationStatus.UNKNOWN
    assert report.configuration.ike_version.status == ObservationStatus.UNKNOWN
    assert len(report.limitations) >= 2


# -----------------------------------------------------------------------------
# 15. API Endpoint Tests for POST /security-assessment
# -----------------------------------------------------------------------------
def test_api_security_assessment_json_endpoint():
    """Verify POST /security-assessment accepts JSON configuration payload."""
    client = TestClient(app)

    payload = {
        "encryption": "AES-128-CBC",
        "dh_group": 5,
        "pfs": False,
        "ike_version": "IKEv2",
    }
    res = client.post("/security-assessment", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["risk_score"] == 60
    assert data["severity"] == "MEDIUM"
    assert len(data["findings"]) == 3
    assert len(data["recommendations"]) == 3
    assert len(data["score_breakdown"]) == 3


def test_api_security_assessment_pcap_endpoint(project_root: Path):
    """Verify POST /security-assessment accepts multipart PCAP upload."""
    client = TestClient(app)
    demo_pcap = project_root / "demo_data" / "demo_capture.pcap"

    with open(demo_pcap, "rb") as f:
        res = client.post(
            "/security-assessment",
            files={"file": ("demo_capture.pcap", f, "application/vnd.tcpdump.pcap")},
        )
    assert res.status_code == 200
    data = res.json()

    assert data["risk_score"] <= 20
    assert data["severity"] == "LOW"
    assert "configuration" in data
    assert "findings" in data
    assert "recommendations" in data
    assert "limitations" in data
