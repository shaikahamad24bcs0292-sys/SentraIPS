"""
Unit and integration tests for Deterministic Security Engine (Phase 3).
Verifies rule execution, risk scoring, threat matrix, evidence chains, and reproducibility.
"""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from packet_analysis.parser import IPsecPCAPParser, PCAPParseResult, IKEAnalysisResult, ESPAnalysisResult
from security_engine import SecurityEngine, SecurityAssessmentReport
from backend.main import app


@pytest.fixture
def secure_pcap(project_root: Path) -> Path:
    pcap = project_root / "demo_data" / "demo_capture.pcap"
    assert pcap.exists()
    return pcap


@pytest.fixture
def weak_pcap(project_root: Path) -> Path:
    pcap = project_root / "demo_data" / "weak_capture.pcap"
    assert pcap.exists()
    return pcap


@pytest.fixture
def engine(project_root: Path) -> SecurityEngine:
    config_file = project_root / "security_engine" / "config.yaml"
    return SecurityEngine(config_path=config_file)


def test_secure_pcap_evaluation(engine: SecurityEngine, secure_pcap: Path):
    """Verify secure PCAP (AES-256-GCM, DH 19, PFS Enabled) yields LOW risk score."""
    report = engine.assess_pcap_file(secure_pcap)

    assert isinstance(report, SecurityAssessmentReport)
    assert report.risk_score <= 20, f"Expected LOW risk (<=20), got {report.risk_score}"
    assert report.severity == "LOW"
    assert report.sub_scores.crypto_risk == 0
    assert report.sub_scores.key_exchange_risk == 0
    assert report.is_deterministic is True

    # Confirm threat matrix has no critical or high severity findings
    assert report.threat_matrix.critical_count == 0
    assert report.threat_matrix.high_count == 0


def test_weak_pcap_evaluation(engine: SecurityEngine, weak_pcap: Path):
    """Verify weak PCAP (AES-128-CBC, DH 5, PFS Disabled) yields HIGH risk score."""
    report = engine.assess_pcap_file(weak_pcap)

    assert isinstance(report, SecurityAssessmentReport)
    assert report.risk_score >= 50, f"Expected HIGH risk (>=50), got {report.risk_score}"
    assert report.severity in ("HIGH", "CRITICAL")
    assert report.sub_scores.crypto_risk >= 15  # Non-AEAD CBC
    assert report.sub_scores.key_exchange_risk >= 35  # DH 5 + PFS disabled

    # Verify specific findings triggered
    rule_ids = [f.rule_id for f in report.threat_matrix.findings]
    assert "CRYPTO_LEGACY_NON_AEAD" in rule_ids
    assert "DH_GROUP_LEGACY" in rule_ids
    assert "PFS_DISABLED" in rule_ids


def test_weak_cipher_rule_trigger(engine: SecurityEngine):
    """Verify 3DES triggers CRYPTO_WEAK_CIPHER with +30 risk points."""
    mock_parse = PCAPParseResult(
        capture_id="mock_3des",
        filename="mock.pcap",
        file_size_bytes=1000,
        is_valid=True,
        ipsec_detected=True,
        ike_detected=True,
        esp_detected=True,
        total_packets=10,
        ike=IKEAnalysisResult(detected=True, encryption="3DES-CBC", dh_group=19),
        esp=ESPAnalysisResult(detected=True, packet_count=5),
    )

    findings = engine.rule_evaluator.evaluate(mock_parse)
    finding_rules = [f.rule_id for f in findings]
    assert "CRYPTO_WEAK_CIPHER" in finding_rules
    crypto_f = next(f for f in findings if f.rule_id == "CRYPTO_WEAK_CIPHER")
    assert crypto_f.severity == "CRITICAL"
    assert crypto_f.risk_contribution == 30


def test_insecure_dh_group_rule_trigger(engine: SecurityEngine):
    """Verify DH Group 2 triggers DH_GROUP_INSECURE with +25 risk points."""
    mock_parse = PCAPParseResult(
        capture_id="mock_dh2",
        filename="mock.pcap",
        file_size_bytes=1000,
        is_valid=True,
        ipsec_detected=True,
        ike_detected=True,
        total_packets=10,
        ike=IKEAnalysisResult(detected=True, encryption="AES-256-GCM", dh_group=2, dh_group_name="modp1024"),
    )

    findings = engine.rule_evaluator.evaluate(mock_parse)
    finding_rules = [f.rule_id for f in findings]
    assert "DH_GROUP_INSECURE" in finding_rules
    dh_f = next(f for f in findings if f.rule_id == "DH_GROUP_INSECURE")
    assert dh_f.severity == "CRITICAL"
    assert dh_f.risk_contribution == 25


def test_score_bounded_in_0_to_100(engine: SecurityEngine):
    """Verify normalization ensures risk score strictly remains in [0, 100]."""
    # Worst case: multiple critical violations
    worst_case_parse = PCAPParseResult(
        capture_id="mock_worst",
        filename="worst.pcap",
        file_size_bytes=1000,
        is_valid=True,
        ipsec_detected=True,
        ike_detected=True,
        esp_detected=True,
        total_packets=10,
        ike=IKEAnalysisResult(
            detected=True,
            version="IKEv1",
            encryption="3DES-CBC",
            encryption_key_length=56,
            authentication="HMAC-MD5",
            dh_group=1,
            pfs=False,
        ),
        esp=ESPAnalysisResult(detected=True, packet_count=5),
    )

    report = engine.assess_parsed_pcap(worst_case_parse)
    assert 0 <= report.risk_score <= 100
    assert report.risk_score == 100  # Max clamp
    assert report.severity == "CRITICAL"


def test_deterministic_reproducibility(engine: SecurityEngine, weak_pcap: Path):
    """Verify that multiple evaluations of identical captures produce identical scores."""
    scores = []
    findings_counts = []
    for _ in range(5):
        rep = engine.assess_pcap_file(weak_pcap)
        scores.append(rep.risk_score)
        findings_counts.append(rep.threat_matrix.total_findings)

    assert len(set(scores)) == 1, "Scores varied across runs; evaluation must be 100% deterministic"
    assert len(set(findings_counts)) == 1, "Finding counts varied across runs"


def test_evidence_chain_integrity(engine: SecurityEngine, weak_pcap: Path):
    """Verify that every finding includes concrete observed evidence and recommendations."""
    report = engine.assess_pcap_file(weak_pcap)
    for finding in report.threat_matrix.findings:
        assert finding.finding_id.startswith("F")
        assert len(finding.title) > 0
        assert len(finding.recommendation) > 0
        assert finding.evidence.observed_field != ""
        assert finding.evidence.observed_value is not None
        assert finding.evidence.packet_source != ""
        assert finding.evidence.rule_criterion != ""


def test_api_evaluate_security_endpoints(secure_pcap: Path, weak_pcap: Path):
    """Verify /evaluate-security and /analyze-pcap FastAPI endpoints include security assessment."""
    client = TestClient(app)

    # 1. Test /evaluate-security with secure capture
    with open(secure_pcap, "rb") as f:
        res_sec = client.post(
            "/evaluate-security",
            files={"file": ("demo_capture.pcap", f, "application/vnd.tcpdump.pcap")},
        )
    assert res_sec.status_code == 200
    sec_data = res_sec.json()
    assert sec_data["risk_score"] <= 20
    assert sec_data["severity"] == "LOW"

    # 2. Test /evaluate-security with weak capture
    with open(weak_pcap, "rb") as f:
        res_weak = client.post(
            "/evaluate-security",
            files={"file": ("weak_capture.pcap", f, "application/vnd.tcpdump.pcap")},
        )
    assert res_weak.status_code == 200
    weak_data = res_weak.json()
    assert weak_data["risk_score"] >= 40
    assert weak_data["severity"] in ("MEDIUM", "HIGH", "CRITICAL")
