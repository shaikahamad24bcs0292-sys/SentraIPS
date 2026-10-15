"""
Phase 5 Test Suite for Knowledge Base, Compliance Evaluation, and Automated Reporting.

Tests:
1. Knowledge Base Loading and Schema Integrity
2. Compliance Engine Evaluation (PASS, WARNING, FAIL, UNKNOWN)
3. Standards & RFC References Verification
4. JSON Report Generation & Schema Conformance
5. HTML Report Generation & Offline Standalone Validation (no external CDN)
6. End-to-End Report Generation Pipeline
7. FastAPI Reporting Endpoints (POST /reports/generate, GET /reports/{id}, GET /reports/{id}/html, GET /reports)
8. Graceful Handling of Unknowns and Missing Fields
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from knowledge_base.compliance_engine import (
    ComplianceEngine,
    ComplianceCheckItem,
    ComplianceEvaluationResult,
)
from reporting.json_report import JSONReportGenerator
from reporting.html_report import HTMLReportGenerator
from reporting.report_generator import ReportGenerator
from reporting.report_schema import (
    SecurityAssessmentReportUnified,
    ReportExecutiveSummary,
    ReportVPNConfiguration,
    ReportTrafficAnalysis,
    ReportFinding,
    ReportComplianceItem,
    ReportRecommendation,
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def compliance_engine(project_root: Path) -> ComplianceEngine:
    kb_path = project_root / "knowledge_base" / "knowledge_base.json"
    return ComplianceEngine(kb_path=kb_path)


@pytest.fixture
def report_generator(project_root: Path) -> ReportGenerator:
    return ReportGenerator(output_dir=project_root / "reports")


@pytest.fixture
def sample_unified_report() -> SecurityAssessmentReportUnified:
    return SecurityAssessmentReportUnified(
        report_id="test_audit_001",
        timestamp="2026-10-06T00:00:00Z",
        summary=ReportExecutiveSummary(
            analysis_id="test_audit_001",
            timestamp="2026-10-06T00:00:00Z",
            overall_risk_score=15,
            severity="LOW",
            ipsec_detected=True,
            ike_version="IKEv2",
            encryption="AES-256-GCM",
            dh_group="Group 19 (ecp256)",
            pfs="Enabled",
            traffic_classification="Web",
            traffic_confidence=0.98,
            compliance_rating="COMPLIANT",
            summary_narrative="Test assessment completed with low risk profile.",
        ),
        vpn_configuration=ReportVPNConfiguration(
            vpn_mode="Tunnel",
            ike_version="IKEv2",
            encryption="AES-256-GCM",
            authentication="SHA-256",
            dh_group="ecp256",
            dh_group_number=19,
            pfs="Enabled",
            esp_detected=True,
            esp_packet_count=100,
            spi_list=["0x12345678", "0x87654321"],
            initiator_spi="0x1111222233334444",
            responder_spi="0x5555666677778888",
        ),
        traffic_analysis=ReportTrafficAnalysis(
            traffic_type="Web",
            confidence=0.98,
            ml_confidence=0.98,
            model_used="RandomForest",
            packet_count=100,
            flow_duration_sec=12.5,
            mean_packet_size=650.0,
            std_packet_size=320.0,
            min_packet_size=64,
            max_packet_size=1420,
            mean_iat_ms=25.4,
            burst_count=8,
            is_inferred=True,
        ),
        security_assessment={
            "risk_score": 15,
            "severity": "LOW",
            "findings_count": 1,
        },
        findings=[
            ReportFinding(
                id="VPN-TEST-01",
                title="Low Risk Test Finding",
                severity="LOW",
                category="Configuration",
                description="Test description for verification.",
                evidence={"test_field": "test_val"},
                impact="Minimal security exposure.",
                recommendation="Monitor traffic periodically.",
                confidence=1.0,
                source="Observed",
                references=["NIST SP 800-77 Rev. 1"],
            )
        ],
        compliance=[
            ReportComplianceItem(
                id="COMP-ENC-01",
                category="Encryption",
                parameter="encryption",
                observed_value="AES-256-GCM",
                status="PASS",
                standard="NIST SP 800-77 Rev. 1 / RFC 8221",
                details="AES-256-GCM meets federal and commercial recommendations.",
                recommendation="Retain AES-256-GCM.",
                references=["NIST SP 800-77 Rev. 1", "RFC 8221"],
            )
        ],
        compliance_summary={"passed": 1, "warnings": 0, "failed": 0, "unknown": 0},
        recommendations=[
            ReportRecommendation(
                id="REC-001",
                priority="LOW",
                title="Periodic Review",
                action="Review cryptographic settings every 90 days.",
                target_parameter="General",
                rationale="Best practice routine audit.",
            )
        ],
        limitations=[
            "Encrypted ESP payload contents were never decrypted.",
            "ML traffic classification is probabilistic inference based on outer header metrics.",
        ],
    )


# =============================================================================
# 1. Knowledge Base Tests
# =============================================================================
def test_knowledge_base_loading(compliance_engine: ComplianceEngine):
    """Verify knowledge base loads all verified rules and matches schema."""
    rules = compliance_engine.get_all_rules()
    assert len(rules) >= 10, f"Expected at least 10 knowledge rules, found {len(rules)}"
    
    # Check key rule IDs exist
    rule_ids = {r.id for r in rules}
    assert "VPN-ENC-001" in rule_ids
    assert "VPN-ENC-002" in rule_ids
    assert "VPN-ENC-003" in rule_ids
    assert "VPN-DH-001" in rule_ids
    assert "VPN-DH-002" in rule_ids
    assert "VPN-DH-003" in rule_ids
    assert "VPN-PFS-001" in rule_ids
    assert "VPN-IKE-001" in rule_ids


def test_knowledge_base_standards_references(compliance_engine: ComplianceEngine):
    """Verify every knowledge base rule has genuine standards references (RFC or NIST)."""
    rules = compliance_engine.get_all_rules()
    for rule in rules:
        assert len(rule.references) > 0, f"Rule {rule.id} has no references!"
        refs_str = " ".join([f"{ref.source} {ref.title}" for ref in rule.references])
        # Must cite RFC or NIST or IANA
        assert any(std in refs_str for std in ["RFC", "NIST", "IANA"]), (
            f"Rule {rule.id} lacks standard reference: {refs_str}"
        )


def test_knowledge_base_lookup(compliance_engine: ComplianceEngine):
    """Verify rule lookup by ID and Category."""
    rule = compliance_engine.get_rule_by_id("VPN-ENC-001")
    assert rule is not None
    assert rule.category == "Cryptography"
    assert "Cipher" in rule.title

    dh_rules = compliance_engine.get_rules_by_category("Key Exchange")
    assert len(dh_rules) >= 3


# =============================================================================
# 2. Compliance Evaluation Tests
# =============================================================================
def test_compliance_evaluation_strong_config(compliance_engine: ComplianceEngine):
    """Verify modern recommended configuration receives PASS results."""
    eval_result = compliance_engine.evaluate_configuration({
        "encryption": "AES-256-GCM",
        "dh_group": 19,
        "pfs": True,
        "ike_version": "IKEv2",
        "auth": "SHA-256",
        "mode": "tunnel",
        "esp_present": True,
        "esp_packet_count": 50,
        "spi_count": 2,
    })

    assert eval_result.overall_status in ("COMPLIANT", "ACCEPTABLE")
    assert eval_result.summary["failed"] == 0
    assert eval_result.summary["passed"] >= 5

    # Check specific item statuses
    enc_item = next(i for i in eval_result.items if i.parameter == "encryption")
    assert enc_item.status == "PASS"

    dh_item = next(i for i in eval_result.items if i.parameter == "dh_group")
    assert dh_item.status == "PASS"

    pfs_item = next(i for i in eval_result.items if i.parameter == "pfs")
    assert pfs_item.status == "PASS"

    ike_item = next(i for i in eval_result.items if i.parameter == "ike_version")
    assert ike_item.status == "PASS"


def test_compliance_evaluation_weak_config(compliance_engine: ComplianceEngine):
    """Verify legacy/weak configuration triggers FAIL and WARNING statuses."""
    eval_result = compliance_engine.evaluate_configuration({
        "encryption": "3DES",
        "dh_group": 5,
        "pfs": False,
        "ike_version": "IKEv1",
        "auth": "MD5",
        "mode": "transport",
        "esp_present": False,
    })

    assert eval_result.overall_status == "NON_COMPLIANT"
    assert eval_result.summary["failed"] >= 2
    assert eval_result.summary["warnings"] >= 1

    # Check 3DES fails
    enc_item = next(i for i in eval_result.items if i.parameter == "encryption")
    assert enc_item.status == "FAIL"

    # Check DH 5 warning
    dh_item = next(i for i in eval_result.items if i.parameter == "dh_group")
    assert dh_item.status == "WARNING"

    # Check PFS disabled warning
    pfs_item = next(i for i in eval_result.items if i.parameter == "pfs")
    assert pfs_item.status == "WARNING"

    # Check IKEv1 fail/warning
    ike_item = next(i for i in eval_result.items if i.parameter == "ike_version")
    assert ike_item.status == "FAIL"


def test_compliance_evaluation_unknown_parameters(compliance_engine: ComplianceEngine):
    """Verify unknown or missing parameters return UNKNOWN without false positives."""
    eval_result = compliance_engine.evaluate_configuration({
        "encryption": "Unknown / Not Detected",
        "dh_group": None,
        "pfs": None,
        "ike_version": "Unknown",
    })

    # Should report UNKNOWN, not FAIL
    enc_item = next(i for i in eval_result.items if i.parameter == "encryption")
    assert enc_item.status == "UNKNOWN"

    dh_item = next(i for i in eval_result.items if i.parameter == "dh_group")
    assert dh_item.status == "UNKNOWN"

    pfs_item = next(i for i in eval_result.items if i.parameter == "pfs")
    assert pfs_item.status == "UNKNOWN"


# =============================================================================
# 3. JSON and HTML Report Generators
# =============================================================================
def test_json_report_generation(sample_unified_report: SecurityAssessmentReportUnified, tmp_path: Path):
    """Verify JSON report serializes accurately and conforms to schema."""
    json_path = tmp_path / "test_report.json"
    json_str = JSONReportGenerator.save_to_file(sample_unified_report, json_path)
    
    assert json_path.exists()
    data = json.loads(json_str)
    assert data["report_id"] == "test_audit_001"
    assert data["summary"]["overall_risk_score"] == 15
    assert data["summary"]["compliance_rating"] == "COMPLIANT"
    assert data["vpn_configuration"]["encryption"] == "AES-256-GCM"
    assert len(data["compliance"]) == 1
    assert data["compliance"][0]["status"] == "PASS"
    assert len(data["limitations"]) == 2


def test_html_report_generation_offline(sample_unified_report: SecurityAssessmentReportUnified, tmp_path: Path):
    """Verify HTML report renders valid offline HTML with no external CDN references."""
    html_path = tmp_path / "test_report.html"
    html_content = HTMLReportGenerator.render_and_save(sample_unified_report, html_path)

    assert html_path.exists()
    assert "<!DOCTYPE html>" in html_content
    assert "SentraIPS Security" in html_content
    assert "test_audit_001" in html_content
    assert "AES-256-GCM" in html_content
    assert "LOW" in html_content

    # Strict check: Must not include external CDNs for offline operation
    assert "http://" not in html_content
    assert "https://cdnjs" not in html_content
    assert "https://fonts" not in html_content
    assert "https://cdn" not in html_content

    # Check presence of mandatory sections
    assert "Risk Score" in html_content or "Executive" in html_content
    assert "Observed VPN Protocol Configuration" in html_content
    assert "Traffic Metadata Classification" in html_content
    assert "Security Findings" in html_content
    assert "Compliance &amp; Best Practice Matrix" in html_content or "Compliance" in html_content
    assert "Prioritized Remediation Roadmap" in html_content
    assert "Audit Limitations &amp; Security Boundaries" in html_content or "Audit Limitations" in html_content


# =============================================================================
# 4. End-to-End Report Generation Pipeline
# =============================================================================
def test_e2e_report_generation(report_generator: ReportGenerator, project_root: Path):
    """Run full Phase 5 report generation from pcap capture file."""
    pcap_path = project_root / "demo_data" / "demo_capture.pcap"
    assert pcap_path.exists(), "demo_capture.pcap must exist"

    report, json_p, html_p = report_generator.generate_report(pcap_path)

    assert isinstance(report, SecurityAssessmentReportUnified)
    assert json_p.exists()
    assert html_p.exists()

    assert report.summary.ipsec_detected is True
    assert report.summary.overall_risk_score >= 0
    assert report.summary.overall_risk_score <= 100
    assert report.traffic_analysis.traffic_type in [
        "Web", "Video", "VoIP", "ICMP", "Bulk/Data Transfer", "Unknown"
    ]
    assert len(report.compliance) > 0
    assert len(report.limitations) > 0


# =============================================================================
# 5. FastAPI Reporting Endpoints
# =============================================================================
def test_api_generate_report(client: TestClient, project_root: Path):
    """Verify POST /reports/generate processes PCAP upload and returns report."""
    pcap_path = project_root / "demo_data" / "demo_capture.pcap"
    with open(pcap_path, "rb") as f:
        response = client.post(
            "/reports/generate",
            files={"file": ("demo_capture.pcap", f, "application/octet-stream")}
        )

    assert response.status_code == 200
    data = response.json()
    assert "report_id" in data
    assert "summary" in data
    assert "compliance" in data
    assert "html_url" in data
    assert "json_url" in data

    report_id = data["report_id"]

    # Test GET /reports/{report_id}
    get_res = client.get(f"/reports/{report_id}")
    assert get_res.status_code == 200
    assert get_res.json()["report_id"] == report_id

    # Test GET /reports/{report_id}/html
    html_res = client.get(f"/reports/{report_id}/html")
    assert html_res.status_code == 200
    assert "text/html" in html_res.headers["content-type"]
    assert "<!DOCTYPE html>" in html_res.text


def test_api_get_nonexistent_report(client: TestClient):
    """Verify 404 response for unknown report ID."""
    res = client.get("/reports/non_existent_id_999999")
    assert res.status_code == 404


def test_api_list_reports(client: TestClient):
    """Verify GET /reports returns list of generated reports."""
    res = client.get("/reports")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, dict)
    assert "reports" in data
    assert isinstance(data["reports"], list)

