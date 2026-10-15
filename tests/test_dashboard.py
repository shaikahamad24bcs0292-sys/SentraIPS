"""
Automated unit and integration tests for SentraIPS Streamlit UI Dashboard (Phase 6).
Verifies headless execution, pipeline orchestration, and Streamlit AppTest simulation.
"""

from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest

from frontend.app import get_engines, run_full_assessment


@pytest.fixture(scope="module")
def weak_pcap_path(project_root: Path) -> Path:
    pcap = project_root / "demo_data" / "weak_capture.pcap"
    assert pcap.exists(), "weak_capture.pcap must exist"
    return pcap


@pytest.fixture(scope="module")
def demo_pcap_path(project_root: Path) -> Path:
    pcap = project_root / "demo_data" / "demo_capture.pcap"
    assert pcap.exists(), "demo_capture.pcap must exist"
    return pcap


@pytest.fixture(scope="module")
def ambiguous_pcap_path(project_root: Path) -> Path:
    pcap = project_root / "demo_data" / "ambiguous_capture.pcap"
    assert pcap.exists(), "ambiguous_capture.pcap must exist"
    return pcap


def test_dashboard_entrypoint_exists(project_root: Path):
    """Verifies that frontend/app.py exists and exports main orchestration symbols."""
    app_file = project_root / "frontend" / "app.py"
    assert app_file.exists(), "frontend/app.py must exist"
    assert app_file.stat().st_size > 5000, "frontend/app.py should contain complete dashboard logic"


def test_dashboard_engines_loading():
    """Verifies that get_engines loads and caches all 9 required engines."""
    engines = get_engines()
    required_keys = [
        "parser",
        "extractor",
        "security_engine",
        "rag_engine",
        "explainer",
        "arbiter",
        "exec_gen",
        "tech_gen",
        "pdf_gen",
    ]
    for key in required_keys:
        assert key in engines, f"Missing required engine key: {key}"
        assert engines[key] is not None, f"Engine {key} must not be None"


def test_dashboard_assessment_weak_pcap(weak_pcap_path: Path):
    """Verifies complete end-to-end pipeline assessment on weak_capture.pcap."""
    results = run_full_assessment(weak_pcap_path)

    assert "sec_report" in results
    assert "traffic_inference" in results
    assert "enriched_findings" in results
    assert "narrative" in results

    report = results["sec_report"]
    assert report.risk_score in (65, 75)
    assert report.severity == "HIGH"
    assert len(results["enriched_findings"]) == 5

    # Check evidence enrichment
    for _, ev, exp in results["enriched_findings"]:
        assert ev.references is not None
        assert len(exp.technical_explanation) > 10


def test_dashboard_assessment_secure_pcap(demo_pcap_path: Path):
    """Verifies pipeline assessment on compliant demo_capture.pcap."""
    results = run_full_assessment(demo_pcap_path)

    report = results["sec_report"]
    assert report.risk_score <= 20
    assert report.severity == "LOW"

    # AI concordant agreement check
    inference = results["traffic_inference"]
    assert inference.agreement is True
    assert inference.status == "classified"


def test_dashboard_assessment_ambiguous_pcap(ambiguous_pcap_path: Path):
    """Verifies pipeline assessment on ambiguous discordant capture (uncertainty trigger)."""
    results = run_full_assessment(ambiguous_pcap_path)

    inference = results["traffic_inference"]
    assert inference.agreement is False
    assert inference.final_prediction == "UNCERTAIN"
    assert inference.status == "investigation_required"


def test_dashboard_streamlit_apptest_run(project_root: Path):
    """Simulates Streamlit app execution using official AppTest framework (zero crashes/exceptions)."""
    app_path = project_root / "frontend" / "app.py"
    at = AppTest.from_file(str(app_path))
    
    # Run Streamlit script in headless simulation
    at.run(timeout=45)

    # Verify no unhandled exceptions occurred
    assert not at.exception, f"Streamlit application raised unhandled exception: {at.exception}"
    
    # Verify title or header was rendered
    assert len(at.tabs) >= 6 or len(at.markdown) > 0, "Dashboard elements should be mounted"
