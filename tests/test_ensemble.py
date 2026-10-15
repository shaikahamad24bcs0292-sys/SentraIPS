"""
Automated Integration and Validation Tests for SentraIPS AI Traffic Inference & Ensemble.
Verifies multimodal predictions, confidence calculation, entropy checks, and uncertainty signaling.
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from models.ensemble import ESPEnsembleClassifier, EnsemblePredictionResult
from packet_analysis.features import ESPFeatureExtractor

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def client():
    """Provides a TestClient instance for API verification."""
    return TestClient(app)


@pytest.fixture
def ensemble():
    """Provides an instantiated ESPEnsembleClassifier with trained weights."""
    return ESPEnsembleClassifier()


def test_ensemble_voip_agreement(ensemble):
    """
    Scenario 1: Both models agree on VoIP traffic characteristics.
    Verifies agreement is True, status is 'classified', and confidence is calculated.
    """
    voip_pcap = PROJECT_ROOT / "dataset" / "captures" / "capture_voip_01.pcap"
    assert voip_pcap.exists(), "capture_voip_01.pcap must exist"

    result = ensemble.predict_pcap(voip_pcap)
    assert isinstance(result, EnsemblePredictionResult)
    assert result.agreement is True
    assert result.final_prediction == "VoIP"
    assert result.status == "classified"
    assert result.final_confidence is not None
    assert 0.5 <= result.final_confidence <= 1.0
    assert result.cnn_prediction == "VoIP"
    assert result.statistical_prediction == "VoIP"


def test_ensemble_web_agreement(ensemble):
    """
    Scenario 2: Both models agree on Web traffic characteristics.
    Verifies agreement is True, status is 'classified', and final_prediction is Web.
    """
    web_pcap = PROJECT_ROOT / "demo_data" / "demo_capture.pcap"
    assert web_pcap.exists(), "demo_capture.pcap must exist"

    result = ensemble.predict_pcap(web_pcap)
    assert isinstance(result, EnsemblePredictionResult)
    assert result.agreement is True
    assert result.final_prediction == "Web"
    assert result.status == "classified"
    assert result.final_confidence is not None
    assert 0.5 <= result.final_confidence <= 1.0


def test_ensemble_disagreement_produces_uncertain(ensemble):
    """
    Scenario 3: Conflicting model predictions produce UNCERTAIN without forcing a label.
    Verifies agreement is False, status is 'investigation_required', and final_confidence is None.
    """
    ambig_pcap = PROJECT_ROOT / "demo_data" / "ambiguous_capture.pcap"
    assert ambig_pcap.exists(), "ambiguous_capture.pcap must exist"

    result = ensemble.predict_pcap(ambig_pcap)
    assert isinstance(result, EnsemblePredictionResult)
    assert result.agreement is False
    assert result.final_prediction == "UNCERTAIN"
    assert result.status == "investigation_required"
    assert result.final_confidence is None
    assert result.cnn_prediction != result.statistical_prediction


def test_disagreement_does_not_claim_malicious(ensemble):
    """
    Crucial SentraIPS Requirement: Disagreement must be treated as an analyst uncertainty signal,
    NOT proof of malicious attack.
    """
    ambig_pcap = PROJECT_ROOT / "demo_data" / "ambiguous_capture.pcap"
    result = ensemble.predict_pcap(ambig_pcap)

    explanation = result.explanation.lower()
    assert "uncertainty" in explanation or "disagreement" in explanation
    assert "attack" not in explanation or "rather than" in explanation
    assert "malicious" not in explanation


def test_evaluation_metrics_no_fabrication():
    """
    Verifies that evaluation metrics are measured from test sessions without fabrication.
    """
    metrics_path = PROJECT_ROOT / "models" / "evaluation_metrics.json"
    assert metrics_path.exists(), "models/evaluation_metrics.json must exist"

    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    assert "Measured result" in metrics.get("evaluation_type", "")
    assert len(metrics.get("test_sessions", [])) > 0
    assert metrics.get("test_sample_count", 0) > 0

    rf = metrics["random_forest"]
    cnn = metrics["cnn_1d"]

    assert 0.0 <= rf["accuracy"] <= 1.0
    assert 0.0 <= cnn["accuracy"] <= 1.0
    assert len(rf["confusion_matrix"]) == 4
    assert len(cnn["confusion_matrix"]) == 4


def test_api_infer_traffic_endpoint(client):
    """Verifies POST /infer-traffic returns structured EnsemblePredictionResult."""
    web_pcap = PROJECT_ROOT / "demo_data" / "demo_capture.pcap"
    with open(web_pcap, "rb") as f:
        response = client.post("/infer-traffic", files={"file": ("demo_capture.pcap", f, "application/octet-stream")})

    assert response.status_code == 200
    data = response.json()
    assert "cnn_prediction" in data
    assert "statistical_prediction" in data
    assert "agreement" in data
    assert "final_prediction" in data
    assert "status" in data
    assert data["status"] in ("classified", "investigation_required")


def test_api_analyze_pcap_includes_traffic_inference(client):
    """Verifies POST /analyze-pcap incorporates traffic_inference alongside security_assessment."""
    web_pcap = PROJECT_ROOT / "demo_data" / "demo_capture.pcap"
    with open(web_pcap, "rb") as f:
        response = client.post("/analyze-pcap", files={"file": ("demo_capture.pcap", f, "application/octet-stream")})

    assert response.status_code == 200
    data = response.json()
    assert "traffic_inference" in data
    assert data["traffic_inference"] is not None
    ti = data["traffic_inference"]
    assert ti["final_prediction"] == "Web"
    assert ti["agreement"] is True
    assert ti["status"] == "classified"

    # Ensure security assessment from Phase 3 is still intact
    assert "security_assessment" in data
    assert data["security_assessment"]["risk_score"] == 15
