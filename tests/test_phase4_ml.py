"""
Unit and integration tests for Phase 4 AI/ML Traffic Classification.
Tests:
- Valid feature vector validation
- Invalid feature vectors (missing features, NaN/Inf, negative values, empty, wrong type)
- Model loading from disk
- Missing model graceful fallback
- Real prediction over PCAP and feature vectors
- Low-confidence cutoff resulting in 'Unknown'
- Unknown classification for zero-ESP traffic
- API endpoint POST /predict-traffic (file upload and JSON body)
- API endpoint POST /analyze-pcap unified traffic_analysis
- Cryptographic parameter separation (ML never predicts cipher/DH/PFS)
- Insufficient dataset error reporting
"""

from pathlib import Path
import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from models.feature_schema import (
    FEATURE_NAMES,
    MODEL_CLASSES,
    TARGET_CLASSES,
    validate_feature_vector,
)
from models.model_manager import ModelManager
from models.predict import predict_traffic
from models.train import load_and_prepare_dataset

client = TestClient(app)


@pytest.fixture
def sample_valid_features() -> dict:
    """Returns a valid 27-feature ESP flow feature dictionary."""
    return {
        "total_packets": 190,
        "total_bytes": 35556,
        "forward_packets": 110,
        "backward_packets": 80,
        "packet_ratio_fwd_bwd": 1.375,
        "byte_ratio_fwd_bwd": 1.25,
        "flow_duration_sec": 2.13,
        "packets_per_sec": 89.2,
        "bytes_per_sec": 16692.9,
        "size_min": 60.0,
        "size_max": 1420.0,
        "size_mean": 187.1,
        "size_median": 120.0,
        "size_std": 198.4,
        "size_p25": 80.0,
        "size_p75": 240.0,
        "size_p90": 520.0,
        "size_skewness": 1.85,
        "iat_min_ms": 0.05,
        "iat_max_ms": 150.2,
        "iat_mean_ms": 11.28,
        "iat_median_ms": 4.5,
        "iat_std_ms": 18.9,
        "burst_count": 15,
        "mean_burst_size_pkts": 12.6,
        "mean_burst_duration_ms": 45.2,
        "mean_burst_bytes": 2370.0,
    }


# =====================================================================
# 1. Feature Vector Validation Tests
# =====================================================================

def test_valid_feature_vector(sample_valid_features):
    """Verify validate_feature_vector accepts a complete, valid dictionary."""
    is_valid, errors, arr = validate_feature_vector(sample_valid_features)
    assert is_valid is True
    assert len(errors) == 0
    assert arr is not None
    assert arr.shape == (len(FEATURE_NAMES),)
    assert arr.dtype == np.float32


def test_invalid_feature_vector_missing_feature(sample_valid_features):
    """Verify validation fails when required features are missing."""
    incomplete = sample_valid_features.copy()
    del incomplete["flow_duration_sec"]
    del incomplete["iat_mean_ms"]

    is_valid, errors, arr = validate_feature_vector(incomplete)
    assert is_valid is False
    assert arr is None
    assert any("flow_duration_sec" in err for err in errors)
    assert any("iat_mean_ms" in err for err in errors)


def test_invalid_feature_vector_nan_inf(sample_valid_features):
    """Verify validation catches NaN and Inf feature values."""
    corrupted_nan = sample_valid_features.copy()
    corrupted_nan["size_mean"] = float("nan")

    is_valid, errors, _ = validate_feature_vector(corrupted_nan)
    assert is_valid is False
    assert any("NaN" in err for err in errors)

    corrupted_inf = sample_valid_features.copy()
    corrupted_inf["bytes_per_sec"] = float("inf")
    is_valid, errors, _ = validate_feature_vector(corrupted_inf)
    assert is_valid is False
    assert any("infinity" in err.lower() for err in errors)


def test_invalid_feature_vector_negative_counts(sample_valid_features):
    """Verify validation rejects non-physical negative packet counts or durations."""
    negative_pkts = sample_valid_features.copy()
    negative_pkts["total_packets"] = -5

    is_valid, errors, _ = validate_feature_vector(negative_pkts)
    assert is_valid is False
    assert any("total_packets" in err and "negative" in err for err in errors)


def test_invalid_feature_vector_empty_and_types():
    """Verify validation handles empty dictionaries and invalid input types."""
    is_valid, errors, _ = validate_feature_vector({})
    assert is_valid is False
    assert "empty" in errors[0].lower()

    is_valid, errors, _ = validate_feature_vector(["not", "a", "dict"])
    assert is_valid is False


# =====================================================================
# 2. Model Loading & Missing Model Fallback Tests
# =====================================================================

def test_model_loading():
    """Verify ModelManager loads the trained Random Forest bundle from disk."""
    manager = ModelManager()
    assert manager.is_loaded is True
    assert manager.model is not None
    assert manager.scaler is not None
    assert len(manager.classes) > 0
    assert manager.model_path.exists()


def test_model_missing_graceful_fallback(tmp_path, sample_valid_features):
    """Verify ModelManager handles a missing model file gracefully without crashing."""
    nonexistent = tmp_path / "missing_model.joblib"
    manager = ModelManager(model_path=nonexistent)
    assert manager.is_loaded is False
    assert manager.model is None

    # Predict should gracefully fall back to statistical heuristic
    res = manager.predict(sample_valid_features)
    assert isinstance(res, dict)
    assert "traffic_class" in res
    assert res["traffic_class"] in TARGET_CLASSES
    assert 0.0 <= res["confidence"] <= 1.0
    assert res["model"] == "RandomForest"


# =====================================================================
# 3. Prediction & Confidence Threshold Tests
# =====================================================================

def test_prediction_from_demo_pcap(project_root: Path):
    """Verify predict_traffic on demo_capture.pcap correctly predicts Web traffic."""
    demo_pcap = project_root / "demo_data" / "demo_capture.pcap"
    assert demo_pcap.exists()

    result = predict_traffic(demo_pcap)
    assert result["traffic_class"] == "Web"
    assert result["confidence"] > 0.50
    assert result["model"] == "RandomForest"
    assert "probabilities" in result
    assert "Web" in result["probabilities"]


def test_prediction_from_dict(sample_valid_features):
    """Verify predict_traffic directly over feature dictionary."""
    result = predict_traffic(sample_valid_features)
    assert result["traffic_class"] in MODEL_CLASSES
    assert 0.0 <= result["confidence"] <= 1.0
    assert result["model"] == "RandomForest"


def test_low_confidence_threshold_returns_unknown(sample_valid_features):
    """Verify that when confidence is below the threshold, traffic_class becomes 'Unknown'."""
    # Setting an impossible threshold (0.999999) forces the threshold cutoff
    result = predict_traffic(sample_valid_features, confidence_threshold=0.999999)
    assert result["traffic_class"] == "Unknown"
    # Genuine confidence is still reported, not fabricated
    assert result["confidence"] < 0.999999
    assert result["model"] == "RandomForest"


def test_unknown_classification_for_empty_capture(tmp_path):
    """Verify that a capture without ESP packets yields 'Unknown' with 0.0 confidence."""
    # Create empty dummy file
    empty_pcap = tmp_path / "empty.pcap"
    empty_pcap.write_bytes(b"")

    result = predict_traffic(empty_pcap)
    assert result["traffic_class"] == "Unknown"
    assert result["confidence"] == 0.0


# =====================================================================
# 4. Cryptographic Parameter Separation Rule
# =====================================================================

def test_cryptographic_separation_rule(project_root: Path):
    """
    CRITICAL SECURITY RULE:
    The ML model must NEVER determine encryption, DH group, PFS, IKE version, or authentication.
    Ensure predict_traffic does not expose or infer any cryptographic keys or cipher suites.
    """
    demo_pcap = project_root / "demo_data" / "demo_capture.pcap"
    result = predict_traffic(demo_pcap)

    forbidden_crypto_keys = [
        "encryption", "cipher", "dh_group", "pfs", "ike_version",
        "authentication", "integrity", "prf", "esp_encryption"
    ]
    for key in forbidden_crypto_keys:
        assert key not in result, f"Security Violation: ML prediction leaked cryptographic key '{key}'"


# =====================================================================
# 5. API Integration Tests
# =====================================================================

def test_api_predict_traffic_pcap_upload(project_root: Path):
    """Verify POST /predict-traffic endpoint with PCAP upload."""
    demo_pcap = project_root / "demo_data" / "demo_capture.pcap"
    assert demo_pcap.exists()

    with open(demo_pcap, "rb") as f:
        response = client.post(
            "/predict-traffic",
            files={"file": ("demo_capture.pcap", f, "application/vnd.tcpdump.pcap")},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["traffic_class"] == "Web"
    assert data["confidence"] > 0.50
    assert data["model"] == "RandomForest"
    assert "probabilities" in data


def test_api_predict_traffic_json_body(sample_valid_features):
    """Verify POST /predict-traffic endpoint with JSON feature vector."""
    response = client.post("/predict-traffic", json=sample_valid_features)
    assert response.status_code == 200
    data = response.json()
    assert data["traffic_class"] in MODEL_CLASSES
    assert 0.0 <= data["confidence"] <= 1.0
    assert data["model"] == "RandomForest"


def test_api_predict_traffic_invalid_extension():
    """Verify POST /predict-traffic rejects non-pcap files."""
    response = client.post(
        "/predict-traffic",
        files={"file": ("invalid.txt", b"plain text payload", "text/plain")},
    )
    assert response.status_code == 400
    assert "unsupported file extension" in response.json()["detail"].lower()


def test_api_analyze_pcap_includes_traffic_analysis(project_root: Path):
    """Verify unified POST /analyze-pcap response contains the required traffic_analysis section."""
    demo_pcap = project_root / "demo_data" / "demo_capture.pcap"
    assert demo_pcap.exists()

    with open(demo_pcap, "rb") as f:
        response = client.post(
            "/analyze-pcap",
            files={"file": ("demo_capture.pcap", f, "application/vnd.tcpdump.pcap")},
        )

    assert response.status_code == 200
    data = response.json()

    # Unified analysis response must contain traffic_analysis
    assert "traffic_analysis" in data
    assert data["traffic_analysis"] is not None
    ta = data["traffic_analysis"]
    assert ta["classification"] == "Web"
    assert ta["confidence"] > 0.50
    assert ta["model"] == "RandomForest"


# =====================================================================
# 6. Insufficient Dataset Handling Test
# =====================================================================

def test_insufficient_dataset_handling(tmp_path):
    """Verify load_and_prepare_dataset raises ValueError when dataset is insufficient or empty."""
    empty_dir = tmp_path / "empty_workspace"
    empty_dir.mkdir(parents=True, exist_ok=True)

    with pytest.raises(ValueError) as excinfo:
        load_and_prepare_dataset(empty_dir)

    assert "Insufficient dataset" in str(excinfo.value)
