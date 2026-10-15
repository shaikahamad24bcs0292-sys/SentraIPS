"""
Automated Unit Tests for SentraIPS AI Models (1D-CNN and Random Forest).
Verifies tensor dimensions, forward passes, serialization, and statistical pipelines.
"""

from pathlib import Path
import tempfile
import numpy as np
import pytest
import torch

from models.cnn_model import ESP1DCNN, CLASSES, CLASS_TO_IDX, IDX_TO_CLASS, SEQUENCE_LENGTH, NUM_CHANNELS
from models.statistical_model import ESPStatisticalModel, FEATURE_NAMES
from packet_analysis.features import ESPTrafficFeatures


@pytest.fixture
def dummy_features():
    """Provides representative ESP traffic features for unit testing."""
    return ESPTrafficFeatures(
        total_packets=50,
        total_bytes=12000,
        forward_packets=25,
        backward_packets=25,
        packet_ratio_fwd_bwd=1.0,
        byte_ratio_fwd_bwd=1.0,
        flow_duration_sec=1.5,
        packets_per_sec=33.3,
        bytes_per_sec=8000.0,
        size_min=64,
        size_max=1200,
        size_mean=240.0,
        size_median=180.0,
        size_std=150.0,
        size_p25=120.0,
        size_p75=300.0,
        size_p90=600.0,
        size_skewness=1.2,
        iat_min_ms=0.5,
        iat_max_ms=45.0,
        iat_mean_ms=15.0,
        iat_median_ms=10.0,
        iat_std_ms=8.0,
        burst_count=3,
        mean_burst_size_pkts=16.6,
        mean_burst_duration_ms=400.0,
        mean_burst_bytes=4000.0,
        packet_size_sequence=[160, 240, 160, 160, 500, 120] + [160] * 58,
        iat_sequence_ms=[20.0, 15.0, 20.0, 19.5, 50.0, 20.0] + [20.0] * 58,
        direction_sequence=[1, -1, 1, 1, -1, 1] + [1] * 58,
    )


def test_cnn_model_architecture_and_forward():
    """Verifies that 1D-CNN processes input tensors of shape (B, 3, 64) and produces (B, 4) logits."""
    model = ESP1DCNN(num_classes=len(CLASSES), in_channels=NUM_CHANNELS, seq_len=SEQUENCE_LENGTH)
    batch_size = 4
    x = torch.randn(batch_size, NUM_CHANNELS, SEQUENCE_LENGTH)
    logits = model(x)

    assert logits.shape == (batch_size, len(CLASSES)), f"Expected shape ({batch_size}, 4), got {logits.shape}"
    probs = torch.softmax(logits, dim=1)
    sums = probs.sum(dim=1).detach().numpy()
    assert np.allclose(sums, 1.0, atol=1e-5), "Softmax probabilities must sum to 1.0"


def test_cnn_features_to_tensor_conversion(dummy_features):
    """Verifies conversion of ESPTrafficFeatures to normalized 3-channel PyTorch tensor."""
    tensor = ESP1DCNN.features_to_tensor(dummy_features, seq_len=SEQUENCE_LENGTH)
    assert tensor.shape == (1, 3, SEQUENCE_LENGTH)
    assert tensor.dtype == torch.float32

    # Check normalization ranges
    sizes_ch = tensor[0, 0].numpy()
    dirs_ch = tensor[0, 1].numpy()
    iats_ch = tensor[0, 2].numpy()

    assert np.all((sizes_ch >= 0.0) & (sizes_ch <= 1.0)), "Sizes channel must be normalized to [0, 1]"
    assert np.all(np.isin(dirs_ch, [-1.0, 0.0, 1.0])), "Directions channel must be -1, 0, or 1"
    assert np.all((iats_ch >= 0.0) & (iats_ch <= 1.0)), "IAT channel must be normalized to [0, 1]"


def test_cnn_prediction_output(dummy_features):
    """Verifies predict() returns valid class name, confidence in [0, 1], and probabilities dict."""
    model = ESP1DCNN()
    tensor = model.features_to_tensor(dummy_features)
    pred_class, confidence, probs_dict = model.predict(tensor)

    assert pred_class in CLASSES
    assert 0.0 <= confidence <= 1.0
    assert len(probs_dict) == len(CLASSES)
    assert abs(sum(probs_dict.values()) - 1.0) < 0.01


def test_statistical_model_feature_array_conversion(dummy_features):
    """Verifies 27 flat features are converted correctly into 1D numpy array."""
    model = ESPStatisticalModel()
    arr = model._dict_to_array(dummy_features.to_flat_dict())
    assert arr.shape == (27,)
    assert not np.isnan(arr).any(), "Feature vector must not contain NaNs"
    assert not np.isinf(arr).any(), "Feature vector must not contain Infs"


def test_statistical_model_fit_and_prediction():
    """Verifies that Random Forest fits training data and outputs valid predictions."""
    model = ESPStatisticalModel(n_estimators=10, max_depth=4, random_state=42)
    # Generate synthetic training batch
    X = np.random.randn(20, 27).astype(np.float32)
    y = ["Web"] * 5 + ["VoIP"] * 5 + ["ICMP"] * 5 + ["Video"] * 5

    model.fit(X, y)
    assert model.is_fitted is True

    # Test prediction on single sample
    sample = {name: float(np.random.rand()) for name in FEATURE_NAMES}
    pred_class, conf, probs = model.predict_dict(sample)

    assert pred_class in CLASSES
    assert 0.0 <= conf <= 1.0
    assert len(probs) == len(CLASSES)


def test_statistical_model_heuristic_fallback():
    """Verifies that un-fitted statistical model safely falls back to rule-informed prior."""
    model = ESPStatisticalModel()
    assert model.is_fitted is False

    voip_feat = {"iat_mean_ms": 20.0, "size_mean": 200.0, "total_packets": 50, "total_bytes": 10000}
    pred_class, conf, probs = model.predict_dict(voip_feat)
    assert pred_class == "VoIP"
    assert conf >= 0.7


def test_model_serialization():
    """Verifies that both CNN and Random Forest models serialize and deserialize without loss."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        cnn_path = Path(tmp_dir) / "cnn.pt"
        rf_path = Path(tmp_dir) / "rf.joblib"

        # CNN test
        cnn = ESP1DCNN()
        cnn.save_weights(cnn_path)
        assert cnn_path.exists()

        cnn_loaded = ESP1DCNN()
        cnn_loaded.load_weights(cnn_path)

        # Random Forest test
        rf = ESPStatisticalModel(n_estimators=5)
        X = np.random.randn(8, 27).astype(np.float32)
        y = ["Web", "VoIP", "ICMP", "Video", "Web", "VoIP", "ICMP", "Video"]
        rf.fit(X, y)
        rf.save(rf_path)
        assert rf_path.exists()

        rf_loaded = ESPStatisticalModel()
        success = rf_loaded.load(rf_path)
        assert success is True
        assert rf_loaded.is_fitted is True
