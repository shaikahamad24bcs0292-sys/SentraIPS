"""
Unit and integration tests for ESP Feature Extractor (Phase 2).
"""

from pathlib import Path
import pytest

from packet_analysis.features import ESPFeatureExtractor, ESPTrafficFeatures


@pytest.fixture
def demo_pcap(project_root: Path) -> Path:
    pcap = project_root / "demo_data" / "demo_capture.pcap"
    assert pcap.exists()
    return pcap


def test_esp_feature_extraction_from_pcap(demo_pcap: Path):
    """Verify statistical and temporal features extracted from real ESP capture."""
    feats = ESPFeatureExtractor.extract_from_pcap(demo_pcap)

    assert isinstance(feats, ESPTrafficFeatures)
    assert feats.total_packets > 0
    assert feats.total_bytes > 0
    assert feats.flow_duration_sec > 0
    assert feats.size_min > 0
    assert feats.size_max >= feats.size_min
    assert feats.size_mean >= feats.size_min
    assert feats.size_median >= feats.size_min
    assert feats.burst_count > 0
    assert len(feats.packet_size_sequence) > 0
    assert len(feats.packet_size_sequence) <= ESPFeatureExtractor.SEQUENCE_MAX_LENGTH


def test_empty_packets_handling():
    """Verify extractor returns default/zeroed features on empty packet list without errors."""
    feats = ESPFeatureExtractor.extract_from_packets([])

    assert feats.total_packets == 0
    assert feats.total_bytes == 0
    assert feats.flow_duration_sec == 0.0
    assert feats.size_mean == 0.0
    assert feats.burst_count == 0
    assert len(feats.packet_size_sequence) == 0


def test_flat_feature_dict_generation(demo_pcap: Path):
    """Verify flat numerical dictionary generation for ML models."""
    feats = ESPFeatureExtractor.extract_from_pcap(demo_pcap)
    flat = feats.to_flat_dict()

    assert isinstance(flat, dict)
    assert "total_packets" in flat
    assert "size_mean" in flat
    assert "size_std" in flat
    assert "iat_mean_ms" in flat
    assert "burst_count" in flat
    for k, v in flat.items():
        assert isinstance(v, (int, float)), f"Value for {k} is not numeric: {v}"
